# Devpts Permission Anomaly

透過檢查虛擬終端裝置檔案系統（`/dev/pts/`）的檔案權限與 SELinux 擴展屬性（`security.selinux`）、動態分配新虛擬終端（PTY），以及掃描自身 `/proc/self/fd` 是否持有 KernelSU 專屬驅動描述符，偵測以 KernelSU 為代表的底層 Root 框架。傳統與現代 Root 工具在處理終端模擬與提權互動時，常會在 PTY 節點殘留 Root 擁有者（UID 0）或特殊的 `ksu_file` 標籤，或在進程內部遺留未關閉的驅動控制描述符。

## 這個檢測在看什麼

本檢測執行三個層面的低階探測：

- **既存 PTY 節點巡檢**：逐一輪詢 `/dev/pts/0` 至 `/dev/pts/100` 共 101 個固定路徑，呼叫 `lstat` 取得擁有者 UID，並透過 `getxattr` 讀取 `security.selinux` 擴展屬性。若檔案擁有者為 `root`（`st.st_uid == 0`）或 SELinux context 包含 `ksu_file`，即標記為異常。
- **動態 PTY 分配驗證**：呼叫 `posix_openpt(O_RDWR | O_NOCTTY)`、`grantpt`、`unlockpt` 與 `ptsname` 分配全新的從屬終端節點，並立即對其執行 `lstat` 與 `getxattr`。正常情況下新建立的 PTY 應屬於當前 App UID，若一建立即屬於 `root` 或具有 `ksu_file` 屬性，代表核心層 PTY 掛載或驅動已被 Root 模組掛鉤。
- **自我行程驅動描述符掃描**：透過原生 syscall `openat` 開啟 `/proc/self/fd`，使用 `getdents64` 走訪所有檔案描述符並以 `readlink` 解析符號連結目標，檢查是否包含 `[ksu_driver]` 或 `[ksu_fdwrapper]`。

## 觸發代表什麼

- 若發現 `[ksu_driver]`、`[ksu_fdwrapper]` 描述符，或異常計數 `hitCount >= 2`：判定為 STRONG。
- 若僅有單一 PTY 異常（例如僅單一既存節點為 UID 0）：判定為 MODERATE。

不能推論的：
- **不能推論當前應用程式已獲得 Root Shell。** 既存的 `/dev/pts/` 節點異常可能是系統其他背景程式（如 ADB 守護行程或終端應用）所留下的產物。
- **不能推論特定惡意目的。** 使用者可能僅啟用過終端模擬器或除錯工具。

## 已知偽陽性來源

- **開機初期系統服務殘留的 PTY 節點**（`native_root_devpts.cpp` 第 52-65 行）：在部分 Android 裝置上，開機時由 `init`、`adbd`（尤其是在 userdebug 或開放 USB 除錯時）或原廠測試服務所分配的 `/dev/pts/0` 等早期節點，可能直接被設置為 UID 0（root）；若 SELinux 允許未受信任應用讀取該節點中繼資料，檢測器會因 `st.st_uid == 0` 將該路徑視為異常，產生誤判。
- **第三方終端模擬器或 ADB 測試工具**（`native_root_devpts.cpp` 第 52-82 行）：使用者若在背景執行 Termux 或透過電腦執行 `adb shell`，產生的 PTY 節點可能殘留於 `/dev/pts/` 中並觸發單一節點命中。

## 看不到什麼

- **PTY 節點超過探測範圍**：檢測硬編碼檢查 `/dev/pts/0` 至 `/dev/pts/100`；若 Root 工具分配在 index > 100 的節點，本檢測無法看見。
- **清理完整的 KernelSU 實作**：若 KernelSU 模組在掛鉤 PTY 時正確將 slave 節點擁有者賦予請求行程的真實 UID，且未打上 `ksu_file` context，既存與動態 PTY 檢測皆不會觸發。
- **關閉驅動描述符的 Hook**：KernelSU 驅動或 su 守護程式若在子行程 fork 或 specialization 階段立即關閉 `[ksu_driver]` 描述符，`/proc/self/fd` 掃描將找不到痕跡。
- **SELinux 存取限制**：若系統 SELinux 規則阻擋 `untrusted_app` 讀取 `/dev/pts/` 的 `getxattr`（回傳 `EACCES`），SELinux context 的比對將失去效力。

## 建議處置

| 強度 | 建議 |
|---|---|
| STRONG | 檢測到明確的 KernelSU 驅動描述符（`[ksu_driver]`）或多個 PTY 同時呈現 Root 特徵，高機率表示底層存在核心級 Root 框架，建議納入高風險決策。 |
| MODERATE | 僅單一既存 PTY 節點呈現異常，極可能為系統 ADB 除錯或殘留節點，建議結合其他 Root 檢測（如 `su-binary`、`context`）交叉判斷。 |
| NOT_OBSERVED | 在 101 個採樣點與動態 PTY 中未發現異常中繼資料，不代表無其他無 PTY 特徵的 Root 方案。 |

## 成本

- 迴圈呼叫 101 次 `lstat`（`/dev/pts/0`..`100`），對可存取節點呼叫 `getxattr`。
- 建立 1 個臨時 PTY（`posix_openpt`、`grantpt`、`unlockpt`、`ptsname`、`lstat`、`getxattr`、`close`）。
- 遍歷 `/proc/self/fd` 目錄（1 次 `getdents64` 迴圈與若干次 `readlink`）。
- 全程在原行程內透過 syscall 完成，不 fork 行程，不啟動外部指令。
- 整合者不需要在 `AndroidManifest.xml` 中配置任何權限或設定。

## Evidence units

### native-root-devpts.pty-metadata

記錄 `/dev/pts/` 節點巡檢、動態分配 PTY 以及 `/proc/self/fd` 驅動描述符的異常發現。包含異常檔案路徑（如 `/dev/pts/0`）、擁有者（`root (uid=0)`）、SELinux context（是否標記 `ksu_file`）、以及驅動描述符類型（`[ksu_driver]` 或 `[ksu_fdwrapper]`）。
