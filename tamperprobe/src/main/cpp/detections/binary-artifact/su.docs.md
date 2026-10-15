# SU Binary Checking

針對 14 個固定 root 候選路徑以及從 `$PATH` 環境變數解析出的目錄（最多追加 32 個路徑），檢查是否存在 `su` 二進位檔或管理產物。檢測器透過 `access`、`lstat`、`open(O_PATH)` 取得目標中繼資料，並在發現常規檔案時透過 `open(O_RDONLY)` 與 `pread` 檢查檔案前 4 位元組是否具有 ELF magic（`\x7fELF`）以及可執行權限。只有固定路徑上的可執行 ELF 二進位檔才會升級為 STRONG 判定，其餘路徑或非 ELF 檔案僅計為 WEAK。

## 這個檢測在看什麼

檢測器檢查以下兩類路徑清單：

1. **14 個固定候選路徑**（`su.cpp` 的 `candidates` 清單）：
   - `/system/app/Superuser.apk`
   - `/sbin/su`
   - `/system/bin/su`
   - `/system/xbin/su`
   - `/data/local/xbin/su`
   - `/data/local/bin/su`
   - `/system/sd/xbin/su`
   - `/system/bin/failsafe/su`
   - `/data/local/su`
   - `/su/bin/su`
   - `/product/bin/su`
   - `/system_ext/bin/su`
   - `/vendor/bin/su`
   - `/odm/bin/su`
2. **`$PATH` 動態擴充路徑**：
   - 讀取當前行程的 `$PATH` 環境變數，依 `:` 切割目錄後在結尾附加 `/su`，最多追加 32 個不重複候選路徑（標記來源為 `environment_path`）。

固定清單的後四項於 2026-09-11 加入。它們是 zygote 預設 `$PATH` 上的系統分區 bin 目錄，而現代 Magisk 的 su 就出現在 `/product/bin`。放進固定清單後，該處若有可執行 ELF 會評為 STRONG；`$PATH` 掃描會略過已在固定清單中的路徑，因此不會重複探測，候選總數不變，只是來源改標為 `fixed_path`。

對每個候選目標，依序執行：
- `access(path, F_OK)` 確認路徑可見性。
- `lstat(path, &linkStat)` 取得符號連結自身狀態。
- `open(path, O_PATH | O_CLOEXEC)` + `fstat(fd, &resolvedStat)` 取得解析後目標的屬性（`st_mode`、`st_uid`、`st_gid`、`st_dev`、`st_ino`）。
- 若目標為常規檔案（`regular`），進一步以 `open(path, O_RDONLY | O_CLOEXEC)` 開啟並以 `fstat` 比對 `st_dev` 與 `st_ino` 確保與 `O_PATH` 所指為同一檔案，隨後以 `pread` 讀取前 4 位元組，驗證是否為 `\x7fELF`。

## 觸發代表什麼

依結果強度分級：

| 強度 | 觸發條件 | 代表意義 |
|---|---|---|
| STRONG | 固定路徑上存在具備可執行權限（`st_mode & 0111 != 0`）且開頭為 `\x7fELF` 的常規檔案 | 高可信度的 su 執行檔產物（`executable_elf_magic`）。 |
| WEAK | 來自 `$PATH` 的路徑可見，或固定路徑上存在非 ELF／無執行權限的檔案（如 `Superuser.apk` 或空檔案） | 存在 su 相關路徑或套件產物（`visible_path`），但無法確認其可執行性或來源信任度。 |

不能推論的：
- **不能推論當前行程成功提權。** 看到 `su` 檔案不保證當前應用程式能成功執行它（例如可能受到 SELinux 阻擋或 su daemon 未啟動）。
- **不能推論特定的 root 提供者。** SuperSU、舊版 Magisk 或自訂 ROM 均可能放置 `su`。

## 已知偽陽性來源

- **Userdebug 與 Eng 原廠測試韌體。** 原廠或 AOSP 的 userdebug / eng 韌體映像檔通常在 `/system/xbin/su` 預載除錯用 su 檔案，該檔案具備合法的 ELF magic 與可執行權限，會觸發 STRONG 判定（`binary_artifact_probe.cpp` 中 `strongSuArtifact` 的判定），但該裝置為原廠開發機而非遭到惡意破解。
- **$PATH 中的非特權腳本或封裝環境。** 使用者在終端模擬器（如 Termux）或 PRoot 環境下，若在 `$PATH` 目錄中建立了名為 `su` 的 wrapper 腳本或別名，會觸發來源為 `environment_path` 的 WEAK 判定。
- **非二進位產物或殘留標記。** 固定候選路徑中包含 `/system/app/Superuser.apk`，其格式為 ZIP 壓縮檔而非 ELF，若該檔案存在只會判定為 WEAK；若有空檔案或 dummy 檔案殘留，亦會觸發 WEAK 判定。
- **OEM 在 vendor／odm 分區放置的除錯 su。** 固定清單包含 `/vendor/bin/su` 與 `/odm/bin/su`；若某原廠韌體在這些分區預載可執行的除錯 su，會被評為 STRONG。本機隊與目前資料中未觀察到這種情形，但它與 `/system/xbin/su` 的 userdebug 案例屬於同一類風險。

## 看不到什麼

- **現代 Systemless Root（Magisk / KernelSU / APatch）。** 現代 root 方案不再於 `/system/bin` 或 `/sbin` 放置明文 su 檔案。Magisk 透過 mount namespace 針對特定應用卸載 su，KernelSU 與 APatch 則在核心層運作。
  實測支持 Magisk 的部分（2026-09-11，`ablation_2026`，Redmi 13C，Magisk 30.6）：`R0`（DenyList 關閉）經 `$PATH`（當時 `/product/bin` 尚未列入固定清單）看到 `/product/bin/su`——它是一個符號連結，位於 Magisk 掛在 `/product/bin` 的 tmpfs 上（`lstat` 所在裝置與目標不同；`MOUNT_INTEGRITY` 在同一格記錄了該 tmpfs），指向 root 擁有、權限 `0755`、具 ELF magic 的 400 KB 執行檔；`R1` 開啟 DenyList 後，同一路徑三個呼叫皆回傳 `ENOENT`。
- **`/system/xbin` 在部分裝置上對 App 不可搜尋。** 同一台 Redmi 上 `/system/xbin/su` 在所有格子（含 `R0`）都回傳 `EACCES`，屬於權限邊界而非隱藏，報告以 `unavailableCandidateCount` 呈現。因此不能說「未授權 App 在所有候選路徑只會看到 `ENOENT`」：部分候選是被拒，而非不存在。
- **強度倒置已修正一半（2026-09-11）。** STRONG 只授予**固定路徑**上的可執行 ELF。此前 `R0` 的 Magisk su 雖完全符合可執行 ELF 的條件，卻因為是從 `$PATH` 找到（`environment_path`）而只被評為 WEAK；而「已知偽陽性來源」所列 userdebug 韌體預載在 `/system/xbin/su` 的除錯 su 位於固定路徑，反而會被評為 STRONG。修正方式是把 `/product/bin/su`、`/system_ext/bin/su`、`/vendor/bin/su`、`/odm/bin/su` 納入固定清單；依 `R0` 記錄的探測結果（regular、權限 `0755`、`elf_magic`），該 su 在新規則下會被評為 STRONG——此為依記錄推導，並非重新擷取。**尚未處理的另一半**：userdebug 除錯 su 仍會被評為 STRONG，因為本檢測不讀取建置類型；從 `$PATH` 其他目錄找到的 su 仍維持 WEAK。
- **自訂名稱或隱藏目錄中的 su。** 未放在固定 14 個路徑且未加入 `$PATH` 的 su 檔案。
- **Syscall Hook。** 若底層 libc 的 `access`、`lstat` 或 `open` 被 hook 統一偽造回傳 `ENOENT`，本檢測無法察覺。

## 建議處置

| 強度 | 建議 |
|---|---|
| STRONG | 系統中存在明確的 su 可執行檔，在非 eng/userdebug 裝置上屬於極高風險訊號，建議納入阻斷或限制高敏感度功能。 |
| WEAK | 僅觀察到路徑可見或來自環境變數，可能為開發工具或非執行檔殘留，建議結合其他 domain（如 `mount_integrity` 或 `system_properties_tamper`）共同研判。 |
| NOT_OBSERVED | 未在受檢路徑中發現 su 產物，不保證環境未 root（現代 root 方案普遍使用 mount namespace 隱藏）。判讀時以 `availableCandidateCount`（真正作答的候選數）為準。 |
| INCONCLUSIVE | 所有候選路徑均無法完成存取檢測，應視為收集失敗。 |

## 成本

- 檢查 14 個固定路徑 + 最多 32 個來自 `$PATH` 的動態路徑（最多 46 個候選目標）。
- 每個目標最多執行 1 次 `access`、1 次 `lstat`、最多 2 次 `open`、最多 2 次 `fstat` 與 1 次 4 位元組 `pread`。
- 不 fork 行程，純 native 系統呼叫，耗時極低。
- 整合者無須在 `AndroidManifest.xml` 中配置任何權限或設定。

## Evidence units

### su-binary.visible-artifact

記錄各候選路徑的探測細節（候選來源 `fixed_path` 或 `environment_path`、檔案屬性、ELF magic 判定）。若固定路徑存在具備執行權限的 ELF 檔案則產出 `executable_elf_magic`（STRONG）；若僅路徑可見或來自環境變數則產出 `visible_path`（WEAK）。
