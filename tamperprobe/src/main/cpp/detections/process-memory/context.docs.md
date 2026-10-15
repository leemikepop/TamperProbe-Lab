# SU Context Checking

透過檢查當前行程的 SELinux 屬性節點（`/proc/self/attr/current`）以及走訪 `/proc` 目錄下所有可見行程的屬性節點（`/proc/<pid>/attr/current`），確認系統中是否存在異常的 Process Domain（行程安全領域）。正常 Android 應用程式應運行於特定的應用領域（如 `untrusted_app` 等）；若自身處於非標準或提權領域，或在可見行程中發現含有 `magisk`、`kernelsu`、`apatch`、`:su:` 或 `permissive` 標記的進程，代表設備已遭到 Root 提權或處於安全策略放寬狀態。

## 這個檢測在看什麼

本檢測執行兩部分的 procfs SELinux 屬性掃描：

- **當前行程領域（`selfContext`）判定**：
  - 讀取 `/proc/self/attr/current`（最多 512 位元組）。
  - 比對是否屬於正常應用領域清單：`{"untrusted_app", "platform_app", "system_app", "priv_app"}`。
  - 比對是否包含可疑關鍵字：`{"magisk", "apatch", "kernelsu", ":su:", "permissive"}`。
  - 若包含可疑關鍵字，或**不屬於上述正常領域清單**，即判定 `selfAbnormal = true`。
- **全系統可見行程（`/proc/<pid>`）掃描**：
  - 以原生 syscall `openat` 開啟 `/proc` 目錄，使用 `getdents64` 走訪所有數字目錄（PID）。
  - 對每一個行程目錄嘗試讀取 `/proc/<pid>/attr/current`。
  - 若能讀取且內容包含上述 5 個可疑關鍵字，將其記錄至 `suspiciousProcesses` 清單（如 `"PID 1234: u:r:magisk:s0"`）。
  - 記錄成功檢查的行程數 `procChecked` 與因權限被拒絕的行程數 `procDenied`。

## 觸發代表什麼

- 若 `selfAbnormal == true` 或 `suspiciousProcesses` 非空：直接判定為 STRONG（`strongObserved()`）。
- 否則判定為 NOT_OBSERVED。

不能推論的：
- **不能推論是哪個特定攻擊者。** 標籤反映的是 SELinux 領域分類。
- **不能保證能看到所有系統行程。** 現行 Android 版本通常啟用 `hidepid` 或 SELinux 隔離，普通 App 無法看見其他 UID 的進程屬性。

## 已知偽陽性來源

- **執行於白名單外的合法系統/隔離應用領域**（`is_normal_context` / `is_abnormal_context`）：正常領域白名單僅硬編碼了 4 個值（`untrusted_app`, `platform_app`, `system_app`, `priv_app`）。若應用程式以 Android 獨立行程執行（如 `isolated_app` 或帶有版本號的 `isolated_app_all`）、即時應用（`ephemeral_app`）、特定 Android 版本的分割領域（如 `untrusted_app_25`, `untrusted_app_27` 等若未匹配子字串），或 OEM 自訂的應用領域（如部分車載或深度客製化 ROM 的專屬 app domain），`is_normal_context` 會回傳 false，導致 `is_abnormal_context` 判定為真，進而產生誤判的 STRONG finding。
- **使用者自建開發機或測試韌體中的 Permissive 守護進程**（`is_suspicious_context` 與可疑行程記錄分支）：在工程機或 userdebug 韌體上，若背景有 OEM 測試守護行程在標籤中帶有 `permissive` 或 `:su:` 且對 app 可見，會使 `suspiciousProcesses` 非空而觸發 STRONG。

## 看不到什麼

- **`hidepid=2` 或 SELinux 阻擋 `/proc/<pid>` 列舉**：在 Android 9+ 的標準安全機制下，`untrusted_app` 無法列舉其他行程的 `/proc/<pid>/attr/current`（會回傳 EACCES，反映於 `procDenied` 計數增加），因此 `/proc` 掃描通常只能看到 App 自身或 Zygote fork 的子進程，無法看到系統背景中的 Root 守護行程。
- **未更換 Domain 的注入（如 Zygisk / LSPosed）**：現代 Hook 工具通常直接注入在 App 自己的進程內，並不切換 SELinux Domain（仍維持 `u:r:untrusted_app:s0`），此時本檢測完全沉默。
- **掛載覆蓋 `/proc/self/attr/current`**：Root 模組若透過 mount namespace 或 chroot 覆蓋 attr 節點，讀出的資料即為偽造內容。

## 建議處置

| 強度 | 建議 |
|---|---|
| STRONG | 行程本身運行在異常 SELinux 領域，或背景存在可見的 Root/Permissive 守護行程，屬於嚴重的安全環境異常，建議納入風控或阻斷決策。 |
| NOT_OBSERVED | 行程處於標準應用領域且未發現可見的可疑進程，但不代表無進程內程式碼注入（見上方盲區）。 |
| INCONCLUSIVE | `/proc/self/attr/current` 讀不到，且 `/proc` 也無法列舉 —— 兩個通道都沒有作答。 | 底層資料無法採集，**不可**判讀為未發現異常網域。 |

## 成本

- 讀取 `/proc/self/attr/current`（最多 512 位元組）。
- 走訪 `/proc` 目錄並對所有數字 PID 嘗試讀取 `/proc/<pid>/attr/current`（通常在百個 syscall 級別，大部分被 SELinux 快速拒絕）。
- 全程在原行程內透過底層 syscall 完成，不 fork 行程，不啟動外部命令。
- 整合者不需要在 `AndroidManifest.xml` 中配置任何權限或設定。

## Evidence units

### su-context.process-domain

記錄當前行程自身 SELinux 領域（`selfContext` 與 `selfAbnormal` 判定）以及 `/proc` 遍歷中所探測到的可疑進程資訊（`suspiciousProcesses`，包含 PID 與其 context 標籤）、已檢查進程數與權限拒絕數。

> 2026-09-12 之前本檢測**沒有任何路徑能回報 INCONCLUSIVE**。`read_text_file` 對「讀取被拒」與
> 「檔案為空」都回傳空字串，而 `is_abnormal_context` 刻意把空字串視為不異常，因此兩個通道
> 全部失效時，結果與一台完全乾淨的裝置**完全相同**。現在 payload 會記錄
> `selfContextReadable` 與 `procEnumerated` 兩個旗標，並在兩者皆否時回報 INCONCLUSIVE。
