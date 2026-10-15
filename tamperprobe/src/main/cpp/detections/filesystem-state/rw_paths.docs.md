# Read-Write Paths Checking

透過 `access(path, W_OK)` 系統呼叫探測 7 個關鍵系統目錄是否具備寫入權限。在標準的 Android 系統架構中，系統分區均為唯讀掛載且受嚴格 DAC/MAC 存取控制，一般應用程式絕不應擁有寫入權限。若任何一個受測路徑回報可寫，即評定為 STRONG 異常。

## 這個檢測在看什麼

檢測器以編譯期常數檢查以下 7 個系統關鍵路徑（`rw_paths.cpp` 的 `paths[]`）：

- `/system`
- `/system/bin`
- `/system/sbin`
- `/system/xbin`
- `/vendor/bin`
- `/sbin`
- `/etc`

對每個路徑呼叫 `access(*path, W_OK)`，透過核心檢查當前行程的真實 UID/GID 與命名空間視角下，該路徑是否具備可寫權限（回傳 0 代表可寫）。失敗時依 `errno` 分類：`EROFS`、`EACCES`、`EPERM` 代表核心**已評估**該路徑並拒絕寫入，是有效的否定答案；`ENOENT` 代表路徑不存在、沒有評估任何東西。

## 觸發代表什麼

- STRONG：在 7 個路徑中至少發現 1 個路徑回報可寫（`payload["writablePaths"]` 非空）。代表當前行程已突破 Android 系統分區唯讀保護的沙箱邊界，可能處於特權模式、系統被 remount 為可寫，或 SELinux/DAC 權限遭受破壞。

不能推論的：
- **不能推論具體的提權工具或修改機制。** 無法區分是由於手動執行 remount 命令、開發者映像檔設定錯誤、OverlayFS 可寫層，還是特定 root 框架所導致。
- **不能推論未檢測分區的狀態。** 僅限於上述 7 個目錄。

## 已知偽陽性來源

- **開啟可寫模式的模擬器或 Userdebug/Eng 韌體。** 透過 `-writable-system` 參數啟動的 Android 模擬器，或是 OEM 內部為除錯而放寬權限的工程用映像檔，其系統分區可能直接以讀寫模式掛載，導致 `access(..., W_OK)` 回傳成功。
- **特殊符號連結或客製路徑映射。** 例如 `/etc` 通常為指向 `/system/etc` 的符號連結；在特定客製化環境或特定車載／物聯網 Android 裝置上，若該目錄被映射至可寫的暫存分區，將直接觸發判定。
- **SELinux Permissive 模式搭配寬鬆 DAC。** 若裝置的 SELinux 處於寬鬆模式且系統目錄的 POSIX 權限未收緊，一般應用程式亦可能測得可寫。

## 看不到什麼

- **現代 Systemless Root 方案（Magisk / KernelSU / APatch）。** 現代 root 工具絕大多數採用 systemless 架構，系統實體分區依然保持唯讀掛載，僅在特定的掛載命名空間中透過 OverlayFS 或 tmpfs 疊加檔案，且通常不會將寫入權限開放給未授權的一般 App UID。因此在標準 Magisk/KernelSU 環境下，本檢測絕大多數情況回傳 NOT_OBSERVED。
- **未納入檢查清單的系統分區。** 例如 `/product`、`/system_ext`、`/odm`、`/apex` 等未列在 7 個路徑中的目錄。
- **清單中有 2–3 條路徑在現行 Android 上不存在。** 實測（2026-09-11）：Redmi 13C（Android 13）上 `/system`、`/system/bin`、`/system/xbin`、`/vendor/bin`、`/etc` 回傳 `EROFS`（已評估、唯讀），`/system/sbin` 與 `/sbin` 回傳 `ENOENT`，作答 5 條；Pixel 7（Android 17）上連 `/system/xbin` 也不存在，`/system`、`/system/bin`、`/vendor/bin`、`/etc` 回傳 `EROFS`，作答 4 條。報告以 `completedPathCount` 與 `notFoundPathCount` 公開；若沒有任何路徑能作答，檢測回報 INCONCLUSIVE 並附收集錯誤。
- **Syscall Hook。** 若底層 libc 的 `access` 被 hook 統一攔截並對 `W_OK` 回傳 `EACCES` 或 `EROFS`，本檢測無法察覺。

## 建議處置

| 強度 | 建議 |
|---|---|
| STRONG | 系統關鍵分區對一般應用程式開放寫入權限屬於極度異常的系統狀態，若非內部測試機，建議採取最高等級防護措施（如拒絕提供敏感服務）。 |
| NOT_OBSERVED | 作答的路徑（`completedPathCount`，實測為 Redmi 5 條、Pixel 4 條）均不可寫，符合標準沙箱預期，但無法排除現代 systemless root 或 namespace 隱藏手段。 |
| INCONCLUSIVE | 沒有任何路徑能從本行程作答，應視為缺乏證據而非乾淨。 |

## 成本

- 僅呼叫 7 次 `access` 系統呼叫。
- 不涉及檔案讀寫、不建立描述符、不 fork 行程。
- 執行時間極短（微秒級），開銷可忽略。
- 整合者無須任何設定。

## Evidence units

### rw-paths.system-path-writability

記錄被探測為可寫的所有路徑清單（`writablePaths`）。只要清單不為空即代表系統寫入權限邊界已被破壞，產出 STRONG 判定。同時記錄覆蓋率：`attemptedPathCount`、`completedPathCount`、`notFoundPathCount` 與 `errorPathCount`。
