# Memory Linker Visibility

透過公開的 `dl_iterate_phdr` 走訪已載入的動態共享函式庫（ELF objects），與 `/proc/self/maps` 的實際記憶體映射區間進行雙向交叉比對，並驗證標準 C 函式庫（Bionic libc）與動態鏈結器關鍵符號的解析位址（GOT/PLT integrity）。隱藏模組常會透過竄改鏈結器鏈結結構（如 unlinking soinfo）來隱藏自身，或透過 PLT Hook 將核心系統呼叫重導向至自訂跳板；這類篡改會打破「Linker 看到的模組範圍」與「核心記憶體映射表」的一致性，並造成符號位址溢出合法的函式庫記憶體區間。

## 這個檢測在看什麼

本檢測執行三個方向的一致性校驗：

- **Linker-Only 模組檢查（`linkerOnlyModules`）**：
  - 呼叫 `dl_iterate_phdr` 收集所有已註冊共享物件的 `PT_LOAD` 載入區間。
  - 對每個模組，檢查其所有載入區間是否能被 `/proc/self/maps` 中的有效映射完全覆蓋（`linkerRangeCoveredByMaps`）。若鏈結器說有載入、但 maps 中找不到對應映射，代表 maps 被過濾或隱蔽。
- **Maps-Only 模組檢查（`mapsOnlyModules`）**：
  - 掃描 `/proc/self/maps` 中所有具備可執行權限且路徑包含 `.so` 或 `.apk!/lib/` 的候選共享庫（排除 JIT、Dalvik、WebView、Chromium 等良性產物）。
  - 比對其區間是否重疊於 `dl_iterate_phdr` 所回報的任何一個模組（`overlapsAnyObject`）。若 maps 中存在具名的可執行共享庫，卻完全未向 Linker 註冊，即為隱藏載入的共享庫。
- **GOT/PLT 符號跳脫檢驗（`gotPltEscapes`）**：
  - 檢驗 8 個關鍵系統底層符號：
    - `open`, `openat`, `read`, `write`, `stat`, `mprotect`, `kill`（預期位址必須落在 `libc.so` 載入區間內）
    - `dlsym`（預期位址必須落在 `libdl.so`、`linker64` 或 `linker` 載入區間內）
  - 透過 `dlsym(RTLD_DEFAULT, symbol)` 取得執行時期的符號位址，檢查其是否落在預期模組的 `loadRanges` 內。若符號解析到預期範圍之外（例如跳板程式碼或匿名跳轉區間），標記為 GOT/PLT 逸出（`gotPltEscapes`）。

## 觸發代表什麼

- **STRONG**：若發現任一 `gotPltEscapes`。代表底層基礎系統函式（如 `open`、`read`、`dlsym`）的符號已被重導向至非官方函式庫區間，是 PLT Hook 或符號劫持的強烈指標。
- **MODERATE**：若發現 `linkerOnlyModules` 或 `mapsOnlyModules`。代表 Linker 與 procfs 記憶體視圖存在可見性脫節。
- **NOT_OBSERVED**：Linker 與 maps 視圖完全吻合，且 8 個目標符號皆落在標準系統函式庫區間內。

不能推論的：
- **不能直接推論是惡意攻擊。** 部分合法的效能監控（APM）或 Native 崩潰收集 SDK 也可能透過 PLT Hook 監聽系統呼叫。

## 已知偽陽性來源

- **第三方 APM 或效能監控 SDK 的 PLT Hook**（`memory_linker_visibility.cpp` 第 163-172、174-207 行）：若應用程式整合了如 ByteHook、xHook、ShadowHook、Bugly 或其他監控 SDK 來攔截 `open`、`read` 或 `stat` 收集 I/O 延遲或崩潰堆疊，`dlsym(RTLD_DEFAULT, "open")` 會回傳監控 SDK 的跳板位址，導致符號解析位址超出 `libc.so` 的合法區間，觸發 STRONG 等級的 `gotPltEscapes`。
- **動態記憶體載入的合法模組**（`memory_linker_visibility.cpp` 第 80-87、153-161 行）：部分加固保護軟體或自帶 ELF 載入器（In-Memory Loader）的函式庫，若在記憶體中自行解析並映射包含 `.so` 的區段而未透過 `android_dlopen_ext` 告知系統 Linker，會觸發 MODERATE 等級的 `mapsOnlyModules`。

## 看不到什麼

- **Inline Hook（行內跳轉掛鉤）**：若 Hook 工具直接改寫 `libc.so` 內部函式的前幾條指令（例如覆寫為 `LDR PC, [PC, #0]` 跳轉），函數入口位址依然落在 `libc.so` 的範圍內，`dlsym` 查出的位址符合預期，GOT/PLT 檢測完全沉默。
- **未被監控的符號**：檢測器硬編碼監控上述 8 個特定符號；若攻擊者 Hook 其他函式（如 `connect`, `ioctl`, `fork`），本檢測不會察覺。
- **同時竄改 Linker 與 maps 的進階工具**：若攻擊者同步偽造 `dl_iterate_phdr` 的回傳清單並修改 procfs 輸出，雙向比對將維持「一致的虛假」。

## 建議處置

| 強度 | 建議 |
|---|---|
| STRONG | 系統核心 C 函式庫符號（如 `open`、`dlsym`）解析位址偏離標準系統庫範圍，代表存在全域符號劫持。正式採用前請先在你的使用者族群上收集分佈，並確認應用程式自身未引入 PLT Hook 監控工具。 |
| MODERATE | 記憶體映射與 Linker 註冊清單存在分歧，建議與其他 Native 偵測結果交叉驗證。 |
| NOT_OBSERVED | Linker 與記憶體映射視圖一致，8 個監控符號未見逸出。 |
| INCONCLUSIVE | `/proc/self/maps` 無法讀取或 `dl_iterate_phdr` 未列舉出任何模組，視為採集失效。 |

## 成本

- 呼叫 1 次 `dl_iterate_phdr` 遍歷所有已載入模組之 program header。
- 完整讀取並解析 `/proc/self/maps`。
- 執行 8 次 `dlsym(RTLD_DEFAULT, ...)` 符號位址查詢。
- 純行程內位址範圍比對，0 子行程，0 執行緒。

## Evidence units

### memory-linker.module-view-consistency

記錄動態鏈結器視圖與 `/proc/self/maps` 映射視圖的比對結果，包含未完全映射的 Linker 模組（`linkerOnlyModules`）、未註冊於 Linker 的 maps 共享物件（`mapsOnlyModules`）、以及解析位址偏離預期庫範圍的 GOT/PLT 符號（`gotPltEscapes`，包含符號名稱、解析位址與解析到的實體路徑）。
