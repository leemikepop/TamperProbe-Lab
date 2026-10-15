# Memory Maps Anomaly

全面稽核進程記憶體映射（`/proc/self/maps`）、核心記憶體統計（`/proc/self/smaps`）與重大例外信號處理常式（Signal Handlers）。動態注入、Inline Hook 與除錯工具（如 Frida、Xposed）在進程中運作時，往往會留下同時具備可寫與可執行的記憶體段（W+X）、無實體檔案支撐的匿名可執行段（`[anon]`）、或是將 `SIGTRAP`、`SIGSEGV`、`SIGILL`、`SIGBUS` 等關鍵信號的處理函式註冊到可疑模組或匿名記憶體中。本檢測串聯記憶體屬性與異常信號監聽，識別進程記憶體空間中的異常執行段。

## 這個檢測在看什麼

本檢測整合三個維度的記憶體取證：

- **可執行映射段異常審查（`/proc/self/maps`）**：
  - 排除 8 個良性執行時期產物（`jit-cache`, `jit-code-cache`, `jit-zygote`, `dalvik-`, `webview`, `chromium`, `v8-code`, `wasm-code`）。
  - 可寫且可執行（W+X，`entry.writable`）：標記為 `writable_executable`（MODERATE）。
  - 匿名可執行段（`isAnonymousPath`，如空路徑、`[anon]`、`[anonymous]`、`[anon:...`、`[anon_shmem:...`、`/dev/zero`、`/memfd:...`）：標記為 `anonymous_executable`（WEAK）。
  - 已自磁碟刪除的可執行段（`entry.deleted`）：標記為 `deleted_executable`（MODERATE）。
- **Smaps 髒頁稽核（`/proc/self/smaps`）**：
  - 逐段解析 `/proc/self/smaps`，檢查系統函式庫分區（`/system/`, `/vendor/`, `/apex/`, `/product/`）下的可執行區段。
  - 若私有或共享髒頁超過 8 KB（`privateDirty > 8 || (privateDirty + sharedDirty) > 8`），記錄為 `smaps_dirty_page`。
  - **重要**：因預鏈結函式庫在開機重定位（relocation）與寫入時複製（COW）在正常設備上也會產生髒頁，且 8 KB 門檻為源自 Duck-Detector 的未校準編譯期常數，此項目前在代碼中被明確標記為 `assessmentImpact: "telemetry_only"`，僅供背景遙測，不影響評估結果。這些條目會以 `assessmentImpact = "telemetry_only"` 放進同一個 `findings` 陣列，但判定只計算非 telemetry 的 finding（`assessmentBearingFindingCount`）。2026-09-12 之前判定用的是整個陣列是否為空，因此**光是這些遙測條目就會讓檢測器回報 WEAK OBSERVED** —— 在任何因重定址或 copy-on-write 而弄髒系統函式庫頁面的正常裝置上都會發生，與本文件、`evidence.json` 的 inferenceLimit 及程式碼自身的註解相牴觸。
- **異常信號處理常式審查（`sigaction`）**：
  - 審查 4 個常用於除錯與 Hook 的關鍵信號：`SIGTRAP`, `SIGSEGV`, `SIGILL`, `SIGBUS`。
  - 透過 `sigaction` 取得已註冊的 handler 位址，比對其在 `/proc/self/maps` 中落在哪個區段。
  - 若 handler 位址落在帶有知名注入工具路徑（`frida`, `gum-js`, `gadget`, `linjector`, `sandhook`, `xposed`）的模組中：標記為 `suspicious_signal_handler`（STRONG）。
  - 若 handler 位址落在匿名記憶體段或未映射區間（`isAnon`）：標記為 `suspicious_signal_handler`（MODERATE）。

## 觸發代表什麼

- **STRONG**：若信號處理常式指向帶有明確注入工具名稱的記憶體區段（`strongFinding = true`）。
- **MODERATE**：若存在非 ART 的 W+X 映射、已刪除的可執行映射，或信號處理常式指向匿名記憶體（`moderateFinding = true`）。
- **WEAK**：僅存在無實體檔案的普通匿名可執行段。
- **NOT_OBSERVED**：未發現非標準的可執行映射，且受監控的信號處理常式皆指向合法的常規函式庫。

不能推論的：
- **不能將 smaps 髒頁直接推論為代碼遭到篡改。** 該項為遙測專用。
- **不能推論匿名信號處理常式必然是惡意軟體。** 部分良性崩潰回報工具亦可能在 JIT 或自建緩衝區建立信號接收常式。

## 已知偽陽性來源

- **第三方崩潰收集工具自訂信號處理常式**（signal handler 稽核區塊）：如 Sentry、Breakpad、Crashlytics 或遊戲引擎自帶的 Native 崩潰捕獲組件，若將 `SIGSEGV` 或 `SIGBUS` 的 handler 設定在動態分配的匿名記憶體或 JIT 代碼段中（`isAnon` 成立），會被判定為 MODERATE 等級的 `suspicious_signal_handler`。
- **非 ART 的 JIT 或動態語言引擎**（良性產物清單與 writable-executable 判斷）：自編 JavaScript 引擎（如 QuickJS）、Mono / Unity IL2CPP、Unreal 引擎或自帶動態二進位翻譯的遊戲，其產生的 W+X 映射或匿名可執行段不在硬編碼的 8 個良性過濾關鍵字中，會被誤判為 `writable_executable`（MODERATE）或 `anonymous_executable`（WEAK）。
- **熱更新或動態載入的刪除產物**（deleted-executable 判斷）：應用程式使用熱更新框架載入 `.so` 後立即自快取目錄刪除該檔案，會觸發 `deleted_executable`。

## 看不到什麼

- **修改指令後復原記憶體保護的 Hook**：Inline Hook 若在寫入跳轉指令後，立即呼叫 `mprotect` 將記憶體權限重設回唯讀且可執行（R-X），在 maps 中將看不到任何 W+X 標記。
- **未註冊上述 4 種信號的 Hook 框架**：若注入工具不接管 `SIGTRAP`、`SIGSEGV`、`SIGILL`、`SIGBUS`，信號稽核將不會觸發。
- **進程記憶體視圖過濾**：若利用核心模組或 Zygisk 遮蔽過濾 `/proc/self/maps` 與 `/proc/self/smaps`，檢測器無法感知底層真實分佈。

## 建議處置

| 強度 | 建議 |
|---|---|
| STRONG | 信號處理常式直接指向 Frida、SandHook 等知名 Hook 框架模組，進程已被動態插樁的確定性極高，建議立即觸發防護處置。正式採用前請先在你的使用者族群上收集分佈。 |
| MODERATE | 存在異常 W+X 區段、已刪除執行映射或匿名信號常式，建議先排除是否由自家遊戲引擎或崩潰回報 SDK 所引起，並與 `memory_fd_anomaly` 交叉驗證。 |
| WEAK | 僅觀察到匿名可執行映射，資訊量薄弱，建議僅供風險計分參考。 |
| NOT_OBSERVED | 映射與信號常式未發現異常。 |
| INCONCLUSIVE | `/proc/self/maps` 無法讀取或為空，視為採集失效。 |

## 成本

- 完整讀取並解析 `/proc/self/maps`。
- 逐行讀取並解析 `/proc/self/smaps`（檔案較大，需耗費數百微秒 I/O）。
- 對 4 個信號（`SIGTRAP`, `SIGSEGV`, `SIGILL`, `SIGBUS`）執行 `sigaction` 查詢。
- 純行程內記憶體與系統呼叫檢查，0 子行程，0 執行緒。

## Evidence units

### memory-maps.executable-mapping-anomaly

記錄進程記憶體中探測到的異常可執行映射與信號常式。包括可寫可執行段（`writable_executable`）、匿名可執行段（`anonymous_executable`）、已刪除可執行段（`deleted_executable`）、僅作遙測的 smaps 系統函式庫髒頁（`smaps_dirty_page`，含私有與共享髒頁 KB 數）、以及指向可疑或匿名區段的信號處理常式（`suspicious_signal_handler`，含信號名稱與 handler 位址）。
