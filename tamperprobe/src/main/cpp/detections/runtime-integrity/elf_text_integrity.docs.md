# ELF Text Integrity

針對行程內載入的關鍵系統函式庫，比對記憶體中唯讀可執行的程式碼區段（`PT_LOAD`）與實體檔案系統上的 ELF 原始位元組是否完全一致。檢測過程完全不透過 `mprotect` 變更記憶體頁面保護屬性，而是透過 `process_vm_readv` 直接由行程內部讀取自身記憶體，以原生系統呼叫比對是否遭受未授權的就地程式碼竄改（例如 inline hook）。

## 這個檢測在看什麼

檢測器以編譯期常數固定監控 3 個關鍵系統函式庫（`kModuleTargets`，第 27-31 行）：

- `libc.so`（必要函式庫，`required: true`）
- `libart.so`（選用函式庫，`required: false`）
- `libinput.so`（選用函式庫，`required: false`）

運作流程如下：

1. **模組列舉**：透過 `dl_iterate_phdr` 遍歷行程中已載入的動態庫，使用 `pathHasBasename` 比對上述 3 個目標函式庫。若必要函式庫 `libc.so` 未能列舉，會記錄收集錯誤並標記為無效。
2. **區段過濾**：走訪目標模組的 Program Header，嚴格篩選符合 `header.p_type == PT_LOAD`、具備執行權限（`header.p_flags & PF_X`）、且**非可寫**（`(header.p_flags & PF_W) == 0` 且 `header.p_filesz > 0`）的唯讀程式碼區段。
3. **記憶體權限校驗**：讀取 `/proc/self/maps`，呼叫 `rangeHasPermissions` 驗證該區段在 maps 中的所有映射區間確實為可讀、可執行且不可寫（`r-x`）。
4. **雙通道位元組比對**：以 `syscall_openat_readonly` 唯讀開啟實體 ELF 檔案，透過 `syscall_read_fd` 分塊（每次 4096 位元組，`kComparisonChunkBytes`）讀取磁碟位元組；同時透過 `process_vm_readv(getpid(), ...)` 分塊讀取目前行程的記憶體位元組，完全不呼叫 `mprotect` 變更記憶體保護屬性。
5. **差異判定**：透過 `std::mismatch` 逐位元組比對；若發現任何不一致，記錄第一個分歧的偏移量（`firstMismatchOffset`）與區段資訊。

## 觸發代表什麼

OBSERVED 代表受監控的關鍵系統函式庫中，記憶體內的唯讀可執行程式碼與實體檔案不一致，整體結果評定為 MODERATE。這表示該區段在記憶體中曾被解除保護並就地寫入過（例如安裝 inline hook 之後再將保護還原為 `r-x`），或執行時映射了非原始檔案的程式碼。

不能推論的：
- **不能推論特定竄改工具或惡意意圖。** 任何在 native 層掛鉤函式庫程式碼的行為（包括第三方除錯工具或效能監控 SDK）皆會產生相同分歧。
- **不能推論裝置已 root。** 程式碼修改可能僅發生在目前應用程式行程內部。

## 已知偽陽性來源

- **第三方 Crash 收集與效能監控（APM）SDK。** 部分常見的 native crash 收集函式庫（如 Bugly、Sentry-Native）或 APM 效能監控套件，為了攔截崩潰訊號或統計 I/O 呼叫，會在應用程式啟動時透過 `mprotect` 將 `libc.so` 或 `libart.so` 的程式碼段改為可寫，寫入跳躍指令（inline hook）後再改回 `r-x`。此時記憶體權限符合 `rangeHasPermissions` 的非可寫要求，但位元組已與磁碟檔案不同，會在 `elf_text_integrity.cpp` 第 167 行被標記為 `modifiedSegments`，進而觸發 MODERATE 判定。
- **特定 OEM 韌體或虛擬機環境的預先修補。** 少數非標準 Android 韌體或模擬器在啟動 bionic 時，可能對 `libc.so` 進行客製化重定位或內建修補，若未反映在唯讀檔案系統上，可能造成誤判。
- **模組路徑無法開啟或權限受限。** 若目標函式庫位於特殊的 APEX 掛載點且應用程式無權以 `open` 讀取實體檔案，會記錄為 unavailable 並造成 INCONCLUSIVE，而非誤報陽性。

## 看不到什麼

- **可寫程式碼區段（`rwx`）。** 若竄改工具在修補程式碼後未將記憶體保護還原為唯讀，或直接分配可讀寫執行的匿名記憶體，該區段因 `(header.p_flags & PF_W) != 0`（第 59 行）或 `entry.writable`（第 83 行）會被直接略過或標為 unavailable，本檢測無法發出 MODERATE 警告。
- **清單外的函式庫。** 僅嚴格監控 `libc.so`、`libart.so`、`libinput.so` 3 個函式庫。若注入工具竄改其他系統函式庫（如 `libbinder.so`、`libutils.so`）或應用程式自身的 `.so`，本檢測完全不檢查。
- **PLT/GOT 或資料段竄改。** 本檢測僅比對宣告為唯讀可執行的 `PT_LOAD` 區段，對於位於資料段（`.got`、`.data.rel.ro`）的函式指標覆寫完全看不見。
- **核心層或系統呼叫攔截。** 若環境在核心層攔截了 `process_vm_readv` 或 `openat`/`read` 並回傳虛偽資料，比對結果將呈現一致。

## 建議處置

在正式作為風控依據前，必須先在自有使用者族群上進行基線數據收集與校準。

| 強度 | 建議 |
|---|---|
| MODERATE | 觀察到關鍵系統函式庫程式碼區段與磁碟檔案分歧。由於可能源自 App 自行整合的 Crash/APM SDK 進行的 inline hook，建議先清查 App 內部使用的 native SDK，並與其他 domain（如 `mount-integrity` 或 `app-visibility`）交叉比對，不建議單獨直接作為封鎖依據。 |
| NOT_OBSERVED | 受監控的 3 個函式庫可執行區段與檔案一致，不代表環境完全沒有其他形式的注入或未受監控函式庫的竄改。 |
| INCONCLUSIVE | `libc.so` 未能列舉、`/proc/self/maps` 無法讀取、或任一區段因權限問題無法比對，應視為收集失敗而非乾淨結果。 |

## 成本

- 透過 `dl_iterate_phdr` 列舉行程內載入模組，讀取 `/proc/self/maps` 一次。
- 最多以 `openat` 開啟 3 個目標函式庫的磁碟檔案。
- 以 4096 位元組為單位分塊呼叫 `syscall_read_fd` 與 `process_vm_readv` 比對程式碼區段；依函式庫大小讀取資料（例如 `libc.so` 約 1 MB、`libart.so` 約數 MB 至 10 MB）。
- 完全在當前行程內執行，不 fork 任何子行程。
- 整合者無須在 `AndroidManifest.xml` 中進行額外設定。

- **不改變它所讀取的記憶體。** 自身記憶體以 `SelfMemoryReader`（寫入 pipe 再讀回）讀取。2026-09-14 之前使用
  `process_vm_readv`，在 Linux 4.19 的 Redmi 13C 上讀過的程式碼頁會變成 Private_Dirty:一次掃描使 `libart.so`
  8416 kB、`libc.so` 768 kB、`libinput.so` 228 kB，約 9.4 MB 在宿主行程存活期間無法回收，且被排在後面的
  `ZYGISK_SMAPS` 當成程式碼竄改。改用 pipe 後同一實驗三者皆為 0 kB，且仍比對了全部 3 個區段（Linux 6.1 的
  Pixel 7 前後皆為 0）。

## Evidence units

### elf-text.mapped-file-mismatch

記錄受監控函式庫中記憶體與磁碟位元組的比對結果。當比對狀態為 `DIFFERENT` 時，payload 會包含函式庫名稱（`library`）、實體路徑（`path`）、區段編號（`segmentIndex`）、記憶體起始位址（`memoryStart`）、檔案偏移（`fileOffset`）、比對位元組總數（`byteCount`）以及首個不符合的位元組偏移量（`firstMismatchOffset`），作為程式碼竄改的核心訊號。
