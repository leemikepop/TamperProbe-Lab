# Prologue Scanner

動態解析 `libc.so` 與 `libdl.so` 中的 14 個關鍵系統函式進入點，驗證符號是否被導向至預期外的模組，並逐位元組比對函式進入點的前 16 個位元組是否與磁碟上的原始 ELF 檔案完全一致。藉由此機制，能精準捕捉常見的 Native Inline Hook 與 GOT 重導向竄改；同時對進入點指令特徵進行分類作為診斷遙測。

## 這個檢測在看什麼

檢測器以編譯期常數鎖定 2 個系統核心函式庫共 14 個關鍵函式（`kLibraryTargets`，`prologue_scanner.cpp` 第 27-35 行）：

1. `libc.so`（預期檔名為 `libc.so`）：
   - 11 個函式：`open`、`openat`、`read`、`write`、`access`、`readlink`、`readlinkat`、`stat`、`mmap`、`mprotect`、`ioctl`
2. `libdl.so`（預期檔名包含 `libdl.so`、`linker`、`linker64`）：
   - 3 個函式：`dlopen`、`dlsym`、`dlclose`

對每一個函式進行兩階段完整性驗證：

1. **模組歸屬驗證**：透過 `dlopen` 與 `dlsym` 取得函式記憶體位址，並以 `dladdr` 反查該位址所屬的實體檔案路徑。若其檔名末端不符合預期的檔名清單（`pathHasExpectedBasename`），代表符號已被導向至其他模組，立即標記為 `MODIFIED`（原因 `resolved_outside_expected_library`）。
2. **進入點指令比對**：若所屬模組正確，呼叫 `compareLoadedAddressWithBackingElf`，讀取實體 ELF 檔的 Program Header 計算該函式在檔案內的 offset，並以 `process_vm_readv` 讀取記憶體中的前 16 個位元組（`kPrologueBytes = 16`）與磁碟位元組比對。若發現差異即判定為 `MODIFIED`。
3. **指令樣態分類**：讀取記憶體前 16 位元組進行架構指令分類（`classifyEntryPattern`），辨識是否具備 jump、branch 或 trampoline 特徵。此部分明確標記為 `diagnostic_only`（第 178、290 行），純供研究分析，不影響檢測結果。

## 觸發代表什麼

OBSERVED 代表上述 14 個受監控函式中，至少有 1 個函式的進入點指令與磁碟原始檔案不同，或符號被解析到了非預期的動態函式庫中，整體評估結果為 MODERATE。最常見的原因是行程內存在 Native Inline Hook 框架（如 Dobby、Frida、SandHook 等），在函式進入點寫入了跳躍指令。

不能推論的：
- **不能推論具體的 Hook 框架或攻擊者意圖。** 任何良性或惡意的 native hook 皆會造成相同指令不一致。
- **不能推論系統層級的提權狀態。** 這是行程內部的函式進入點竄改，與整體設備是否 root 無直接等價關係。

## 已知偽陽性來源

- **良性 Crash 防護或 APM 效能監控 SDK。** 許多廣泛使用的第三方監控套件（如 Bugly、Sentry-Native、Firebase Crashlytics 或各類 APM SDK）會在應用程式內對 `open`、`openat`、`read`、`mprotect` 或 `dlopen` 等 libc 函式安裝 inline hook，以攔截底層呼叫收集崩潰堆疊或統計耗時。這會直接改寫函式前 16 位元組，導致 `compareLoadedAddressWithBackingElf` 回報不一致（`prologue_scanner.cpp` 第 154 行），觸發 MODERATE 判定。
- **非標準 Linker 檔名造成的歸屬誤判。** 在檢查 `libdl.so` 的函式時，程式碼嚴格限制其檔名必須為 `libdl.so`、`linker` 或 `linker64`（第 33 行）。若在特定 OEM 韌體、ASan/HWASan 調試環境或特殊模擬器中，動態連結器命名為 `linker_asan` 或其他客製名稱，`pathHasExpectedBasename` 將回傳 false（第 145 行），誤將合法符號視為 `resolved_outside_expected_library` 並觸發 MODERATE。
- **動態 IFUNC 或 CPU 特定跳躍樁。** 在少數架構或特殊 libc 編譯版本中，若特定函式在載入時由 dynamic linker 透過 GNU IFUNC 重寫進入點跳轉至特定指令集最佳化實作，亦可能產生指令分歧。

## 看不到什麼

- **14 個函式以外的 Native Hook。** 檢測範圍僅限上述寫死的 14 個函式。若注入模組掛鉤其他 libc 函式（如 `connect`、`fork`、`execve`、`kill`）或 ART 虛擬機內部函式，本檢測完全無法察覺。
- **深度 Inline Hook（16 位元組之後）。** 本檢測僅嚴格比對前 16 個位元組（`kPrologueBytes = 16`，第 19 行）。若 Hook 框架將跳躍指令置於函式位址 +16 位元組之後（例如中段 hook），將因超出檢查範圍而漏報。
- **直接系統呼叫（Direct Syscall）。** 攻擊者若透過內嵌組合語言直接發起 `svc #0` 系統呼叫，完全繞過 libc 函式進入點，本檢測無法防禦。
- **核心層或 Seccomp 攔截。** 在核心空間或透過 seccomp-bpf 進行的呼叫攔截不修改使用者空間程式碼，本檢測無法觀察。

## 建議處置

| 強度 | 建議 |
|---|---|
| MODERATE | 檢測到關鍵 libc/libdl 函式進入點被改寫或重導向。強烈建議先審視 App 本身是否有引入帶有 Native Hook 特性的 Crash 收集或效能分析 SDK。若排除合法 SDK 因素，應視為環境受執行期注入工具（如 Frida、Dobby）操控，結合其他 domain 訊號評估風控處置。 |
| NOT_OBSERVED | 14 個監控函式的進入點與原始 ELF 檔案完全一致且歸屬正確。 |
| INCONCLUSIVE | `/proc/self/maps` 無法讀取、或任一受監控函式無法載入/解析，判定為收集不完整。 |

## 成本

- 對 `libc.so` 與 `libdl.so` 呼叫 `dlopen` 與 `dlclose`。
- 執行 14 次 `dlsym` 與 `dladdr` 符號解析。
- 讀取 `/proc/self/maps` 一次。
- 讀取目標 ELF 檔案標頭與對應 offset 的 16 位元組，並透過 `process_vm_readv` 讀取記憶體 16 位元組。
- 不 fork 任何子行程。無須任何 AndroidManifest 設定。

- **不改變它所讀取的記憶體。** 函式開頭位元組以 `SelfMemoryReader`（寫入 pipe 再讀回）讀取。2026-09-14 之前
  使用 `process_vm_readv`，在 Linux 4.19 的 Redmi 13C 上會使 `libc.so` 約 28 kB 程式碼頁變成 Private_Dirty —— 已
  超過 `ZYGISK_SMAPS` 的 8 kB 門檻。改用 pipe 後為 0 kB，且仍取得全部 14 個函式的入口樣式。

## Evidence units

### prologue-scanner.entry-integrity

核心信號單元。記錄 14 個受監控函式的符號解析狀態、實際解析路徑、磁碟 ELF 偏移量與位元組比對結果。若函式被重導向至非預期庫或前 16 位元組與磁碟不符，狀態標記為 `modified`，推動 MODERATE 判定。

### prologue-scanner.entry-pattern

診斷專用單元（`diagnostic_only`）。記錄函式進入點前 16 位元組的十六進位字串（`entryBytesHex`）與架構樣態分類（如 `branch_like`、`trampoline_like`、`expected_prologue`、`ordinary`）。此單元僅供深入研判與離線分析使用，不獨立影響檢測判定。
