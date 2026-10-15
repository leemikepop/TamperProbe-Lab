# Cross-Process Descriptor Forensics

檢查「核心對同一份 file descriptor table 的三種說法是否互相矛盾」。同一組描述符會分別透過
`fcntl(F_GETFD)`、`readlink("/proc/self/fd/<n>")` 與 `readdir("/proc/self/fd")` 各問一次；
這三條路徑是核心內部彼此獨立的實作，正常情況下必然一致。若某個描述符在重複取樣後仍然只被其中
一條路徑看到，就代表有人在過濾 procfs。這是**矛盾**，不是門檻比較，所以不需要任何裝置校準。

## 這個檢測在看什麼

同一件事問三次，比對答案：

| 視角 | 問法 | 走的核心路徑 |
|---|---|---|
| 描述符表 | `fcntl(fd, F_GETFD)` | 直接查 `files_struct` |
| procfs lookup | `readlink("/proc/self/fd/<n>")` | `proc_fd_link` |
| procfs iterate | `readdir("/proc/self/fd")` | `proc_readfd` |

隱藏工具常常只攔截目錄列舉（`readdir`）而忘記攔截單點查詢（`readlink`），因為前者才是
`ls /proc/self/fd` 這種「被看到」的路徑。lookup 說有、iterate 說沒有，就是這種實作的指紋。

同一套比對會在**宿主行程**和一個從 Zygote 全新 fork 出來的 helper 行程
（`:tamperprobe_fd_forensics`）各跑一次。helper 行程的描述符表很安靜，執行緒少、開關檔頻率低，
race 的機會遠低於已經跑滿 ART 與 UI 的宿主行程。

## 觸發代表什麼

OBSERVED 代表**這個行程看到的 procfs 與核心的描述符表不一致**，而且該不一致在多輪重取樣後穩定重現。
最合理的解釋是有一層東西在過濾 `/proc/self/fd`。

不能推論的：
- **不能推論是哪個工具。** 任何 procfs 過濾實作都會產生同樣的矛盾，本檢測不讀取任何工具特徵字串。
- **不能推論裝置已 root。** 過濾可能來自核心模組、LSM、容器執行環境或安全產品。
- **不能推論注入。** 這裡看的是 procfs 可見性，不是程式碼注入。

## 已知偽陽性來源

- **執行緒競態。** 另一條執行緒在兩次取樣之間開關描述符，會造成一次性的不一致。已用「同一個
  三視角簽章必須在每一輪重複出現」過濾掉；只出現一次的會被標成 `unstable` 並排除。
- **`phantom_*` 方向。** 「表說關、procfs 說開」這種反方向不一致，來自競態的機率遠高於過濾，
  因此只記錄在原始資料裡，不計入 finding、不影響 outcome。
- **procfs 整體不可用。** 若描述符表回報有開啟的描述符、但 procfs 一個都解析不出來，會被判定為
  `procfsUnusable` 並整個略過比對，而不是產生上千筆矛盾 —— 這是本檢測最糟的失效模式，已明確擋掉。
- 尚無乾淨機基線，殘餘 race 比例未知，因此強度上限壓在 MODERATE。

## 看不到什麼

- **同時過濾 lookup 與 iterate 的實作。** 兩條路徑被一致地攔截時，三視角會一致，本檢測沉默。
- **連 `fcntl` 一起攔截的核心層 hook。** 三個視角都被統一竄改就無從比對。
- **不涉及 procfs 可見性的注入。** Zygisk 模組只要不動 `/proc/self/fd`，這裡就看不到它。
- helper 行程若無法綁定（低記憶體、行程被限制），該側會標為 unavailable，宿主側仍會單獨完成比對。

## 建議處置

| 強度 | 建議 |
|---|---|
| MODERATE | 視為環境完整性訊號，建議與其他 domain 的結果合併判讀，不建議單獨作為封鎖依據。正式採用前請先在你的使用者族群上收集分佈。 |
| NOT_OBSERVED | 只代表沒觀察到 procfs 過濾，不代表環境乾淨。 |
| INCONCLUSIVE | 宿主與 helper 兩側都無法完成比對（通常是 procfs 不可用），請當作收集失敗而非陰性結果。 |

payload 的 `overview.processDivergence` 會標示「兩個行程只有一邊出現矛盾」，這是研究用欄位，
目前不影響 outcome。

## 成本

- 對 `[0, min(RLIMIT_NOFILE, 2048))` 範圍每個描述符做 2 次 syscall，加上每輪一次目錄列舉；
  候選描述符通常是 0 個，確認輪只在有候選時才跑。
- **會啟動一個額外行程**（`:tamperprobe_fd_forensics`），每次掃描存活約 2 秒後由系統回收。
- 該 service 由 library 自己的 AndroidManifest 宣告，manifest merger 會自動併入宿主 App，
  **整合者不需要做任何設定**。
- 實機觀測（Redmi 13C、Android 13）：payload 約 1 KB，整體掃描時間增加在雜訊範圍內。

## Evidence units

### zygisk-fd-forensics.descriptor-view-differential

本 detector 唯一會發出 SIGNAL 的 unit。只有兩種方向會被計為 finding：
`hidden_from_lookup`（表說開、procfs 查不到）與 `hidden_from_iterate`（查得到、列舉不到）。
兩者都必須在所有確認輪中維持同一個三視角簽章才成立。描述符的目標路徑不會原樣輸出，
只會輸出粗分類（`socket` / `pipe` / `anon_inode` / `memfd` / `device` / `system_image` /
`app_storage` / `other`，必要時加上 `+deleted`），避免把儲存路徑與 socket 對端識別資訊寫進證據。

### zygisk-fd-forensics.cross-process-trap

**Telemetry only —— 這個通道永遠不會影響 outcome，adapter 層也強制擋住。**

它忠實重現 Duck-Detector 的 cross-process FD trap：在宿主行程建立一個已 unlink 的暫存檔描述符、
寫入簽章、透過 Binder 傳給 helper 行程，再於該行程 `fstat` / `pread` / `readlink` 驗證。
之所以不採信，是因為該描述符是由 binder driver 在 helper 行程**完成 specialization 之後**才安裝進去的，
而 Zygisk 系列的描述符清理發生在 specialization 當下 —— 兩者時間上不可能相交，
因此 Duck 版本的三個陽性分支結構上不可達。保留它是為了能獨立重現並回報這個否定結果。
詳見論文 Chapter 3 的 `cross_process_fd_trap.md`。
