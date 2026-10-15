# 二進位檔案與執行環境檢測 (Binary & Context Detections)

這個目錄包含用來檢查系統中是否存在常見 Root 工具二進位檔案，以及當前執行環境是否異常的檢測機制。路徑命中只代表呼叫端目前看得到某個候選物件，不直接等同於 Root 權限可用。

## Binary artifact observation model

`SU_BINARY` 與 `BUSYBOX` 共用 `binary_artifact_probe.cpp`。每個候選路徑依序保存：

1. `access(F_OK)` 的存在性結果與原始 `errno`。
2. `lstat` 所見的目錄項型別、mode、owner、size、device 與 inode。
3. `open(O_PATH)` 後以 `fstat` 取得的 resolved-object metadata；若路徑是 symlink，這一層可和 `lstat` 區分。
4. 僅對 regular file 另外開啟 read-only descriptor，以 `fstat` 比對 device/inode 是否仍是 `O_PATH` 所解析的同一物件，再讀取最多四個 bytes。結果分類為 `elf_magic`、`other`、`truncated` 或 `empty`；`elf_magic` 只表示 magic bytes 相符，不是完整 ELF validation。

每個操作都使用 `present`、`not_found`、`denied`、`error` 或 `not_attempted` 表示可用性，並保留 `errno`。Payload schema v1 同時提供：

- `overview`：候選數、available/unavailable candidate 數、finding 數，以及 denied/error operation 數。
- `findings`：可影響 assessment 的最窄推論。
- `probes`：各路徑的原始觀測鏈。
- `foundPaths`：detector-specific payload field；public v1 由 adapter 轉成 unit report。

Detector 不會執行候選檔案或呼叫 `su -c`；能否取得 privilege 是不同的介面與風險邊界。
若至少一個候選得到可見或一致的 `not_found` 結果而沒有 finding，assessment
為 `NOT_OBSERVED/NONE`；若所有候選都只有 denial/error，則為
`INCONCLUSIVE/NONE`。部分不可用路徑仍保留在 overview 與 probes 中，不會被
轉成 finding。

## 檢測項目

### 1. SU 檔案檢測 (`su.cpp`)
- **候選來源**: 固定的傳統路徑加上目前程序 `$PATH` 中最多 32 個 absolute-directory candidates；重複路徑會去除。
- **判讀**: 固定候選的 resolved object 是 regular file、具有任一 executable mode bit、read-only descriptor 仍指向相同 device/inode，且四-byte ELF magic 相符時，形成 strong finding。`PATH` 是程序可控制的輸入，因此由 `environment_path` 產生的候選最多只形成 weak finding；只有路徑可見、物件身分改變、magic 無法確認、不是 regular file，或沒有 executable bit 時也只形成 weak finding。
- **限制**: 即使 strong finding 成立，也只表示 app view 中存在可執行格式的 `su` artifact，不證明呼叫者能成功取得 elevated privilege。

### 2. BusyBox 檢測 (`busybox.cpp`)
- **候選來源**: 檢查固定的常見 BusyBox 路徑，並使用同一套物件與 header 觀測鏈。
- **判讀**: 所有可見 BusyBox artifact 都是 weak finding。自訂 ROM、開發或維護工具也可能合法提供 BusyBox，因此 ELF 與 executable metadata 不會把它提升為 Root 的強證據。
- **限制**: 路徑不可見不代表系統沒有 BusyBox；namespace、MAC policy、hook 或 coordinated concealment 都可能改變目前 app 所見。

### 3. 執行環境上下文檢查 (`context.cpp`)
- **原理**: 檢查應用程式或系統的安全性上下文 (Security Context) 與環境變數是否異常，例如可能被植入不尋常的環境變數，或執行身分與預期不符。
- **目的**: 攻擊者可能透過修改環境變數來注入代碼或改變程式行為，此檢查有助於發現這類隱蔽的操作。
