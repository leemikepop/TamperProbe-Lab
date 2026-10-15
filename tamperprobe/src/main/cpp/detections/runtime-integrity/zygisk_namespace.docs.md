# Dynamic Linker Namespace Audit

審計動態連結器列舉的已載入共用函式庫路徑，檢查是否存在位於異常目錄或已被刪除的模組；同時掃描 `/proc/self/task/*/comm` 尋找可疑的 Hook 框架執行緒名稱。此外，內建單行程檔案描述符隔離陷阱作為遙測，用以全面掌握執行期的動態注入痕跡。

## 這個檢測在看什麼

檢測器透過三個維度審查行程的執行期載入狀態：

1. **動態連結器命名空間與模組路徑審計（`zygisk_namespace.cpp` 第 29-61 行）**：
   透過 `dl_iterate_phdr` 列舉所有載入的 ELF 物件，檢查路徑是否包含以下 5 個可疑目錄前綴：
   - `/data/adb/`（Magisk / KernelSU 模組常見存放區）
   - `/data/local/tmp/`（除錯工具或暫存 payload 路徑）
   - `/data/data/`（應用程式私有內部儲存目錄）
   - `/data/user/`（多使用者架構下的私有儲存目錄）
   - `memfd:`（匿名記憶體檔案）
   此外，亦檢查路徑中是否帶有 `(deleted)` 標記（許多注入器在 `dlopen` 後會立即刪除實體檔案以規避磁碟掃描）。命中任一條件即記錄至 `suspiciousLibs`。
2. **執行緒名稱特徵掃描（第 68-128 行）**：
   走訪 `/proc/self/task` 目錄，讀取每個執行緒的 `comm` 檔案，轉小寫後比對是否包含以下 8 個關鍵字：
   - `zygisk`、`magisk`、`riru`、`xposed`、`lspd`、`frida`、`gum-`、`linjector`
   命中者記錄至 `suspiciousThreads`。
3. **行程內檔案描述符隔離陷阱（In-Process FD Trap，第 132-185 行）**：
   在應用程式檔案目錄（或 `/data/local/tmp`）以 `O_TMPFILE` 或 `mkstemp` 建立已 unlink 的暫存檔案描述符，寫入簽章後驗證 `fstat`、`pread` 與 `readlink`。此陷阱在程式碼中明確標註為 `telemetry_only`（第 224 行），因為單行程內微秒級的建立與驗證無法跨越 Zygote specialization 的清理邊界，僅作為診斷遙測，不推動判定。

## 觸發代表什麼

OBSERVED 代表在動態連結器清單中發現了來自可疑路徑或已刪除的函式庫，或者在執行緒清單中發現了命中 8 個特徵關鍵字的執行緒名稱，整體評估判定為 STRONG。這強烈指示行程內存在 Zygisk、Magisk、Xposed 或 Frida 等運行時注入產物。

不能推論的：
- **不能推論特定注入框架的唯一身分。** 例如路徑位於 `/data/local/tmp/` 可能來自多種不同的除錯工具或注入器。
- **不能直接推論系統已被 root。** 應用程式私有目錄載入動態庫或 Frida 注入在非 root 環境下亦可能發生。

## 已知偽陽性來源

- **應用程式合法從內部私有儲存載入 Native 函式庫。** 檢測器的 `suspiciousPrefixes` 包含了 `/data/data/` 與 `/data/user/`（`zygisk_namespace.cpp` 第 43-44 行）。許多正規應用程式為了實現動態模組載入、插件化架構、熱修復（如 Tinker、Sophix）或遊戲資源包（DLC）下載，會將 `.so` 檔案下載解壓至內部私有儲存目錄（如 `/data/data/<package>/files/` 或 `/data/user/0/<package>/app_libs/`），隨後透過 `System.load()` 或 `dlopen` 載入。這會導致路徑無條件匹配前綴（第 49 行），被列為 `suspiciousLibs` 並直接引發 STRONG 誤判！
- **正常運作中的動態函式庫更新與刪除。** 部分應用程式在升級熱修復套件時，可能先加載舊庫後在背景刪除該檔案，導致 maps/linker 中標註 `(deleted)`（第 56 行），引發誤判。
- **執行緒名稱子字串碰撞。** 執行緒名稱比對採用子字串搜尋（第 120 行），若應用程式內部執行緒名稱恰好含有 `gum-`、`riru` 等字眼（例如拼寫包含該字母組合的模組或任務名），會被標記為可疑執行緒。

## 看不到什麼

- **自訂隱蔽目錄或系統覆蓋掛載。** 若注入模組將 `.so` 放置於非 `/data/` 監控前綴的其他路徑，或透過 OverlayFS/bind mount 掛載至 `/system/lib64` 等系統目錄中，本檢測無法從路徑前綴識別。
- **手動記憶體載入（Manual-Load）且未註冊 Linker。** 攻擊者若自行實作 ELF 載入器將程式碼映射進記憶體，且不呼叫標準 `dlopen` 註冊至動態連結器，`dl_iterate_phdr` 將完全看不到該模組。
- **執行緒重命名。** 注入工具的背景工作執行緒若主動呼叫 `prctl(PR_SET_NAME)` 將執行緒改名為常見名稱（如 `pool-1-thread-1` 或 `Binder:1234_1`），執行緒掃描將被繞過。
- **核心層 procfs 隱藏。** 若環境具備核心過濾能力，使 `/proc/self/task` 無法列舉特定注入執行緒。

## 建議處置

| 強度 | 建議 |
|---|---|
| STRONG | 發現可疑載入路徑或特徵執行緒名稱。整合者務必先排查 App 本身是否有從 `/data/data/` 或 `/data/user/` 私有目錄動態載入 `.so` 的行為（如熱修復或動態功能）。若已排除 App 自身行為，應視為高可信度的運行時注入訊號納入風控。 |
| NOT_OBSERVED | 未發現可疑的函式庫路徑或特徵執行緒名稱。 |
| INCONCLUSIVE | `/proc/self/task` 無法開啟**且** `dl_iterate_phdr` 未列舉到任何共享物件 —— 兩個通道都沒有作答。 |

> 2026-09-12 之前這一列是**程式碼無法產生的宣稱**:整個 `zygisk_namespace.cpp` 裡沒有出現過
> `inconclusive` 這個字。`opendir("/proc/self/task")` 失敗時會直接回傳空結果、不留任何紀錄，
> 因此與一次健康的掃描產生完全相同的 NOT_OBSERVED。現在 payload 會記錄
> `taskDirectoryReadable` 與 `linkerObjectCount`，兩個通道皆未作答時回報 INCONCLUSIVE。

## 成本

- 透過 `dl_iterate_phdr` 列舉一次行程內已載入模組。
- 走訪 `/proc/self/task` 目錄並讀取每個執行緒的 `comm` 檔案。
- 執行一次行程內暫存檔案描述符操作（建立、寫入 28 位元組簽章、讀取與 unlink）。
- 不 fork 任何子行程。無須任何 AndroidManifest 設定。

## Evidence units

### zygisk-namespace.loaded-library-path

記錄動態連結器模組審計（`suspiciousLibs`）、執行緒名稱掃描（`suspiciousThreads`）與行程內 FD 陷阱狀態（`fdTrapStatus`，遙測）。當發現可疑函式庫或執行緒時產出 STRONG 判定，作為環境遭受執行期注入的核心依據。
