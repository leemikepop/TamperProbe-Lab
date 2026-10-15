# Memory FD Anomaly

交叉比對進程記憶體映射（`/proc/self/maps`）與開啟的檔案描述符（`/proc/self/fd`），尋找具備可執行權限的記憶體匿名檔案（`memfd`）、共享記憶體（`ashmem`）以及磁碟已被刪除（`(deleted)`）的可執行映射。攻擊者與動態注入框架常透過在記憶體中建立匿名檔案或載入後立即自磁碟刪除檔案來規避靜態檔案系統掃描；本檢測將帶有明確工具標記或可疑目錄來源的產物歸為 finding，其餘無標記的通用匿名產物則保留為研究遙測候選（candidates），不影響評估結果。

## 這個檢測在看什麼

本檢測執行兩個 procfs 來源的相互關聯：

- **記憶體映射（`/proc/self/maps`）分析**：
  - 檢視所有具備執行權限（`entry.executable`）的映射段。
  - 自動排除 14 個良性執行時期產物（`jit-cache`, `jit-code-cache`, `jit-zygote`, `dalvik-`, `webview`, `chromium`, `v8-code`, `wasm-code`, `gralloc`, `hwui`, `skia`, `fontmap`, `gfxstats`, `fresco`）。
  - 若為 `memfd:` 或 `/dev/ashmem`：
    - 比對 9 個注入工具關鍵字：`frida`, `gum-js`, `gadget`, `linjector`, `zygisk`, `riru`, `lspd`, `lsposed`, `xposed`。若命中，列為 `direct_marker` 並計入 `findings`；未命中者列為 `generic_candidate` 僅記入 `candidates`（不影響判定）。
  - 若為已刪除檔案（`entry.deleted`）：
    - 檢查是否命中上述 9 個工具關鍵字，或來自可疑可執行路徑（`/data/adb/` 或 `/data/local/tmp/`）。命中者列入 `findings`；未命中者列入 `candidates`。
- **檔案描述符（`/proc/self/fd`）走訪**：
  - 走訪 `/proc/self/fd` 連結目標，過濾出目標為 `memfd` 且非上述良性產物的描述符。
  - 比對 9 個注入工具關鍵字，命中者計入 `findings`，其餘計入 `candidates`。

## 觸發代表什麼

- 若 `findings` 非空（即發現帶有明確注入工具特徵的 memfd/ashmem 或來自 `/data/adb/`、`/data/local/tmp/` 的已刪除可執行映射）：判定為 MODERATE（`moderateObserved()`）。
- 若 `findings` 為空，且 maps 與 fd 目錄皆正常讀取：判定為 NOT_OBSERVED。
- 若 maps 不可用或 fd 目錄無法讀取：判定為 INCONCLUSIVE。

不能推論的：
- **不能將 candidates 視為受到篡改。** 未匹配特定特徵字串的匿名可執行 memfd 屬於研究候選，可能來自遊戲 JIT 或自訂引擎。
- **不能推論注入已成功執行業務邏輯劫持。** 僅代表記憶體中存在該工具模組之鏡像。

## 已知偽陽性來源

- **包含關鍵字子字串的合法套件**（`isInstrumentationMarker`）：關鍵字列表中包含通用的單詞如 `gadget` 或 `lspd`；若第三方合法函式庫（例如特定硬體外設的 USB gadget 管理庫、或命名巧合的 SDK）以 memfd 方式加載或映射，會誤觸發 `direct_marker`。
- **開發測試時由 `/data/local/tmp/` 執行的自動化測試**（`isSuspiciousSource` 與 fd 掃描迴圈）：工程團隊透過 adb push 執行檔至 `/data/local/tmp/` 執行單元測試或 benchmark，若該執行檔在執行中自我刪除或更新，會觸發 `suspicious_source`。

## 看不到什麼

- **隨機化或乾淨命名的 memfd 注入**：若惡意模組將 memfd 命名為一般系統函式庫名稱（如 `memfd:libc.so`）或純隨機字串，且不包含 9 個特徵關鍵字，該映射將僅被記錄為 `generic_candidate`（遙測記錄），評估結果依然為 NOT_OBSERVED。
- **重新鏈結並抹除已刪除標記的模組**：若注入工具在載入後將 VMA（Virtual Memory Area）改寫名稱，或透過特定核心模組修改 procfs 輸出，檢測器無法在 maps 中看見。
- **procfs 存取受限**：若 `/proc/self/maps` 或 `/proc/self/fd` 遭到過濾，檢測回傳 INCONCLUSIVE。

## 建議處置

| 強度 | 建議 |
|---|---|
| MODERATE | 記憶體中明確出現知名動態注入工具（如 Frida、Zygisk、LSPosed）的執行段或來自 `/data/adb/` 的孤立執行映射，強烈暗示進程已被注入，建議提高風險等級或阻斷敏感交易。 |
| NOT_OBSERVED | 未發現帶有已知標籤的可疑記憶體描述符或刪除映射。請注意 `candidates` 陣列中的純匿名段僅供離線分析，不代表異常。 |
| INCONCLUSIVE | `/proc/self/maps` 或 `/proc/self/fd` 無法完整讀取，視為收集失敗。 |

## 成本

- 完整讀取並解析 `/proc/self/maps` 內容。
- 遍歷 `/proc/self/fd` 目錄（`opendir` / `readdir`）並對每個描述符執行 `readlink`。
- 純記憶體字串比較與結構過濾，0 子行程，0 執行緒。
- 整合者不需要在 `AndroidManifest.xml` 中配置任何權限或設定。

## Evidence units

### memory-fd.executable-artifact

記錄進程記憶體中探測到的可執行 memfd、ashmem 以及已刪除的可執行映射。區分為影響判定的 `findings`（`direct_marker` 與 `suspicious_source`）與僅供研究分析的 `candidates`（`generic_candidate`），並包含記憶體區間、權限字串與檔案描述符目標路徑。
