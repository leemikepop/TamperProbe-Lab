# Runtime Instrumentation

跨通道綜合探測行程內部的可移植運行時痕跡，涵蓋 `/proc/self/maps` 記憶體映射、`/proc/self/fd` 檔案描述符、`/proc/self/task/*/comm` 執行緒名稱，以及 `dl_iterate_phdr` 動態連結器列舉清單，比對是否存在 20 個已知的 Hook 與注入工具特徵字串。同時收集通用運行時異常（如 GLib 相關執行緒與未具名執行檔記憶體映射）作為診斷遙測。

## 這個檢測在看什麼

檢測器透過四條相互獨立的行程內部觀察通道進行掃描：

1. **`/proc/self/maps` 映射分析**：掃描所有記憶體區段的路徑與權限。
2. **`/proc/self/fd` 描述符分析**：透過 `readdir` 列舉所有開啟的描述符，並以 `readlink` 解析其指向的目標路徑。
3. **`/proc/self/task/*/comm` 執行緒分析**：走訪所有執行緒目錄並讀取其 `comm` 執行緒名稱。
4. **`dl_iterate_phdr` 連結器分析**：列舉所有經由動態連結器載入的共用物件路徑。

比對邏輯分為兩類：

- **直接標記比對（Direct Markers，`runtime_instrumentation.cpp` 第 25-40 行）**：
  在上述四個通道中，將字串轉為小寫後，搜尋以下 20 個工具候選字串並標記其歸屬框架：
  - `playcurl`、`playintegrityfix`、`libpif`、`pif`（Play Integrity Fix）
  - `trickystore`（TrickyStore）
  - `shamiko`（Shamiko）
  - `zygisk_lsposed`、`lsposed`、`lspd`（LSPosed）
  - `magiskhide`（MagiskHide）
  - `frida`、`gum-js`、`frida-gadget`（Frida）
  - `linjector`（linjector）
  - `zygisk`（Zygisk）
  - `riru`（Riru）
  - `xposed`（Xposed）
  - `edxp`（EdXposed）
  - `sandhook`（SandHook）
  - `yahfa`（YAHFA）
- **通用異常遙測（Generic Anomalies，第 48、51-56 行）**：
  記錄名稱為 `gmain`、`gdbus` 或 `pool-spawner` 的異常執行緒，以及路徑包含 `memfd:` 且具備執行權限（排除 JIT cache）的匿名可執行記憶體區段。此部分僅作為研究遙測（`assessmentImpact: "telemetry_only"`，第 200 行），不影響評估結果。

## 觸發代表什麼

OBSERVED 代表在記憶體映射、檔案描述符、執行緒名稱或連結器模組中，至少命中一個已知的直接特徵字串，整體評估為 MODERATE。這表示行程內部極可能存在活躍的 Hook 工具、注入框架或隱藏模組。

不能推論的：
- **不能推論系統已被完全 root。** 某些注入工具（如 Frida Gadget、免 root Xposed）可在未取得 root 權限的環境下直接注入應用程式。
- **不能推論裝置層級的整體安全狀態。** 標記僅代表當前行程內部的觀察結果。

## 已知偽陽性來源

- **過短的特徵字串缺乏邊界檢查。** 比對邏輯採用小寫子字串搜尋 `lowered.find(candidate.marker) != std::string::npos`（`runtime_instrumentation.cpp` 第 42 行）。清單中的 `"pif"`（第 39 行）僅有 3 個字元，若任何檔案路徑、執行緒名稱或描述符路徑包含 `pif`（例如英文單詞 `epifany`、`spiffy`、`typification`、`amplifier`、Linux 的 `...epoll_pfd...`、含有 `.pif` 的副檔名或字型檔），皆會無條件命中並被標記為 "Play Integrity Fix"，直接觸發 MODERATE 判定。
- **其他短特徵字串碰撞。** `"edxp"`（第 37 行）與 `"riru"`（第 35 行）亦為 4 字元無邊界比對，在特殊的套件名稱或第三方程式庫路徑中存在潛在的字串碰撞風險。
- **合法整合 GStreamer 或 GLib 的應用程式。** 雖然通用異常目前設定為遙測，但若未來規則提升，使用 GLib/GStreamer 的合法應用程式會正常產生名為 `gmain` 或 `gdbus` 的工作執行緒（第 48 行）。

## 看不到什麼

- **隨機化檔名與自訂編譯。** 攻擊者若自行編譯 Frida 或 Zygisk 模組，並將輸出函式庫與執行緒名稱全部更改為隨機字串（避開上述 20 個關鍵字），本檢測的直接標記比對將完全沉默。
- **完全內存加載且無符號的注入。** 不透過動態連結器、不產生常規檔案描述符且將記憶體標記抹除的完全內存注入技術。
- **核心層 procfs 過濾。** 若底層安裝了可過濾 `/proc/self/maps`、`/proc/self/fd` 與 `/proc/self/task` 的核心模組（如 Shamiko 正常運作狀態），相關字串在讀取時已被剔除。

## 建議處置

判讀前務必於自有使用者群體中校準觀測分佈。

| 強度 | 建議 |
|---|---|
| MODERATE | 命中直接工具標記。應檢視 payload 中 `directMarkers` 的 `channel`、`value` 與 `marker`。若命中標記為 `pif` 等較短字串，需人工比對是否為單詞誤判；若命中 `frida-gadget` 或 `zygisk_lsposed` 等具體長標記，可視為高風險注入信號。 |
| NOT_OBSERVED | 四個通道皆可讀取，且未發現 20 個已知特徵標記。不保證環境沒有經過名稱混淆的注入工具。 |
| INCONCLUSIVE | `/proc/self/maps`、`/proc/self/fd`、`/proc/self/task` 任一通道無法讀取，或 public linker 物件數量為 0，視為收集不完整。 |

## 成本

- 讀取並解析 `/proc/self/maps` 一次。
- 走訪 `/proc/self/fd` 目錄並對每個開啟的描述符執行 `readlink`。
- 走訪 `/proc/self/task` 目錄並對每個執行緒讀取其 `comm` 檔案。
- 透過 `dl_iterate_phdr` 列舉所有載入的動態庫。
- 不 fork 任何子行程。整合者無須在 `AndroidManifest.xml` 中進行設定。

## Evidence units

### runtime-instrumentation.direct-marker

承載四個通道中命中 20 個直接特徵字串的觀測結果。記錄來源通道（`maps`、`fd`、`thread`、`linker`）、原始數值（`value`）、匹配標記（`marker`）與推斷歸屬（`attribution`），推動 MODERATE 判定。

### runtime-instrumentation.generic-anomaly

承載通用異常遙測（`telemetry_only`）。記錄符合 GLib 執行緒名稱（`gmain`、`gdbus`、`pool-spawner`）或未具名可執行 `memfd:` 的記憶體區段。純供後續分析使用，不影響當前檢測評估。
