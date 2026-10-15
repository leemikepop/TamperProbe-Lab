# System Property Source Integrity

同一個 Android 系統屬性，透過七條互相獨立的路徑各讀一次，比對答案是否一致；同時直接解析
property area 的原始位元組，檢查 Trie 結構有沒有被改寫過的痕跡。`resetprop` 這類工具會就地改寫
屬性，但很難讓所有讀取路徑同時說謊 —— 不一致的那條路徑就是被動過手腳的那一條。

## 這個檢測在看什麼

**來源交叉比對。** 每個受監控屬性會從以下來源各取一次值：

| 來源 | 機制 | 信任位置 |
|---|---|---|
| `proc_cmdline` | `/proc/cmdline` 與 `/proc/bootconfig` 的 `androidboot.*` | 核心，唯一在使用者空間之下 |
| `property_area:<context>` | 直接解析 bionic 已映射的 property area 位元組 | 原始資料，繞過 accessor |
| `bionic` | `__system_property_find` + `__system_property_read_callback` | 行程內 native accessor |
| `bionic_legacy` | `__system_property_get` | 行程內 native accessor（舊路徑） |
| `getprop` | fork 出的 `getprop` 子行程 | 另一個行程 |
| `android_system_properties` | `android.os.SystemProperties.get` | Java API |
| `android_build` | `android.os.Build` 靜態欄位 | 行程啟動時的快照 |

強度不看「有幾條不一致」，而是看**哪一條是離群值**，以及該不一致跨越了多遠的信任邊界。

**Property area 結構檢查。** 直接解析映射進來的 property area，走訪 Trie 並標記每一塊被引用的
配置區間；沒有被任何節點引用、卻仍被計入 `bytes_used` 的區間即為孤兒配置，是屬性被改寫或刪除後
留下的物理痕跡。

## 觸發代表什麼

依離群來源分級：

| 離群來源 | 讀法 | 強度 |
|---|---|---|
| `proc_cmdline` | 核心記錄的開機參數與使用者空間屬性矛盾 | STRONG |
| `property_area` | 原始位元組與 bionic accessor 說法不同 —— accessor 在對我們說謊 | STRONG |
| `bionic` / `bionic_legacy` | native accessor 與其他所有讀取者不同 | STRONG |
| `android_system_properties` / `getprop` | Java API 被 hook，或另一個行程讀到不同的值 | MODERATE |
| `android_build` | 屬性在本行程啟動之後才被改動 | WEAK |
| 孤兒 Trie 配置 | property area 內有被棄置的節點 | STRONG |

不能推論的：**不能推論是哪個工具**。任何在讀取路徑上做中介的實作都會產生同樣的分歧。

## 已知偽陽性來源

- **格式差異而非語意差異。** 值在比對前會先 trim、轉小寫，布林型屬性再做別名正規化
  （`1` / `true` / `locked` / `yes` / `green` 視為同一值）。這個名單是編譯期常數，
  若某 OEM 對名單外的屬性用了不同寫法，會產生誤判。
- **超長屬性。** `__system_property_get` 對超過 `PROP_VALUE_MAX`（92 bytes）的值會回傳固定的
  提示字串而非真值。該字串在比對前會被丟棄，否則 `ro.build.fingerprint` 之類的屬性會在每一台
  裝置上都不一致。
- **屬性值內含 NUL（潛在，刻意未處理）。** `__system_property_get` 回傳的是存放長度，可能包含值
  內部的 NUL；`bionic_legacy` 來源保留這個長度，其他來源（callback、`getprop`、Java）則讀到 NUL
  就停。2026-09-24 量到一支乾淨、上鎖的 Xiaomi 13T Pro 把 `ro.boot.vbmeta.digest` 存成 64 個十六進位
  字元加一個 NUL。若被比對的屬性也這樣存放，`bionic_legacy` 會成為唯一的不同意見。目前比對清單中
  沒有屬性出現這種情形。由於兩個 bionic 入口之間的分歧正是本檢測判斷 hook 的依據，這裡沒有截斷；
  若一筆 mismatch 的唯一差異是結尾的 NUL，應視為這個情形，而不是竄改。
- **`android.os.Build` 快取語意。** Build 欄位在類別初始化時就固定，屬性在那之後被合法改動
  （例如系統服務更新）就會分歧。因此只納入 AOSP 以單一屬性無條件初始化的四個欄位
  （`ro.build.{type,tags,fingerprint,id}`），`ro.product.*` 系列因為有分區 fallback 邏輯而排除，
  且此方向只給 WEAK。
- **非典型 property area 版面。** 孤兒配置的判定假設標準 bionic Trie 版面；客製化實作可能誤判。

## 看不到什麼

- **一致地竄改所有路徑的實作。** 如果所有讀取路徑都被統一改寫，交叉比對就沒有分歧可看。
- **僅大小寫或空白差異的偽造。** 正規化為了壓掉 OEM 格式雜訊，同時也放過了只改大小寫的偽造。
- **開機參數不可得的裝置。** 實機觀測到 `/proc/cmdline` 對 `untrusted_app` 是 Permission denied
  且該 build 沒有 `/proc/bootconfig`（Redmi 13C、Android 13），此時 STRONG 的核心層級完全無法取得。
- **未被監控的屬性。** 只比對 `securityPropertyKeys()` 清單內的屬性。
- property area 目錄無法列舉（現行 Android 對 app 一律拒絕），改由 `/proc/self/maps` 取得
  bionic 自己的映射；**只有本行程碰過的 context 會被映射**，沒碰過的 context 看不到。

## 建議處置

| 強度 | 建議 |
|---|---|
| STRONG | 高可信度的環境竄改訊號。核心 vs 使用者空間、或原始位元組 vs accessor 的矛盾很難用良性原因解釋，建議納入風險決策。 |
| MODERATE | Java 層或跨行程分歧，建議與 `runtime-integrity` 的結果合併判讀。 |
| WEAK | 僅代表屬性在行程啟動後改變，單獨不足以做判斷。 |
| NOT_OBSERVED | 只代表被監控的屬性在可得來源上一致，不代表屬性未被竄改（見上方盲區）。 |

payload 的 `comparisons[].outlierSources` 會標出實際分歧的來源，`overview.strongestFinding`
給出本次最高強度，`areaSummary` 則是 property area 的解析統計。

## 成本

- 每個受監控屬性向七個來源各讀一次；property area 需解析所有已映射 context
  （實機觀測 68 個），一次掃描的量級。
- **會 fork 一個 `getprop` 子行程**（2 秒逾時保護）。這是唯一會啟動外部行程的來源；
  它的價值在於提供一個不受行程內 hook 影響的觀察點。
- payload 已裁剪：只輸出解析失敗或含孤兒配置的 property area（上限 16 個、每個最多 8 段區間），
  其餘以 `areaSummary` 計數表示。實機 payload 約 7 KB。
- 整合者不需要任何設定。

## Evidence units

### system-properties.source-consistency

承載來源交叉比對。finding id 對應離群方向：`boot_property_inconsistency`（核心層）、
`property_accessor_contradiction`（原始位元組 vs accessor）、`property_source_mismatch`
（Java API 或跨行程）、`property_snapshot_drift`（`android.os.Build` 快照落差）。
多數值視為參考值、與其分歧者視為離群；平手時以第一個出現的值為準，讓分類保持決定性，
而不假裝知道哪一個才是真的。

### system-properties.area-layout

承載 property area 的結構完整性。走訪 Trie 標記所有被引用的配置後，剩下未被引用卻仍計入
`bytes_used` 的區間即為孤兒配置（`prop_area_unreferenced_hole`，STRONG）。
這是屬性被 `resetprop` 覆寫或刪除後留下的物理痕跡，不依賴任何數值門檻。
若 property area 無法解析，此 unit 會回報收集失敗而非陰性結果。
