# Custom ROM Detection

透過讀取 Android 系統屬性（system properties），檢查當前韌體映像檔是否包含測試金鑰簽署特徵（test-keys）、是否開啟除錯模式（ro.debuggable）或關閉安全模式（ro.secure），並逐一比對 9 個知名第三方客製化 ROM（如 LineageOS、CyanogenMod、PixelExperience 等）的專屬屬性特徵。這項檢測旨在評估裝置是否運行於非原廠官方發佈的客製化韌體或工程測試環境中。

## 這個檢測在看什麼

檢測器依序透過 Bionic 的 `__system_property_get` 查詢 12 個系統屬性：

1. **建置簽署標籤（`ro.build.tags`）**：檢查字串中是否包含 `"test-keys"`（第 38-47 行），用以辨識未經原廠私鑰（release-keys）簽署的公開測試韌體。
2. **除錯模式標誌（`ro.debuggable`）**：比對值是否精準等於 `"1"`（第 50-59 行），確認系統是否全域允許 ADB 除錯與偵錯工具附掛。
3. **安全模式標誌（`ro.secure`）**：比對值是否精準等於 `"0"`（第 61-71 行），確認系統核心與 init 是否運行於非安全模式。
4. **9 個知名第三方 ROM 專屬特徵屬性**（第 74-84 行）：
   - `ro.lineage.build.version`（LineageOS）
   - `ro.cm.version`（CyanogenMod）
   - `ro.modversion`（Custom ROM 通用標記）
   - `ro.pixelexperience.version`（PixelExperience）
   - `ro.carbon.version`（CarbonROM）
   - `ro.crdroid.version`（crDroid）
   - `ro.potato.version`（PotatoProject）
   - `ro.evolution.version`（Evolution X）
   - `ro.corvus.version`（Corvus OS）

若任一 ROM 屬性非空，即計入一筆命中。總命中數（`hitCount`）若累積達 3 次或以上判定為 STRONG；命中 1 至 2 次判定為 WEAK；0 次則為 NOT_OBSERVED。

## 觸發代表什麼

| 判定 | 條件 | 代表意義 |
|---|---|---|
| STRONG | `hitCount >= 3` | 系統同時呈現多項第三方韌體或工程建置指標（例如 test-keys + debuggable=1 + 含有 LineageOS 屬性，或 test-keys + debuggable=1 + ro.secure=0），高度代表處於自訂 ROM 或重度修改的開發映像檔。 |
| WEAK | `1 <= hitCount <= 2` | 觀察到單一或少數開發/測試指標（例如僅 `ro.debuggable=1` 或僅 `ro.build.tags` 為 test-keys）。 |

不能推論的：
- **不能推論裝置已取得 root 權限。** 刷寫第三方 ROM 或使用使用者版客製韌體（如 LineageOS 官方 user build）並不等於當前行程或系統已安裝 su 或已提權。
- **不能推論遭受惡意攻擊或代碼注入。** 許多追求隱私或延長舊機壽命的使用者會主動刷入第三方 ROM。
- **不能推論特定的 root 提權框架。** 本檢測僅分析建置中繼資料，不涉及任何 Magisk、KernelSU 或 APatch 之提權通道。

## 已知偽陽性來源

- **原廠工程機與測試韌體。** OEM 內部工程開發機或使用者預覽版（developer preview / userdebug）常將 `ro.build.tags` 設為 `test-keys`（`custom_rom.cpp` 第 40 行）且 `ro.debuggable` 設為 `1`（`custom_rom.cpp` 第 52 行），此時 `hitCount` 即達 2，觸發 WEAK；若該工程映像檔同時將 `ro.secure` 設為 `0`（`custom_rom.cpp` 第 64 行），則 `hitCount` 達 3，會直接在原廠良性工程機上被判定為 STRONG。
- **模擬器映像檔。** 官方 Android SDK 模擬器預設為 userdebug 建置，通常同時具備 `test-keys`、`ro.debuggable=1` 與 `ro.secure=0`，會觸發 STRONG。
- **單純開啟除錯的使用者。** 開發者使用自身裝置開啟除錯或刷入測試版 AOSP 產物時，僅因單一指標即可觸發 WEAK。

## 看不到什麼

- **透過 `resetprop` 或 Magisk 偽造屬性。** 本檢測僅呼叫單一 `__system_property_get` API（第 15 行）。攻擊者使用 `resetprop` 或 MagiskHide/Shamiko 將 `ro.build.tags` 改寫為 `release-keys`、將 `ro.debuggable` 改寫為 `0`、`ro.secure` 改寫為 `1`，本檢測無法察覺，亦無法如 `SYSTEM_PROPERTIES_TAMPER` 進行多來源交叉驗證。
- **名單外的第三方 ROM。** 硬編碼的 ROM 屬性名單僅包含 9 個項目（第 74-84 行）；若裝置運行 GrapheneOS、CalyxOS、Paranoid Android、ArrowOS、PixelOS 或自行編譯的 AOSP，且採用 `release-keys` 與 `user` 建置配置，此檢測將回報 `NOT_OBSERVED`。
- **分區屬性（如 `ro.vendor.*`、`ro.system.*`）。** 本檢測僅讀取全域頂層屬性，不比對分區層級殘留的自訂 ROM 標誌。

## 建議處置

| 強度 | 建議 |
|---|---|
| STRONG | 裝置同時具備多項客製韌體或工程建置特徵。建議視為高風險或非標準執行環境，與 `hardware-attestation`（硬體證明）或 `runtime-integrity` 訊號合併評估。若應用程式要求嚴格的受信任硬體與官方韌體保證，可限制敏感交易。 |
| WEAK | 僅觀察到 1 至 2 項指標（常見於開發測試機或 userdebug 系統）。不建議單獨以此判定阻斷一般使用者，建議搭配其他指標觀察。 |
| NOT_OBSERVED | 監控的 12 個屬性均未命中客製化特徵。不能排除屬性已被 hook/spoof 或使用不在清單內的 ROM。 |
| INCONCLUSIVE | `ro.build.tags`、`ro.debuggable`、`ro.secure` 三個錨點屬性**一個都讀不到**，代表屬性通道本身不可用，沒有任何建置屬性可供判讀。 |

> `read_property_value` 對「屬性不存在」與「本行程讀不到」都回傳空字串，兩者無法區分，因此
> 「沒讀到」本身不構成乾淨的答案。上列三個錨點在任何 Android 建置（原廠或自訂）上都必然存在，
> 所以用它們判斷通道是否還活著。2026-09-12 之前本檢測**沒有任何路徑能回報 INCONCLUSIVE**，
> 屬性通道完全失效時會靜默回報 NOT_OBSERVED。

## 成本

- 僅進行 12 次記憶體內的 `__system_property_get` 屬性讀取。
- 不建立子行程（無 fork），不進行檔案系統 I/O，不發起網路通訊。
- 整合者不需要在 `AndroidManifest.xml` 中配置額外權限。

## Evidence units

### custom-rom.build-fingerprint

記錄並回報命中之客製化 ROM 屬性與除錯狀態。輸出 payload 包含 `buildTags`、`roDebuggable`、`roSecure` 原始值、命中總數 `hitCount`，以及每一個命中項目的 `check`、`value` 與 `detail` 描述。當 `hitCount >= 3` 輸出 STRONG，`hitCount > 0` 輸出 WEAK，否則輸出 NOT_OBSERVED。
