# Emulator System Profile

檢查 Android 系統屬性中宣告的 QEMU 虛擬硬體平台標記（如 Goldfish、Ranchu、VirtualBox）、模擬器產品型號、顯示與相機模擬服務，並比對系統建置指紋（ro.build.fingerprint）是否符合通用模擬器樣式。這項檢測旨在辨識系統層級公開宣告的模擬器環境。

## 這個檢測在看什麼

檢測器依序透過 Bionic 的 `__system_property_get` 查詢並比對 24 項 QEMU 屬性規則與建置指紋：

1. **QEMU 與虛擬硬體屬性規則（24 項）**（第 46-71 行）：
   - **STRONG 規則（10 項）**：
     - `ro.kernel.qemu` == `"1"`
     - `ro.boot.qemu` == `"1"`
     - `ro.hardware` 包含 `"goldfish"`、`"ranchu"`、`"vbox86"` 或 `"cheets"`
     - `ro.product.board` 包含 `"goldfish"` 或 `"ranchu"`
     - `ro.boot.hardware` 包含 `"goldfish"` 或 `"ranchu"`
   - **MODERATE 規則（14 項）**：
     - `ro.product.model` 包含 `"sdk_gphone"`、`"Android SDK built for x86"`、`"Emulator"` 或 `"google_sdk"`
     - `ro.product.device` 包含 `"generic"`
     - `ro.product.name` 包含 `"sdk_gphone"`
     - `ro.hardware.egl` 包含 `"emulation"` 或 `"swiftshader"`
     - `ro.boottime.init.cold_boot_wait` 非空且不為 `"0"` 或 `"false"`
     - `init.svc.goldfish-logcat`、`init.svc.goldfish-setup`、`init.svc.qemu-props` 服務狀態非空
     - `qemu.hw.mainkeys`、`qemu.sf.fake_camera` 屬性非空
2. **建置指紋比對**（第 73-82 行、第 154-172 行）：
   讀取 `ro.build.fingerprint`（若為空則嘗試 `ro.bootimage.build.fingerprint`），轉小寫後比對：
   - 是否以 `"google/sdk_gphone"`、`"generic"` 或 `"unknown/generic"` 開頭。
   - 是否包含 `"vbox86p"` 或 `"emulator"`。
   若匹配，產出 WEAK finding `emulator_build_fingerprint`。

評估時以命中之最高強度決定整體 outcome（STRONG > MODERATE > WEAK > NOT_OBSERVED）。

## 觸發代表什麼

| 判定 | 條件 | 代表意義 |
|---|---|---|
| STRONG | 命中 10 項硬體規則之一（QEMU 標誌為 1，或硬體包含 goldfish/ranchu/vbox86/cheets） | 系統直接於核心或引導層面宣告運行於 QEMU、Goldfish、Ranchu、VirtualBox 或 ChromeOS 容器。 |
| MODERATE | 命中 14 項產品型號、虛擬驅動或模擬服務規則之一 | 系統屬性包含模擬器專屬的型號標記或背景支援服務。 |
| WEAK | 僅建置指紋符合泛用模擬器前綴或關鍵字 | 映像檔指紋來自 AOSP 通用樣板或 SDK 模擬器建置產物。 |

不能推論的：
- **不能推論裝置已 root。** 許多官方 SDK 模擬器為乾淨的原廠開發映像檔，無 root 權限。
- **不能推論使用者具有惡意。** 開發者進行偵錯或自動化測試時必然使用此類映像檔。

## 已知偽陽性來源

- **ChromeOS ARC 容器環境（STRONG 偽陽性）。** Chromebook 上運行的官方 Android 相容執行環境（ARC++ / ARCVM）將 `ro.hardware` 設為 `"cheets"`（`emulator_system_profile.cpp` 第 52 行），會直接被判定為 STRONG 模擬器。
- **實體設備上的 AOSP 通用系統映像檔（GSI）。** 開發者在實體手機刷入 Google 官方 GSI 映像檔進行相容性測試時，`ro.product.device` 常包含 `"generic"`（第 61 行）或 `ro.build.fingerprint` 以 `"generic"` 開頭（第 77 行），觸發 MODERATE 或 WEAK 誤判。
- **特定實體手機保留 `qemu.hw.mainkeys` 屬性。** 某些歷史機種或客製韌體為控制螢幕導覽鍵，在系統中宣告了 `qemu.hw.mainkeys` 屬性（第 69 行），只要值非空即觸發 MODERATE。

## 看不到什麼

- **商業模擬器之屬性偽裝（如雷電、夜神、BlueStacks）。** 主流商業模擬器通常內建「機型偽裝」功能，將 `ro.product.model`、`ro.hardware` 等屬性改寫為實體旗艦機型（如 Samsung SM 系列）並清空 `ro.kernel.qemu`，本檢測無法識別。
- **透過 `resetprop` 改寫屬性。** 本檢測僅透過 `__system_property_get` 單一介面讀取屬性（第 27 行），無法對抗屬性篡改。
- **名單外的自訂虛擬化平台。** 未使用上述名稱的客製化 QEMU 或容器環境無法被匹配。

## 建議處置

| 強度 | 建議 |
|---|---|
| STRONG | 命中底層虛擬硬體特徵。正式採用前請先在你的使用者族群上收集分佈；若確認非 ChromeOS 合法情境，可作為模擬器環境阻斷指標。 |
| MODERATE | 命中模擬器型號或輔助服務。建議與其他硬體指標交叉比對。 |
| WEAK | 僅建置指紋匹配通用模板，不建議單獨作為阻斷依據。 |
| NOT_OBSERVED | 未觀察到受檢之模擬器系統屬性。不代表一定是實體機。 |
| INCONCLUSIVE | `ro.build.fingerprint` 與 `ro.bootimage.build.fingerprint` **都讀不到**，代表屬性通道不可用。 |

> 受檢的模擬器屬性（`qemu.*`、`ro.kernel.qemu` 等）在實體機上本來就不存在，因此它們讀不到是
> 預期結果、不能用來判斷通道是否活著。建置指紋才是錨點：任何 Android 建置都有指紋，若兩個
> 指紋屬性都讀不到，代表沒有任何建置識別可供判讀。2026-09-12 之前本檢測**沒有任何路徑能回報
> INCONCLUSIVE**，且宣告了 `collectionErrors` 陣列卻從未寫入。

## 成本

- 呼叫 26 次 `__system_property_get`（24 項 QEMU 規則 + 2 項指紋屬性）。
- 行程內記憶體快速查表，不 fork 子行程，無檔案讀寫，無網路通訊。
- 整合者無需配置任何 Android 權限。

## Evidence units

### emulator-profile.qemu-properties

記錄並比對 24 項 QEMU 與 Android 模擬器專屬系統屬性規則。命中項目產出 finding id `qemu_system_property`，依規則分別指派 STRONG 或 MODERATE 強度。

### emulator-profile.build-fingerprint

記錄並比對 `ro.build.fingerprint` 與 `ro.bootimage.build.fingerprint`。若字串符合泛用模擬器樣式，產出 finding id `emulator_build_fingerprint`，強度為 WEAK。
