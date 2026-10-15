# Security-Relevant System Properties

讀取 Bionic 系統屬性並針對 8 項關鍵安全性規則進行判定，評估 Android 核心模式（ro.secure）、Verified Boot 啟動狀態（ro.boot.verifiedbootstate）、Bootloader 解鎖（ro.boot.flash.locked、ro.boot.vbmeta.device_state）以及除錯與金鑰建置設定；另讀取 `Settings.Global` 的 `adb_enabled`，把 0/1 以外的非標準值判為規避跡象（第 9 項規則；API 37 以上讀到的 0 是平台遮蔽值，記為 `redacted_by_platform`，不算回答）；同時收集 QEMU 模擬器與 USB/ADB 傳輸之環境態勢作為純遙測記錄。

## 這個檢測在看什麼

檢測器透過 Bionic 的原生屬性存取介面（`__system_property_find` 與 `__system_property_read_callback`），查詢兩組預定義鍵值：

1. **安全屬性集（8 個鍵值）**：
   - `ro.secure`：檢查是否明確為 `"0"`（非安全模式，MODERATE，第 90-97 行）。
   - `ro.boot.verifiedbootstate`：檢查是否明確為 `"orange"` 或 `"red"`（未受信任之開機狀態，MODERATE，第 98-107 行）。
   - `ro.boot.flash.locked`：檢查是否明確為 `"0"`（Bootloader 刷寫鎖定已解除，MODERATE，第 108-115 行）。
   - `ro.boot.vbmeta.device_state`：檢查是否明確為 `"unlocked"`（VBMeta 裝置狀態已解鎖，MODERATE，第 116-125 行）。
   - `service.adb.root` 與 `ro.debuggable`：檢查是否兩者同時為 `"1"`（debuggable 建置上啟用了 ADB root，MODERATE，第 127-138 行）。
   - `ro.debuggable`：單獨檢查是否為 `"1"`（系統開啟除錯模式，WEAK，第 140-147 行）。
   - `ro.build.type`：檢查是否為 `"eng"` 或 `"userdebug"`（工程或開發者建置版本，WEAK，第 148-156 行）。
   - `ro.build.tags`：檢查是否包含 `"test-keys"` 或 `"dev-keys"`（開發簽名金鑰，WEAK，第 157-165 行）。

2. **環境態勢屬性集（4 個鍵值，純遙測）**：
   - `ro.boot.qemu`、`ro.kernel.qemu`：比對是否為 `"1"`（記錄為 QEMU 模擬器態勢）。
   - `sys.usb.config`、`persist.sys.usb.config`：比對是否包含 `"adb"` 功能項目。
   - `service.adb.root`：比對在非 debuggable 建置下是否請求了 root。

3. **`Settings.Global.adb_enabled`（第 9 項規則，`adb_enabled_nonstandard`）**：
   - 透過 JNI 呼叫 App 自己的 `ContentResolver` 與 `Settings.Global.getString`（`dangerous_props.cpp` 第 48-112 行），保留原始字串而不是 `getInt()`，因為「無法解析的值」本身也是判定對象。`ADB_ENABLED` 是公開且標註 `@Readable` 的設定，一般第三方 App 不需權限即可讀取（Android 13 至 16 的 AOSP 原始碼皆同）；Android 17 QPR1 起讀取仍會成功，但值被平台遮蔽，見下方「平台遮蔽」。
   - 判定依據是 AOSP 自身的語意：Settings UI（SettingsLib `AbstractEnableAdbPreferenceController`）與 `AdbService.systemReady()` 只會寫入 `1` 或 `0`；`AdbService.AdbSettingsObserver` 則以 `getInt(ADB_ENABLED, 0) > 0` 決定是否啟動 adbd。因此 `settings put global adb_enabled 3` 會讓 adbd 照常運作，但讓整合者常見的 `getInt(ADB_ENABLED) == 1` 檢查失效。0/1 以外的值沒有正當來源，值本身就是刻意規避的證據，與是哪個工具寫入無關。
   - 分類比照 `Integer.parseInt`（`property_detector_logic.cpp` 第 177-205 行）：`0`/`1` 為標準值，不產生 finding（開啟 ADB 是正常開發者行為，維持「單純 ADB 開啟只是遙測」的原則）；大於 1 的整數為 `nonstandard_enabled`；負整數為 `nonstandard_disabled`；無法解析（含空字串、超出 32 位元）為 `unparsable`。
   - 強度（第 232-276 行）：預設 WEAK；只有 `nonstandard_enabled` 且 `sys.usb.config` 或 `persist.sys.usb.config` 含有 `adb` 功能項目（佐證 adb 確實在運作）時升為 MODERATE。負值與無法解析的值依 AOSP 語意會被系統當成停用，達不到「adb 照開、檢查失效」的效果，因此固定為 WEAK。
   - 讀取失敗（JNI、`ContentResolver` 或 provider 例外）記為 `source=settings_global`、`property=adb_enabled` 的 collection error，只標記 `environment-posture` unit，且不計入 `availableRuleCount`，絕不當成乾淨。設定列不存在（`getString` 回傳 null）視為已回答：AdbService 與 Settings UI 都把它讀成 0。

4. **平台遮蔽（API 37 以上，`redacted_by_platform`）**：
   - 事實：Google 的 `Settings.Global` 參考文件對 `ADB_ENABLED`（以及 `DEVELOPMENT_SETTINGS_ENABLED`）寫著 "This will always return 0 for all third-party apps."（2026-10-08 直接讀取參考頁確認此句，頁面標示最後更新 2026-08-03；文件本身沒有標註從哪個版本開始）。把這個行為對到版本的是外部回報與本專案實測：KeyMapper issue #2289（Pixel 8、CalyxOS 8.0.4.21／Android 17：`adb` 查得 `development_settings_enabled=1`，第三方 App 讀到 0，回報者指出控制的 flag 是 `android.provider.enable_redacted_value_for_readable`）；Shizuku-Next issue #4（Pixel 9 Pro、Android 17 QPR1 build `CP3A.260905.009`；依論文工作區紀錄轉引，本次未重新讀取原文）；另有 Shizuku 修補 repo 回報 Pixel 10 Pro 上即使持有 `WRITE_SECURE_SETTINGS` 仍讀到 0（同樣轉引自論文工作區紀錄）。論文工作區 `evaluation/followup_2026/adb_enabled_2026-10-08/` 的實測：Pixel 7 跑 Android 17 QPR1（API 37、`CP3A.260905.009`），`adb shell settings get global adb_enabled` 為 1、再設成 3，Sample App 在 18 份匯出中一律讀到 0，規則因此從未觸發；Redmi 13C（Android 13）讀到真值，設成 3 時判為 MODERATE。
   - 規則（`property_detector_logic.cpp` 第 217-230 行，`dangerous_props.cpp` 第 130-134 行）：以 `android_get_device_api_level()` 取得 API level（讀 `ro.build.version.sdk`，與 `Build.VERSION.SDK_INT` 同源）。API level ≥ 37，或讀不到 API level（回傳 −1，無法排除遮蔽）時，`Integer.parseInt` 讀成 0 的值（`0`、`00`、`+0`、`-0`）改記為 `state=redacted_by_platform`：observation 不寫 `value`、附上 `apiLevel`，另發出一筆 `collectionWarnings`（`source=settings_global`、`property=adb_enabled`、`state`、`apiLevel`、`detail`，第 154-184 行）。不產生 finding，也不計入 `availableRuleCount`。
   - 為什麼記成 warning 而不是 error：讀取本身成功了，是平台拒絕給出答案。`environment-posture` 的 issue route（`property=adb_enabled`）同樣認領它，所以這個 unit 變成 `PARTIAL`（issue code `DANGEROUS_PROPS.environment-posture.collectionWarnings`），`security-posture` 維持 `COMPLETE`。只要任一項屬性規則有回答，detector 仍是 `NOT_OBSERVED`；只有屬性規則也全部無法取得時才是 `INCONCLUSIVE`。
   - 非 0 值仍是回答：遮蔽只會產生 0，所以 API 37 以上讀到 `1`、`3`、負值或無法解析的值都不可能出自遮蔽，代表的是裝置真值：QPR1 之前的 base Android 17，或關閉該 flag 的 build，仍可能回傳真值（本專案沒有在這類 build 上實測過），因此照第 3 項的規則分級。
   - 刻意的保守取捨：QPR1 沒有提高 API level，app 也無法得知 flag 狀態，所以在不遮蔽的 API 37 build 上，真的 0 也會被記成 `redacted_by_platform`。代價只是少算一個回答（0 本來就不產生 finding），不會讓判定變得較不保守。
   - `getString` 回傳 null（設定列不存在）不是遮蔽的輸出，在 API 37 以上仍視為已回答。

環境態勢遙測（telemetry）僅供研究與診斷，明確排除於 assessment 計算之外（`dangerous_props.cpp` 第 220-221 行）；`adb_enabled_nonstandard` 則是規則，會參與 assessment。整體檢測最高強度上限為 MODERATE。

## 觸發代表什麼

| 判定 | 條件 | 代表意義 |
|---|---|---|
| MODERATE | 命中 5 項安全規則之一（ro.secure=0、verifiedbootstate 為 orange/red、flash lock 為 0、vbmeta 為 unlocked、或 adb root + debuggable） | 系統開機驗證鏈被解鎖、核心安全邊界被關閉，或處於具備特權除錯通道之環境。 |
| MODERATE | `adb_enabled` 為大於 1 的整數，且 USB 設定含有 `adb` | 有人刻意把 ADB 開關寫成非標準值，讓 `== 1` 檢查失效而 adbd 仍在運作。 |
| WEAK | 僅命中開發型指標（ro.debuggable=1、build.type 為 eng/userdebug、或 build.tags 含有 test/dev-keys） | 系統採用開發者建置配置，多見於工程樣機或使用者自編韌體。 |
| WEAK | `adb_enabled` 為 0/1 以外的值，但缺少 USB 設定佐證，或為負值、無法解析 | 設定被非 UI 途徑改寫過；是否真的維持 adb 運作無法由此確認。 |

不能推論的：
- **不能推論特定 root 工具。** 任何解鎖 Bootloader 或啟用除錯的設備皆會觸發相應判定，本檢測無法識別具體的 root 提供者。
- **不能推論應用程式已遭代碼注入。** 此處僅反映作業系統建置與引導安全態勢。
- **不能將 USB/ADB 開啟視為攻擊。** ADB 傳輸遙測與 `adb_enabled=1` 都不影響 assessment 判定；只有 0/1 以外的值才是 finding。
- **不能從 `adb_enabled_nonstandard` 推論 root。** 寫入 global setting 只需要 `WRITE_SECURE_SETTINGS`，`adb shell settings put` 不需 root 就能做到；這個 finding 證明的是刻意規避 ADB 檢查，不是 root 存在。
- **不能把 `redacted_by_platform` 讀成任何一種裝置狀態。** 它只表示這個通道在 API 37 以上沒有回答：裝置真值可能是 0、1 或 3，App 無從得知。它不代表 ADB 關閉，也不代表 ADB 開啟或設定被改寫；它也不是隱匿工具的跡象，因為平台對所有第三方 App 都這樣回傳。

## 已知偽陽性來源

- **使用者解鎖 Bootloader 之良性實體設備。** 使用者透過官方途徑開啟 OEM unlocking 並解鎖引導載入程式（例如 Google Pixel 或 OnePlus 設備），系統會如實呈現 `ro.boot.flash.locked == "0"`（`property_detector_logic.cpp` 第 108 行）、`ro.boot.verifiedbootstate == "orange"`（第 98 行）與 `ro.boot.vbmeta.device_state == "unlocked"`（第 116 行），直接引發 MODERATE 判定。
- **原廠預覽版或工程測試機（userdebug）。** OEM 內部測試韌體常配置 `ro.build.type == "userdebug"`（第 148 行）、`ro.build.tags` 含有 `test-keys`（第 157 行）以及 `ro.debuggable == "1"`（第 140 行），會觸發 WEAK 判定。
- **官方 Android SDK 模擬器。** 模擬器映像檔通常將 `ro.secure` 預設為 `0`（第 90 行），觸發 MODERATE。
- **開發者或測試框架手動寫入非標準 `adb_enabled`。** 任何持有 `WRITE_SECURE_SETTINGS` 的來源（`adb shell`、MDM/裝置管理程式、自動化測試腳本）都可能寫入 0/1 以外的值；AOSP 的 SettingsProvider 對 `adb_enabled` 沒有寫入驗證器。尚未在任何裝置上觀察到 OEM 韌體或系統元件寫入這類值，但本專案沒有足以排除的裝置母體，因此未佐證時只給 WEAK。

## 看不到什麼

- **透過 `resetprop` 或記憶體 Hook 竄改屬性。** 本檢測僅讀取當前行程的 Bionic property accessor（`property_observation.cpp` 第 223 行）。若攻擊者已透過 MagiskHide 或 Shamiko 將屬性改寫為官方發佈預期值（如將 `ro.boot.verifiedbootstate` 竄改為 `green`），本檢測無法察覺（多來源交叉驗證需依賴 `SYSTEM_PROPERTIES_TAMPER`）。
- **非清單監控之屬性。** 僅評估寫死的 8 項安全屬性規則、1 項 `adb_enabled` 規則與 4 項態勢鍵值。
- **把 `adb_enabled` 剛好設成 0 的工具。** 規避工具若寫入 `0`（或以 Hook 讓本 App 讀到 `0`/`1`），再另外維持 adbd（例如直接設定 `sys.usb.config`/`persist.sys.usb.config`），本規則看不到；`adb_transport_enabled` 遙測仍可能記錄 USB 設定含有 adb，但不參與判定。
- **Hook `Settings.Global` 讀取。** 讀取發生在本行程內（`ContentResolver` → `Settings$NameValueCache`），LSPosed/Xposed 類模組或針對 settings provider 的回應竄改可以回傳任意值。
- **重開機後消失的設定。** `AdbService.systemReady()` 每次開機都依 `persist.sys.usb.config` 把 `adb_enabled` 改寫回 `0` 或 `1`，因此非標準值只在下次重開機前存在，除非工具在開機後（例如模組的 `service.sh`）重新寫入。
- **API 37 以上（Android 17 QPR1 起）的 `adb_enabled`。** 平台對第三方 App 一律回傳 0，所以本規則只能在 API 37 以下，或平台沒有遮蔽的 build 上觸發；在遮蔽的裝置上，`adb_enabled` 被設成 3 也看不到，`environment-posture` 只會是 `PARTIAL`。
- **不以「`adb_enabled=0` 但 USB 設定含 adb」判定矛盾。** 在 Android 17 QPR1 上，每一支開著 USB 偵錯的正常手機都會呈現這個組合（App 讀到遮蔽的 0，`sys.usb.config` 仍含 `adb`），因此這條候選規則已撤回。
- **只看 USB ADB。** `adb_wifi_enabled`（無線偵錯）未納入本規則。
- **純遙測態勢不影響結果。** 即使設備明確偵測到 `ro.boot.qemu=1` 或 ADB 啟用，若 8 項安全規則未被觸發，仍會回報 `NOT_OBSERVED`。

## 建議處置

| 強度 | 建議 |
|---|---|
| MODERATE | 設備存在重大安全降級特徵（如 Bootloader 解鎖或非安全建置）。建議與硬體證明（`hardware-attestation`）或執行期完整性（`runtime-integrity`）交叉比對；若應用程式牽涉高額資產保護，可考慮提升驗證層級。 |
| WEAK | 僅表示開發或除錯導向建置（如 userdebug），或 `adb_enabled` 被改寫成未佐證的非標準值。不建議單獨以此判定阻斷終端使用者。 |
| NOT_OBSERVED | 可取得的規則（8 項屬性規則與 `adb_enabled`）均處於標準狀態。不能代表屬性或設定未被隱匿工具竄改；`adb_enabled` 讀取失敗（`collectionErrors`）或在 API 37 以上被平台遮蔽（`collectionWarnings`）時，看 `environment-posture` 的 issue：那代表 `adb_enabled` 規則沒有被評估。 |
| INCONCLUSIVE | 9 項規則全部無法取得（屬性服務讀取失敗，且 `Settings.Global` 讀取失敗或被平台遮蔽）。 |

## 成本

- 僅透過 Bionic accessor 讀取 12 個屬性鍵值（8 個安全屬性與 4 個態勢屬性），另以一次 `Settings.Global.getString` 讀取 `adb_enabled`（一次 settings provider binder 呼叫，命中 `NameValueCache` 時更少），並以 `android_get_device_api_level()` 讀一次 API level。
- 行程內記憶體快速查表，不 fork 子行程，無檔案讀寫，無網路通訊。
- 整合者無需配置任何 Android 權限。

## Evidence units

### dangerous-props.security-posture

依據 8 項安全性規則評估屬性（finding ids: `ro_secure_disabled`, `verified_boot_untrusted`, `flash_unlocked`, `vbmeta_unlocked`, `adb_root_debuggable`, `debuggable_build`, `development_build_type`, `development_signing_keys`）。任何一項規則命中即產出對應 strength（MODERATE 或 WEAK），最高強度決定本 unit 之 outcome。

### dangerous-props.environment-posture

記錄 QEMU 模擬器屬性（`emulator_environment`）、USB 配置中之 ADB 傳輸功能（`adb_transport_enabled`）以及未授權之 ADB root 請求（`adb_root_requested`），這三項仍是 `RESEARCH` 遙測，不影響 assessment outcome。本 unit 唯一可產生 `SIGNAL` 的規則是 `adb_enabled_nonstandard`（finding id；原始值見 `observations` 中 `source=settings_global` 的那一筆）。`adb_enabled` 讀取失敗只會讓本 unit 變成 `PARTIAL`（`collectionErrors`），不影響 `security-posture`。API 37 以上讀到 0 時，該筆 observation 記為 `state=redacted_by_platform`（沒有 `value`，附 `apiLevel`），本 unit 以 `DANGEROUS_PROPS.environment-posture.collectionWarnings` 變成 `PARTIAL`，同樣不影響 `security-posture`。

注意：兩個 unit 的 `SIGNAL` record 都帶 detector 層級的 strength，同時命中時，較弱那個 unit 的 record 會顯示較強的值。
