# Native Root SELinux Policy Oracle

透過獨立受控的 `app_zygote` 載體行程（carrier），直接向核心與 Android 隱藏框架發起 SELinux 存取決策查詢（SELinux policy oracle），檢查系統策略中是否存在 Magisk、KernelSU、ADB-root 與 su 提權專屬的放行規則（allow rules）。現代 Root 工具在開機時常需要對 SELinux 策略動態注入規則以打通跨領域通訊；本檢測透過 6 道嚴格驗證門檻，在不依賴檔案路徑的前提下直接檢驗核心策略庫的純淨度。

## 這個檢測在看什麼

本檢測在獨立的 `app_zygote` 輔助行程（`:tamperprobe_policy_oracle`）中執行，以 native（`libselinux.so`）與 Java 隱藏 API 兩條管道重複驗證（`kRepeatCount = 2`），查詢以下 4 條 Root 相關 SELinux 規則：

1. `magisk_binder_call`：`u:r:untrusted_app:s0` -> `u:r:magisk:s0`，類別 `binder`，權限 `call`。
2. `ksu_file_read`：`u:r:untrusted_app:s0` -> `u:object_r:ksu_file:s0`，類別 `file`，權限 `read`。
3. `adbd_adbroot_binder_call`：`u:r:adbd:s0` -> `u:r:adbroot:s0`，類別 `binder`，權限 `call`。
4. `shell_su_transition`：`u:r:shell:s0` -> `u:r:su:s0`，類別 `process`，權限 `transition`。此規則僅在正式發布版本（`ro.build.type == "user"`）上作為弱強度 finding，在 `userdebug` 上則降級為 `telemetry_only`。

同樣經由 6 道查核門檻（Gates）驗證載體行程身分、Enforcing 強制模式、查詢符號可用性、正負對照組（dyntransition / ptrace），並排除 native 與 Java 矛盾。

## 觸發代表什麼

- 任一受關注規則回傳 allowed 時，判定為 WEAK（`weakObserved()`）。
- 所有規則皆被 denied 且通過 native_trusted 檢驗時，判定為 NOT_OBSERVED。native 層級在現行 Android 上無法使用，所以實際上本檢測不會回報 NOT_OBSERVED，見「看不到什麼」。

不能推論的：
- **不能推論當前應用程式已獲得 Root 權限。** 策略存在放行規則僅代表系統開機時被注入過相關 policy，或韌體本身具備該設定，不代表目前有 Root 程序在運行或授權給本 App。
- **不能推論特定工具活躍中。** 例如 Magisk 模組被卸載後，若重啟未復原原始 boot.img，殘留的 policy 也可能觸發。

## 已知偽陽性來源

- **OEM 特製或第三方韌體殘留 Policy 規則**（`shell_su_transition_allowed` finding）：部分第三方愛好者 ROM（如 LineageOS 或自訂 user build）雖然設定 `ro.build.type=user`，但策略中仍保留允許 `shell` 轉移至 `su`（`shell_su_transition`）或允許 ADB root 的規則，會觸發 `shell_su_transition_allowed`。
- **開發板或工廠測試韌體**（`adbd_adbroot_binder_allowed` finding）：在某些車載、電視或測試設備上，OEM 可能將 `adbd_adbroot_binder_call` 納入正式策略，產生誤判。

## 看不到什麼

- **無 SELinux 策略修改的 Root 方案**：若 Root 實作完全不定義新 context、不修改 allow 規則，而是動態切換到現有的高權限 domain（如 `init` 或 `vold`），本檢測不會命中。
- **LSM 核心層隱藏與查詢過濾**：KernelSU susfs 或客製化 LSM 模組可攔截 `selinux_check_access` 系統呼叫，在查詢特定 target 時直接偽造為 `EACCES`。
- **型別不存在只能得到「可隱藏否定」，不算可信答案。** 型別是否存在由 `contextState()` 判定（有 libselinux 時用 `security_check_context`，否則寫入 `/sys/fs/selinux/context`，後者不需要 libselinux），但**不存在是隱藏工具可以製造出來的**。實測證據：KernelSU 的「Hide SELinux modification」讓 `ksu_file` 從 `P0` 的 `valid` 變成 `P0s` 的 `absent`。一個真正不存在的型別和一個被隱藏的型別無從區分。自 2026-10-05 起（`collectPolicyOracleNegatives()`），在 6 道 gate 全部通過、沒有任何矛盾時，目標型別不存在的必要規則可以支撐 NOT_OBSERVED，但它一律列入 payload 的 `concealableNegatives`（每筆帶 `targetContextState: "absent"` 與 `concealable: true`），只計入 `overview.concealableNegativeCount`、不計入 `overview.trustedNegativeCount`，並在 unit 中各自發布一筆 `NATIVE_ROOT_SEPOLICY.policy-oracle.concealable-negative` OBSERVATION 紀錄。native 層級先前把不存在當成可信的否定答案，現在同樣只算可隱藏否定（outcome 不變）。
- **user build 的乾淨手機仍回報 INCONCLUSIVE。** native 層級需要 `libselinux.so`，它不在 App 的 linker namespace 內——實測裝置（Android 13、15 與 17）上都無法使用，實際在跑的是 Java 層級。`u:r:su:s0` 是 AOSP 在每種 build 都定義的型別，所以 `shell_su_transition` 的目標型別存在，Java 查詢回 `denied`；而 Java 層級的 denied 無法與 API 失敗區分，不算答案。因此在 `ro.build.type=user` 的手機上，即使 magisk、ksu、adbroot 三個型別都不存在，本檢測仍回報 INCONCLUSIVE（實測：Xiaomi 12，Android 15，E1 `C-xiaomi12-8c664b4`）。只有 `userdebug`／`eng` 建置（`shell_su_transition` 降為 telemetry）或 native 層級可用時，乾淨裝置才會得到 NOT_OBSERVED。依同一機制，開啟 Hide SELinux 的 user build（如 `P0s`）也停在 INCONCLUSIVE，而不是像 Duck-Detector 一樣回報 CLEAR。
  這也說明了本檢測實際在觀察什麼：一條規則只有在它的目標型別存在時才會變成可信，而 `ksu_file` 或 `magisk` 這類型別只有在對應 root 框架把 policy 補丁載入後才存在。實測（`ablation_2026`）：Pixel 7（KernelSU）上 `ksu_file_read` 為 `valid`／`java_controlled`／`allowed`，`magisk_binder_call` 為 `absent`；Redmi 13C（Magisk）上正好相反。開啟 Hide SELinux 的 `P0s` 是十四格中唯一的 INCONCLUSIVE。（以上為 2026-10-05 以前的規則下的結果。）
- **`app_zygote` 服務不可用**：在 Android 9 及以下裝置，或因系統限制無法建立 `app_zygote` 行程時，檢測直接回報 INCONCLUSIVE。

## 建議處置

| 強度 | 建議 |
|---|---|
| WEAK | 核心 SELinux 策略中確認存在 Magisk、KernelSU 或 su 相關的放行通道。正式採用前請先在你的使用者族群上收集分佈。建議作為輔助證據，與 `native_root_prctl` 或二進位檔案檢測交叉參照。 |
| NOT_OBSERVED | 6 道 gate 全部通過，且每條必要規則（user build 上含 `shell_su_transition`）都是 native 層級可信的 denied，或目標型別不存在。判讀時必看 `overview.trustedNegativeCount` 與 `concealableNegatives`：可隱藏否定只代表型別不存在，Hide SELinux 一類功能可以製造這個結果；`trustedNegativeCount` 為 0 的 NOT_OBSERVED 不含任何可信答案，不應計入有效作答的覆蓋數字。即使全部是可信答案，也不保證無其他動態或零策略修改之提權手法。 |
| INCONCLUSIVE | 載體行程無法啟動、查詢管道失敗或對照組出現矛盾，請視為採集失效而非陰性結果。目標型別存在、但只有 Java 層級回 denied 的必要規則也落在這裡（Java 的 denied 無法與 API 失敗區分）——user build 乾淨手機上的 `shell_su_transition` 就是這種情況。 |

## 成本

- 依賴跨行程通訊（IPC / Binder），向獨立的 `:tamperprobe_policy_oracle`（`app_zygote`）服務發起快照請求。
- 在載體行程中執行約 12 次 native/Java SELinux 查詢（包含對照組與重複確認）。
- 需要在 `AndroidManifest.xml` 中聲明 `android:useAppZygote="true"` 的服務（SDK 已自動處理 manifest 宣告）。

## Evidence units

### native-root-sepolicy.policy-oracle

記錄透過 `app_zygote` 載體行程發起的 Root 相關 SELinux 策略查詢結果，涵蓋 6 道檢驗門檻的通過狀態、正負對照組結果、以及 `magisk_binder_call`、`ksu_file_read`、`adbd_adbroot_binder_call` 與 `shell_su_transition` 等規則的決策、信任等級，以及每條規則目標型別的存在狀態（`targetContextState`）。NOT_OBSERVED 時，`overview.trustedNegativeCount`、`overview.concealableNegativeCount` 與 `concealableNegatives` 說明否定的依據；每筆可隱藏否定另以 `NATIVE_ROOT_SEPOLICY.policy-oracle.concealable-negative` OBSERVATION 紀錄發布，屬性為 `ruleId`、`targetContext`、`targetContextState=absent`、`concealable=true` 與 `trustedTier`。
