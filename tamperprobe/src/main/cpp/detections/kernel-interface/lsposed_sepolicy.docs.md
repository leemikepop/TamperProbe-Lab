# LSPosed SELinux Policy Oracle

透過獨立受控的 `app_zygote` 載體行程（carrier），直接向核心與 Android 隱藏框架發起 SELinux 存取決策查詢（SELinux policy oracle），檢查系統策略中是否存在 LSPosed 或 Xposed 專屬的放行規則（allow rules）。LSPosed 模組注入時常需要對 SELinux 策略動態打補丁以允許未受信任應用程式存取其專屬 context；本檢測透過 6 道嚴格驗證門檻與正負向對照組，驗證查詢來源的可信度並識別策略篡改。

## 這個檢測在看什麼

本檢測在獨立的 `app_zygote` 輔助行程（`:tamperprobe_policy_oracle`）中執行，以 native（`libselinux.so`）與 Java 隱藏 API（`android.os.SELinux.checkSELinuxAccess`）兩條管道，各重複測試 2 次（`kRepeatCount = 2`），查詢與比對以下 SELinux 規則：

1. `lsposed_file_read`：`u:r:untrusted_app:s0` -> `u:object_r:lsposed_file:s0`，類別 `file`，權限 `read`。
2. `xposed_data_read`：`u:r:untrusted_app:s0` -> `u:object_r:xposed_data:s0`，類別 `file`，權限 `read`。
3. `system_server_execmem`：`u:r:system_server:s0` -> `u:r:system_server:s0`，類別 `process`，權限 `execmem`（僅供遙測記錄，不影響 outcome）。

此外，檢測器設立 6 道查核門檻（Gates）驗證環境真偽：
- Gate 1 & 2：載體行程處於 `app_zygote` SELinux 領域且 UID 與主 App 一致。
- Gate 3：強制模式檢驗（`security_getenforce` 或 Java 均回報 Enforcing）。
- Gate 4：查詢管道可用性（native 或 Java 符號成功解析）。
- Gate 5：對照組查核 —— 正向對照（`app_zygote` 到 `isolated_app` 的 `dyntransition` 必須為 `allowed`）與負向對照（`untrusted_app` 到 `init` 的 `ptrace` 必須為 `denied`）。
- Gate 6：矛盾檢驗（native 與 Java 說法必須一致，重複查詢結果必須穩定，且 context 不存在時不可回傳 allowed）。

## 觸發代表什麼

- `lsposed_file_read` 在 `native_trusted` 層級通過：判定為 MODERATE finding（`lsposed_file_read_allowed`）。
- `lsposed_file_read` 在 `java_controlled` 層級通過：判定為 WEAK finding。
- `xposed_data_read` 通過：判定為 WEAK finding（`xposed_data_read_allowed`）。
- 若存在任一 finding，總體判定為 MODERATE 或 WEAK。
- 若所有規則皆為 denied 且通過 native_trusted 檢驗，判定為 NOT_OBSERVED。native 層級在現行 Android 上無法使用，所以實際上本檢測不會回報 NOT_OBSERVED，見「看不到什麼」。

不能推論的：
- **不能推論當前行程已被 Hook 或注入。** SELinux policy 是全系統共享的核心狀態，存在 allow rule 僅代表系統中存在或曾存在 LSPosed 模組，不代表主應用程式當前已載入 Hook 程式碼。
- **不能推論裝置已 Root。** 規則可能是透過韌體內嵌、第三方 Recovery 刷入或未授權提權的孤立模組產生。

## 已知偽陽性來源

- **自訂 ROM 或測試韌體預載 Policy**（規則表中的 `lsposed_file` 與 `xposed_data` 目標）：部分愛好者韌體或維護者在編譯 ROM 時，將 Xposed/LSPosed 相關的 SELinux 宣告（如 `lsposed_file`、`xposed_data` context）預先靜態編譯進 `precompiled_sepolicy`，即使系統中沒有實際安裝 LSPosed 執行環境，本檢測仍會查詢到 allowed。
- **SELinux 處於 Permissive 模式**（Gate 3 的強制模式檢驗）：雖然門檻檢查強制模式，但若 OEM 核心針對特定 domain 設定為 permissive，可能使查詢全部回傳 allowed。

## 看不到什麼

- **無 SELinux 修改的新型注入**：若 LSPosed 透過其他系統現有合法 context（例如直接借用 app 私有目錄 context），未在策略中新增 `lsposed_file` 或 `xposed_data`，策略查詢不會命中。
- **核心層 Policy 虛擬化或 Hook**：若底層使用 KernelSU 的 susfs 或特定 LSM 模組針對 policy 查詢進行過濾（例如攔截 `selinux_check_access` 回傳 EACCES），本檢測無法察覺。
- **型別不存在只能得到「可隱藏否定」，不算可信答案。** 型別是否存在由 `contextState()` 判定（有 libselinux 時用 `security_check_context`，否則寫入 `/sys/fs/selinux/context`，後者不需要 libselinux），但**不存在是隱藏工具可以製造出來的**。實測證據：KernelSU 的「Hide SELinux modification」讓 `ksu_file` 從 `P0` 的 `valid` 變成 `P0s` 的 `absent`。一個真正不存在的型別和一個被隱藏的型別無從區分。自 2026-10-05 起（`collectPolicyOracleNegatives()`），在 6 道 gate 全部通過、沒有任何矛盾時，目標型別不存在的必要規則可以支撐 NOT_OBSERVED，但它一律列入 payload 的 `concealableNegatives`（每筆帶 `targetContextState: "absent"` 與 `concealable: true`），只計入 `overview.concealableNegativeCount`、不計入 `overview.trustedNegativeCount`，並在 unit 中各自發布一筆 `LSPOSED_SEPOLICY.policy-oracle.concealable-negative` OBSERVATION 紀錄。native 層級先前把不存在當成可信的否定答案，現在同樣只算可隱藏否定（outcome 不變）。
- **LSPosed 未安裝時回報 NOT_OBSERVED，但只是可隱藏否定。** native 層級需要 `libselinux.so`，它不在 App 的 linker namespace 內——實測裝置（Android 13、15 與 17）上都無法使用，實際在跑的是 Java 層級。在沒有安裝 LSPosed 的裝置上，`lsposed_file` 與 `xposed_data` 兩個型別都不存在，兩條必要規則都只能是可隱藏否定，所以結果是 `trustedNegativeCount` 為 0、`concealableNegativeCount` 為 2 的 NOT_OBSERVED。隱藏這兩個型別的工具會得到完全相同的報告；這不是乾淨的證明，只是「沒有看到放行規則」。
  2026-10-05 以前，Java 層級把不存在的型別一律當成無法作答，本檢測在這些裝置上回報 INCONCLUSIVE。實測（`ablation_2026` 十四格）：LSPosed 在兩台裝置上都沒有安裝，`lsposed_file` 與 `xposed_data` 兩個型別在每一格都是 `absent`、規則皆為 `untrusted`，每一格都回報 INCONCLUSIVE；乾淨對照機 Xiaomi 12（E1 `C-xiaomi12-8c664b4`）也一樣。本文件與研究記錄更早之前把這個結果歸因於 libselinux 無法使用的平台限制——那只是一半的原因，另一半是 Java 層級刻意不採信不存在的型別。現行規則把這些格改判為帶可隱藏標記的 NOT_OBSERVED。
- **`app_zygote` 無法啟動**：在 Android 9（API 28）及以下版本（`app_zygote` 自 Android 10 引進），或因記憶體極度不足導致 carrier service 無法綁定時，結果為 INCONCLUSIVE。

## 建議處置

| 強度 | 建議 |
|---|---|
| MODERATE | 核心 SELinux 策略中確認存在 LSPosed 檔案讀取允許規則，高度暗示設備環境存在動態 Hook 框架。正式採用前請先在你的使用者族群上收集分佈。建議結合 `runtime-integrity`（如記憶體與 maps 檢測）作綜合處置。 |
| WEAK | 僅在 Java 受控層級或僅觀察到 Xposed 歷史資料規則，環境可能有舊版相容殘留，建議僅作為風險評估參考。 |
| NOT_OBSERVED | 6 道 gate 全部通過，且 `lsposed_file_read`、`xposed_data_read` 都是 native 層級可信的 denied，或目標型別不存在。判讀時必看 `overview.trustedNegativeCount` 與 `concealableNegatives`：在只有 Java 層級的現行 Android 上，LSPosed 未安裝的裝置得到的是 `trustedNegativeCount` 為 0 的 NOT_OBSERVED，兩條規則都是可隱藏否定，不應計入有效作答的覆蓋數字。即使全部是可信答案，也不排除無 SELinux 痕跡的進階注入。 |
| INCONCLUSIVE | 載體行程無法啟動、SELinux 查詢管道失敗或對照組出現矛盾，請視為採集失效。目標型別存在、但只有 Java 層級回 denied 的必要規則也落在這裡（Java 的 denied 無法與 API 失敗區分）。 |

## 成本

- 依賴跨行程通訊（IPC / Binder），向獨立的 `:tamperprobe_policy_oracle`（`app_zygote`）服務發起快照請求。
- 在載體行程中執行約 10 次 native/Java SELinux 查詢（包含對照組與重複確認）。
- 需要在 `AndroidManifest.xml` 中聲明 `android:useAppZygote="true"` 的服務（SDK 已自動處理 manifest 宣告）。

## Evidence units

### lsposed-sepolicy.policy-oracle

記錄透過 `app_zygote` 載體行程發起的 SELinux 策略查詢結果，涵蓋 6 道檢驗門檻的通過狀態、正負對照組結果、以及 `lsposed_file_read`、`xposed_data_read` 與 `system_server_execmem` 等規則的決策（`allowed` / `denied` / `unavailable`）、信任等級（`native_trusted` / `java_controlled` / `untrusted`），以及每條規則目標型別的存在狀態（`targetContextState`：`valid` / `absent` / `unavailable`）。規則的信任等級取決於目標型別是否存在：在 Java 層級下，型別不存在的規則為 `untrusted`。NOT_OBSERVED 時，`overview.trustedNegativeCount`、`overview.concealableNegativeCount` 與 `concealableNegatives` 說明否定的依據；每筆可隱藏否定另以 `LSPOSED_SEPOLICY.policy-oracle.concealable-negative` OBSERVATION 紀錄發布，屬性為 `ruleId`、`targetContext`、`targetContextState=absent`、`concealable=true` 與 `trustedTier`。
