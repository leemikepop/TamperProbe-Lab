# TEE Keystore Consistency

透過執行 3 項 Android Keystore 必要公開 API 規範的不變量測試（ECDSA 簽署往返、金鑰生命週期刪除與重新產生、純憑證項目之私鑰隔離），並收集 AES-GCM 與 StrongBox 支援能力作為診斷資訊。這項檢測旨在確認系統之 KeyStore 服務與底層 Keymaster/KeyMint HAL 是否具備符合 Android 標準規範的內部行為一致性。

## 這個檢測在看什麼

檢測器透過 JNI 呼叫 Java 端 `TeeKeystoreCollector.collectKeystoreConsistency`，執行 6 項檢查：

1. **必要公開 API 一致性檢查（4 項，影響 assessment）**：
   - `ec_signature_roundtrip`（`runSignatureCheck`）：產生暫存 EC 金鑰對，以私鑰對 32 位元組亂數進行 `SHA256withECDSA` 簽署，並以憑證中取出的公鑰驗證簽名。若驗證失敗，回報 `contradiction`。
   - `key_lifecycle`（`runLifecycleCheck`）：產生金鑰後呼叫 `deleteEntry`，驗證 `containsAlias` 是否回傳 false；隨後以相同別名重新產生金鑰，驗證新公鑰位元組是否與原公鑰不同（保證刪除落實且隨機金鑰刷新）。若任一條件不符，回報 `contradiction`。
   - `certificate_only_entry`（`runCertificateEntryCheck`）：產生金鑰對後將其憑證以 `setCertificateEntry` 存入另一獨立別名，驗證該項目為 `TrustedCertificateEntry` 且呼叫 `getKey` 必然為 null（確保未外洩私鑰）。若不符，回報 `contradiction`。
   - `rsa_oaep_sha256`：產生硬體支援之 RSA-2048 金鑰，以公鑰執行 `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` 加密後再以私鑰解密，驗證是否還原原始明文。若不符，回報 `contradiction`。用以攔截 TrickyStore 類型的金鑰攔截注入 —— 它能偽造一條驗證得過的 attestation 鏈，卻不見得能正確實作每一個密碼基語。
     **這項檢查於 2026-09-07 由 `TEE_ATTESTATION` 移入本檢測。** 原因是成本而非有效性：實測它在 Pixel 7 上耗時 335–903 ms、Redmi 13C 上 1,567 ms，獨立出來後 `TEE_ATTESTATION` 不必為一個尚未校準的異常啟發式承擔這個成本。
2. **選用診斷檢查（2 項，純診斷不影響 assessment）**：
   - `aes_gcm_roundtrip`（`runAesRoundTrip`）：測試 AndroidKeyStore 之 256 位元 AES-GCM 加密與解密往返。
   - `strongbox_capability`（`runStrongBoxDiagnostic`）：若系統宣告具備 `FEATURE_STRONGBOX_KEYSTORE`，測試是否能成功建立 StrongBox 支援之硬體金鑰。

C++ 端（`tee_keystore_consistency.cpp` 的檢查過濾迴圈）過濾各項檢查：若任一必要檢查回報 `contradiction`，產出 MODERATE finding；選用檢查若不可用僅記錄 collection warning。

## 觸發代表什麼

| 判定 | 條件 | 代表意義 |
|---|---|---|
| MODERATE | 4 項必要檢查（簽章往返、生命週期刪除/重建、純憑證隔離、RSA-OAEP 往返）中至少有一項回報 `contradiction` | Android Keystore 公開 API 表現出內部矛盾行為（例如私鑰簽名無法由公鑰驗證、刪除金鑰後仍可存取、或純憑證項目回傳私鑰），代表底層 HAL 嚴重損壞或遭遇非標準之 Hook 代理。 |

不能推論的：
- **不能推論裝置已 root。** 某些晶片廠商之非標準 HAL 實作缺陷亦可能引發行為不一致。
- **不能推論未攔截 Keystore 之 root 工具。** 若 root 框架（如標準 Magisk）未 hook Keystore 公開 API，各項檢查將順利通過。
- **選用診斷失敗不代表異常。** AES 或 StrongBox 診斷不計入 assessment。

## 已知偽陽性來源

- **特定 OEM 晶片平台之 Keymaster/KeyMint HAL 實作缺陷。** 部分廠商客製韌體在呼叫 `deleteEntry` 後立即以相同別名呼叫 `generateKeyPair` 時，因硬體快取非同步延遲而偶發未能及時更新（`runLifecycleCheck`），或在 `setCertificateEntry` 上處理異常（`runCertificateEntryCheck`），會在良性未 root 設備上觸發 MODERATE 判定。
- **Keystore 守護行程（keystore2）短暫競態或記憶體壓力。** 密集進行暫存金鑰建立與刪除時，若系統服務短暫卡頓可能導致一致性檢查回報失敗。

## 看不到什麼

- **未干預 Keystore 公開介面之 Root 框架。** 傳統 Root 方案只要未修改 AndroidKeyStore 提供者或 Hook 相關簽章 API，本檢測無法察覺。
- **精確維持不變量之 Hook 模組。** 若 Hook 工具（如特定 Keybox 替換模組）完整且規範地實現了簽章、刪除與憑證隔離語意，本檢測回報 `NOT_OBSERVED`。
- **選用診斷失敗不影響結果。** 即使設備宣稱支援 StrongBox 但金鑰生成失敗，因 `required=false`，不會觸發安全 finding。

## 建議處置

| 強度 | 建議 |
|---|---|
| MODERATE | Keystore 必要公開不變量發生內部矛盾。正式採用前請先在你的使用者族群上收集分佈並校準基線；若排除特定 OEM 機種相容性問題，可作為金鑰庫遭受中介干預的風險訊號。 |
| NOT_OBSERVED | 3 項必要公開 API 一致性測試均符合預期。 |
| INCONCLUSIVE | 任何一項必要檢查無法執行、回報 unavailable，或 JNI 初始化失敗。 |

## 成本

- 於 AndroidKeyStore 中建立並刪除 4 至 6 組暫存金鑰（EC、AES、**RSA-2048**、StrongBox），執行 ECDSA 簽署/驗證、AES-GCM 加解密與 RSA-OAEP 加解密。
- 與系統 `keystore2` 服務進行多次 IPC 通訊。

**本檢測是目錄中最昂貴的幾個之一，且成本集中在一處。** 實測（2026-09-07）：本檢測整體在 Pixel 7 上 312 ms、Redmi 13C 上 632 ms，**再加上移入的 RSA-OAEP 探針**（Pixel 335–903 ms、Redmi 1,567 ms）。RSA-2048 硬體金鑰生成本身就昂貴且變異極大，這是它與 `TEE_ATTESTATION` 分開的原因。
- 需傳入 JNIEnv 與 Android Context。無網路連線，無需額外 Android 權限。

## Evidence units

### tee-keystore.public-api-consistency

記錄並評估 Android Keystore 4 項必要公開 API 不變量測試（`ec_signature_roundtrip`、`key_lifecycle`、`certificate_only_entry`、`rsa_oaep_sha256`）之執行狀態，並收集 AES-GCM 與 StrongBox 選用診斷。若任一必要項目發生行為矛盾，產出 MODERATE 強度 finding。
