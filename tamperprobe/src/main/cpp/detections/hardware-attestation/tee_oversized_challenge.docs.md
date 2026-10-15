# TEE Oversized Challenge

向 Android Keystore 請求產生帶有 256 位元組超長隨機 Challenge 的硬體證明金鑰，驗證金鑰庫實作是否嚴格落實官方規格所記載的 128 位元組長度上限。這項檢測旨在確認金鑰證明堆疊是否遵循標準邊界防護，藉此發掘非標準代理或放寬邊界的竄改環境。

## 這個檢測在看什麼

Android 官方規格（`KeyGenParameterSpec.Builder.setAttestationChallenge`）明確規定：Attestation Challenge 的長度不得超過 128 位元組；若傳入超過 128 位元組之資料，標準 Keystore 實作必須拒絕並拋出例外。

檢測器執行以下流程（本檔的 `execute`，與 `TeeKeystoreCollector.checkOversizedChallenge`）：

1. 透過 JNI 呼叫 `checkOversizedChallenge`，傳入長度為 256 位元組（`kOversizedChallengeBytes = 256`）之隨機位元組陣列作為 Attestation Challenge。
2. 嘗試產生暫存 EC 金鑰對：
   - 若金鑰生成被拒絕，且錯誤代碼為 `ERROR_ATTESTATION_CHALLENGE_TOO_LARGE` 或例外原因包含 `InvalidAlgorithmParameterException`，記錄狀態為 `rejected`。
   - 若金鑰生成完全未受阻擋而順利完成（`state == "accepted"`），記錄狀態為 `accepted`，並產出 STRONG finding `oversized_challenge_accepted`。
   - 其餘非預期之底層錯誤則記錄為 `provider_error` 或相應錯誤類別。
3. 無論成功與否，均於 finally 區塊中安靜刪除該暫存金鑰別名（`aliasCleanupSucceeded`）。

在 `assessOversizedChallenge` 中（`tee_assessment.cpp`），狀態為 `accepted` 判定為 STRONG，`rejected` 判定為 NOT_OBSERVED，其餘判定為 INCONCLUSIVE。

## 觸發代表什麼

| 判定 | 條件 | 代表意義 |
|---|---|---|
| STRONG | `state == "accepted"` | Android Keystore 順利為 256 位元組的超長 Challenge 完成硬體證明金鑰生成（`oversized_challenge_accepted`），明確違反 Android 官方 128 位元組限制之安全規範，高度代表底層 Keystore / KeyMint 堆疊遭到非官方修改、中介代理或採用了非標準實作。 |

不能推論的：
- **不能推論特定 root 工具。** 任何放寬長度限制的修改版 ROM、非標準 HAL 驅動或軟體模擬器均會產生相同現象。
- **不能證明未攔截金鑰庫之 root 工具。** 若 root 框架未觸碰此 API，系統依然會正常拒絕超長 Challenge。

## 已知偽陽性來源

- **放寬長度限制之原廠 OEM Keymaster/KeyMint HAL 實作。** 少數 OEM 廠商或特殊晶片平台在底層韌體與 HAL 實作中自行放寬了 Challenge 長度檢查（例如允許最高 512 位元組），且未在 Java framework 層被攔截（本檔的 `accepted` 分支、`TeeKeystoreCollector.checkOversizedChallenge`），會使 256 位元組金鑰生成成功，在良性原廠未 root 裝置上觸發 STRONG 判定。

## 看不到什麼

- **拒絕原因無法區分。** 本檢測的訊號是「接受」超長 challenge；任何在參數驗證階段的拒絕都算乾淨。
  Android 對這個拒絕沒有單一錯誤碼：Pixel 7 / Android 17 回報
  `ERROR_INCORRECT_USAGE (13)`，其他版本回報 `ERROR_ATTESTATION_CHALLENGE_TOO_LARGE (9)`，
  兩者都歸為 `rejected`。因此「裝置確實強制 128 位元組上限」與「裝置因其他參數理由拒絕」
  在本檢測中不可分。基礎設施性失敗（keystore 不可用、權限拒絕、attestation key 缺失、
  StrongBox 不存在）刻意**不**歸為拒絕，會落到 `provider_error` 並回報 INCONCLUSIVE，
  避免把收集失敗說成乾淨。
- **未介入 Keystore 金鑰生成之 Root 工具。** 標準 Magisk、KernelSU 或 APatch 若未對金鑰產生流程進行 hook，底層 Keystore 仍會正常回報 `rejected`，本檢測回報 `NOT_OBSERVED`。
- **忠實模擬 128 位元組限制之 Hook 模組。** 若 Hook 工具在代理層明確檢查並拒絕超過 128 位元組之 challenge，本檢測無法察覺。

## 建議處置

| 強度 | 建議 |
|---|---|
| STRONG | Keystore 接受了超過官方規格限制之超長 Challenge。代表金鑰證明堆疊處於非標準或受竄改環境，建議與 `TEE_ATTESTATION` 憑證鏈簽章檢驗結果合併研判。 |
| NOT_OBSERVED | Keystore 正常依規範拒絕了超長 Challenge（`challenge_too_large`）。 |
| INCONCLUSIVE | 探測過程中發生非預期的 Provider 錯誤或 Context 無效。 |

## 成本

- 嘗試產生 1 組帶有 256 位元組 Challenge 的暫存 EC 金鑰對。
- 在符合規範之標準設備上，通常於 framework 或 Keymaster 參數檢驗階段即快速拋出例外（僅耗時數毫秒）；若被接受則需完成一次完整金鑰生成。隨後立即刪除暫存別名。
- 需傳入 JNIEnv 與 Android Context。無網路連線，無需額外 Android 權限。

## Evidence units

### tee-oversized-challenge.limit-enforcement

記錄 Android Keystore 對於超過規格上限（256 位元組）之 Attestation Challenge 的邊界處理行為。若被接受（accepted）產出 STRONG finding `oversized_challenge_accepted`；若被拒絕（rejected）產出 NOT_OBSERVED。
