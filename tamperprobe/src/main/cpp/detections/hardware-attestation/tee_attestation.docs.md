# TEE Attestation Validation

透過 Android Keystore 生成帶有當次掃描專屬隨機 Challenge 的金鑰對，要求硬體支援的 Attestation 證明；在 Native 端逐一解析葉憑證之 ASN.1 擴充欄位，嚴格驗證憑證鏈數位簽章、Challenge 吻合度、Google 官方根憑證信任錨、離線憑證吊銷清單（status.json）、RootOfTrust 安全開機狀態與雜湊一致性，並執行 KeyMint 密碼基語異常探針。

## 這個檢測在看什麼

檢測流程整合 Java 端金鑰生成與 C++ 端密碼學深度檢驗：

1. **動態隨機 Challenge 與金鑰生成**（`TeeKeystoreCollector.java`）：
   生成 32 位元組隨機 Challenge，透過 `KeyPairGenerator` 要求硬體 Attestation，收集憑證鏈 DER 與序號清單，並在結束後清理暫存金鑰別名。
2. **憑證鏈簽章與 Google 信任錨**：
   驗證鏈上每一個憑證是否確實由下一級憑證之私鑰簽署（失敗則產出 STRONG finding `chain_signature_invalid`），並驗證根憑證是否屬於內建之 Google 官方信任錨（`attestation_roots.json`）。
3. **ASN.1 擴充欄位解析**（`parse_tee_certificate`）：
   - **Challenge 驗證**：比對憑證內之 challenge 是否與本次掃描生成之 32 位元組隨機值精準吻合（不符則產出 STRONG finding `challenge_mismatch`）。
   - **RootOfTrust 開機狀態**：檢查 `deviceLocked`（若為 0 產出 WEAK finding `device_unlocked`）與 `verifiedBootState`（若非 Verified 產出 WEAK finding `verified_boot_not_verified`）。
   - **開機金鑰與雜湊完整性**：在 Verified 或 SelfSigned 狀態下，檢查 `verifiedBootKey` 或 `verifiedBootHash` 是否全為零（全零產出 MODERATE finding `zero_verified_boot_key` 或 `zero_verified_boot_hash`），並比對 `verifiedBootHash` 與系統屬性 `ro.boot.vbmeta.digest` 是否一致（不一致產出 MODERATE finding `verified_boot_hash_mismatch`）。兩邊正規化後（小寫、去除空白與冒號、去除 `0x`）的值都發布在 `bootConsistency.runtimeDigestHex` 與 `bootConsistency.attestedDigestHex`。
   - **硬體安全層級**：若 securityLevel 非 TrustedEnvironment（1）或 StrongBox（2），產出 WEAK finding `software_backed_attestation`。
4. **KeyMint 密碼基語探針**：
   - `single_use_ec`：測試限制使用一次之金鑰（`setMaxUsageCount(1)`）是否被繞過而允許第二次簽章（命中產出 MODERATE finding `single_use_ec_bypass`）。
   - **`rsa_oaep_sha256` 已於 2026-09-07 移出本檢測**，改由 `TEE_KEYSTORE_CONSISTENCY` 承載。原因是成本：實測該探針在 Pixel 7 上耗時 335–903 ms、Redmi 13C 上 1,567 ms，本身就是本檢測的大部分；RSA-2048 金鑰生成本來就昂貴。本檢測不產出 `rsa_oaep_crypto_failure`；該證據由 `TEE_KEYSTORE_CONSISTENCY` 提供。
5. **離線憑證吊銷狀態檢驗**（`evaluateRevocation`）：
   將憑證序號比對本機 `attestation_status.json`。若匹配且狀態為 `REVOKED` 或 `SUSPENDED`（且未過期），產出 STRONG finding `revoked_or_suspended_attestation_artifact`。

## 觸發代表什麼

| 判定 | 條件 | 代表意義 |
|---|---|---|
| STRONG | 憑證鏈簽章無效、Challenge 不符、或憑證序號已被 Google 官方標記為 REVOKED/SUSPENDED | 證明材料在密碼學上無效，或設備所使用的硬體金鑰庫已遭外洩並被 Google 官方吊銷。 |
| MODERATE | 開機雜湊與 vbmeta.digest 矛盾、開機雜湊為全零，或 KeyMint 密碼基語探針異常 | 證明資料存在結構性矛盾，或 KeyMint 介面遭遇攔截注入。 |
| WEAK | 裝置未上鎖（deviceLocked=false）、開機狀態非 Verified，或僅為軟體模擬 Keystore | 設備處於解鎖或非標準開機狀態，常見於客製韌體或無硬體 TEE 之設備。 |

不能推論的：
- **不能替代伺服器端遠端證明。** 本地驗證僅於終端執行，若攻擊者直接篡改應用程式記憶體或作業系統核心，無法取代具備伺服器 Nonce 的遠端鑑別。
- **不能推論未吊銷之非法金鑰庫。** 若攻擊者注入外洩之合法金鑰盒（Keybox）且該序號尚未被 Google 加入吊銷清單，密碼學簽章依然會驗證通過。

## 已知偽陽性來源

- **合法解鎖 Bootloader 之實體裝置。** 使用者為開發用途合法解鎖設備，RootOfTrust 會真實記錄 `deviceLocked=false`（finding `device_unlocked`）或 `verifiedBootState != Verified`（finding `verified_boot_not_verified`），觸發 WEAK 判定。
- **離線吊銷清單版本落後或涵蓋過廣。** 若內建或快取之 `attestation_status.json` 包含未被過濾的 OEM 批次測試金鑰，持有該批次原廠設備的使用者可能被判定為 STRONG（`revoked_or_suspended_attestation_artifact`）。
- **無硬體 TEE / StrongBox 之舊型設備。** 缺少硬體安全模組的平價或舊款設備僅能以軟體模擬金鑰生成，觸發 WEAK（`software_backed_attestation`）。
- **曾把一支乾淨、上鎖的原廠手機誤報為 `verified_boot_hash_mismatch`（已修正，2026-09-24）。** Xiaomi 13T Pro（Android 16，bootloader 鎖定、從未 root）把 `ro.boot.vbmeta.digest` 存成 64 個十六進位字元再加一個 NUL。`__system_property_get` 回傳的是存放長度，本行程據此建字串，NUL 便跟著進入比對；正規化只去除空白與冒號，於是兩個完全相同的摘要只差最後一個位元組而判為不一致（MODERATE）。`getprop` 與 Java API 讀到 NUL 即停止。現在屬性讀取同樣以第一個 NUL 為界，同一台手機重掃後兩值一致。

## 看不到什麼

- **尚未被 Google 官方吊銷的有效 Keybox 注入。** 例如 TrickyStore 工具若載入未列入 `status.json` 的外洩真實 OEM 憑證金鑰，其數位簽章、Google 信任錨與 Challenge 比對皆能順利通過。
- **本地記憶體修補（In-process memory patching）。** 攻擊者若於當前行程 hook 驗證函式之回傳值，端點層級驗證會被繞過。

## 建議處置

| 強度 | 建議 |
|---|---|
| STRONG | 數位簽章無效、Challenge 矛盾或憑證已被官方吊銷。高度確定證明鏈不可信，強烈建議阻斷涉及財務或機敏資產的操作。 |
| MODERATE | 開機雜湊矛盾或 KeyMint 基語被攔截。提示金鑰庫或開機狀態異常，建議升高風控等級。 |
| WEAK | 僅表示 Bootloader 解鎖或無硬體 TEE。不建議單獨以此判定永久封鎖使用者。 |
| NOT_OBSERVED | 硬體證明完全通過且無異常。 |
| INCONCLUSIVE | Keystore 不可用、憑證鏈解析失敗、或離線吊銷檔案缺失。 |

## 成本

- 透過 JNI 呼叫 Android Keystore 生成暫存 EC 金鑰對並要求 Attestation，隨後於 finally 清除金鑰。
- 解析 DER 憑證 ASN.1 欄位、驗證鏈路數位簽章、讀取本機 `attestation_status.json`。
- 需傳入 JNIEnv 與 Android Context。無外部網路呼叫，無需額外 Android 權限。

**實測成本（2026-09-07，30 次量測中位數）**：移出 RSA-OAEP 探針之前，本檢測在 Pixel 7 上為 756 ms（IQR 323 ms、p95 1,373 ms），Redmi 13C 上為 1,550 ms。逐操作拆解為：

| 操作 | Pixel 7 | Redmi 13C |
|---|---:|---:|
| attested EC 金鑰生成 | 33–50 ms | 93 ms |
| single-use EC 探針 | 56–57 ms | 133 ms |
| ~~RSA-OAEP 往返~~（已移出） | ~~335–903 ms~~ | ~~1,567 ms~~ |

硬體金鑰生成的耗時高度依裝置而異，且變異很大 —— 這是本檢測成本的主要來源，不是憑證解析。

## Evidence units

### tee-attestation.chain-and-root-of-trust

全面承載 Android Keystore 硬體證明之驗證。涵蓋憑證鏈簽章有效性、隨機 Challenge 吻合度、Google 官方根錨信任、本機吊銷清單核對、RootOfTrust 開機狀態與雜湊一致性，以及 KeyMint 密碼基語探針異常。
