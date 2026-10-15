# Keystore Grant Chain Consistency

把同一把 Keystore 金鑰的憑證鏈讀兩次 —— 一次走一般的 alias 路徑，一次走本 App 發給自己 uid 的 grant 路徑 —— 然後比對兩份結果。已儲存的憑證鏈對任何讀取者都是同一份位元組，因此兩次讀取不一致，就證明憑證鏈是**每次查詢當場產生**的，而不是從儲存區取出的。這條檢測不帶任何參考資料、不需要允許清單，所以即使 keybox 偽造工具送出一條能驗證到原廠根憑證的鏈，它仍然成立：偽造方必須在每一條 App 能問的路徑上給出**一致**的答案，而 grant 路徑是攔截層必須額外處理的一條。

## 這個檢測在看什麼

流程如下：

1. 產生一把新的、帶 attestation challenge 的 EC 金鑰（P-256），alias 唯一且用完即刪。
2. 用 `KeyStore.getCertificateChain(alias)` 讀出 **owner 側**憑證鏈。
3. 用 `KeyStoreManager.grantKeyAccess(alias, 自己的 uid)` 對同一把金鑰發出 grant，取得 grant id。
4. 用 `KeyStoreManager.getGrantedCertificateChainFromId(grantId)` 讀出 **grantee 側**憑證鏈。
5. 逐張比對：先比鏈長度，再比每一張憑證的 SHA-256。
6. 若第 4 步丟出「grant 後面沒有金鑰」（見下），執行**陽性對照**：產生一把**不帶** attestation
   challenge 的金鑰，同樣發 grant 給自己再讀回。對照成功才把這個狀態記為 `grant_key_missing`。
7. 無論結果為何，撤銷 grant 並刪除金鑰（對照金鑰亦同）。

「grant 後面沒有金鑰」的判別方式：`getGrantedCertificateChainFromId` 丟出
`UnrecoverableKeyException`、訊息以 `No asymmetric key found` 開頭、且**沒有 cause**。依 AOSP
`AndroidKeyStoreProvider`，這只發生在 keystore2 對 `Domain.GRANT` 回 `KEY_NOT_FOUND`，或查到的是一筆
沒有金鑰的純憑證項目；其他 keystore2 錯誤一律包成帶 cause 的 `Failed to obtain information about key`，
仍歸為收集失敗。而 `grantKeyAccess(alias)` 能成功，本身就代表發 grant 當下 keystore2 認得這個 alias。

離開 collector 的只有**每張憑證的長度與摘要**，憑證本身永遠不會進入 payload —— attestation 鏈帶有裝置與應用程式身分。

`KeyStoreManager` 自 API 36 起才存在。低於 API 36 的裝置回報 `INCONCLUSIVE` 並附上原因，**不會**回報 NOT_OBSERVED —— 一個沒有跑起來的檢查沒有觀察到任何事，把「API 不存在」講成「裝置乾淨」是錯的。

## 觸發代表什麼

| 判定 | 條件 | 代表意義 |
|---|---|---|
| STRONG | 兩條鏈長度不同，或任一張憑證摘要不同（`splitKind` 為 `chain_length`、`leaf_certificate`、`chain_certificate`） | 憑證鏈是按查詢路徑當場生成的。這是 Keystore 被攔截並重簽的直接證據，且與 attestation 內容是否「看起來正確」無關 |
| MODERATE | alias 路徑回傳了鏈、grant 已發出，但 grant 讀回否認金鑰存在；同一行程的非 attestation 對照金鑰 grant 讀回成功（`splitKind=grant_key_missing`，finding `keystore_grant_key_missing`） | 帶 attestation 的金鑰只有「一條鏈」，背後沒有一把存在 keystore2 的金鑰。對照排除了 grant 通道本身壞掉的可能 |
| NOT_OBSERVED | 兩條鏈完全相同 | 未觀察到分歧。見下方「看不到什麼」 |
| INCONCLUSIVE | API < 36、`KeyStoreManager` 服務不可用、金鑰產生失敗、任一條鏈為空、grant 讀回以其他原因失敗、或 grant 讀回否認金鑰且**對照也失敗** | 通道沒有產出，不能視為乾淨 |

`controlReadback` 欄位記錄對照結果（`not_run`、`ok`，或 `failed stage=… type=…`），`grantReadback`
記錄主金鑰的 grant 讀回（`not_run`、`ok`、`key_missing`）。

可以推論的：**憑證鏈不是從儲存區取出的。**

MODERATE 而不是 STRONG 的原因：摘要不符是位元組層級的直接比較；「金鑰不存在」則依賴平台例外的語意，
而且目前只有一台上鎖、未改機、API 36 以上的裝置（Xiaomi 13T Pro，三次皆 NOT_OBSERVED）量過這條路徑。

不能推論的：
- **不能推論是哪一層做的。** 任何 hook Keystore 的東西都會產生同樣的證據，本檢測不會指名工具。
- **不能推論 attestation 的內容是假的。** 分歧證明的是產生方式，不是內容真偽；兩者是不同的命題。

## 已知偽陽性來源

- **平台自身的憑證後處理。** 若某個 Android 版本或 OEM 在 grant 路徑上對憑證做了任何重新編碼（即使語意相同），DER 位元組就會不同。目前沒有實機觀察到這種情形，但這是本檢測最可能的真實偽陽性來源。
- **RKP（Remote Key Provisioning）路徑差異。** 若兩條路徑分別取得不同的 attest key，鏈自然不同。本檢測目前不區分這種情況。
- **乾淨對照只有一台。** 2026-09-17 在上鎖、未改機的 Xiaomi 13T Pro（Android 16 / API 36）上三次皆
  NOT_OBSERVED，grant 讀回正常。一台不構成比率，**不能引用偽陽性率**。
- **`grant_key_missing` 的平台成因。** 若某個 OEM 的 keystore2 在 grant 查詢上對帶 attestation 的金鑰
  行為與不帶的不同，就會落入 MODERATE。目前沒有觀察到；陽性對照只能排除「grant 通道整體壞掉」，排除不了
  這種僅限 attestation 金鑰的平台差異。

## 看不到什麼

- **答案一致的攔截層。** 如果偽造工具在 alias 與 grant 兩條路徑上都回傳同一份合成鏈，本檢測完全看不到。這是本設計的核心限制：它抓的是**不一致**，不是**偽造**。
- **API 36 以下的所有裝置。** 包含測試機隊中的 Redmi 13C（API 33）。
- **隔離行程作為第二個讀取者。** 那會是更強的第二條路徑（不同 uid、攔截層更難辨識），但**隔離行程在任何裝置上都無法連上 Keystore 服務**，所以那條路徑結構上不可用。Duck-Detector 實作了該變體，其報告顯示 public 與 hidden 兩個階段都以「Could not connect to Keystore service」失敗。
- **Duck 實際找到證據的那條路徑。** Duck 是靠手工組 parcel 直接呼叫 `IKeystoreService`，比較 `Domain.APP` 與 `Domain.GRANT`。那是未公開介面，交易編號可隨平台版本變動；一個被連結進他人 App 的 SDK 不能承擔在平台更新後讓宿主行程崩潰的風險。**因此本檢測有可能在 Duck 有發現的裝置上回報 NOT_OBSERVED**，這是刻意的取捨，不是缺陷。

### `grant_key_missing` 的由來：曾被丟掉的證據（2026-09-24 起改為 MODERATE）

2026-09-09 於 Pixel 7（Android 17 / API 37，KernelSU v3.3.0 全模組）量測到一個本檢測當時
看不到、但其實**正是它要找的東西**的情形。以下是當時的診斷紀錄；2026-09-24 起這個狀態已依上文
升為獨立的 MODERATE 結果。

在 Sample App（`io.leemikepop.tamperprobe`）中，alias 路徑成功回傳一條 **4 張憑證**的鏈，
對同一把金鑰發出 grant 也成功，但 `getGrantedCertificateChainFromId` 丟出
`java.security.UnrecoverableKeyException: No asymmetric key found by the given alias`，
拋出點在 `AndroidKeyStoreProvider.loadAndroidKeyStoreKeyPairFromKeystore`。同一台裝置、
同一分鐘、同一份 collector 程式碼，在 library 自測 App（`io.leemikepop.tamperprobe.lib.test`）
中則完全正常：`available=1 split=0 ownerLen=5 granteeLen=5`。

差別已定位：**TrickyStore 1.4.1 的 `/data/adb/tricky_store/target.txt` 列有
`io.leemikepop.tamperprobe`，但沒有列 library 自測 App。** 再以「同一支 App 內、有無
attestation challenge」對照，把機制鎖定在 attestation 攔截上：

| 金鑰 | ownerLen | grant 讀回 |
|---|---|---|
| 帶 attestation challenge | 4 | `UnrecoverableKeyException` |
| 不帶 challenge | 1 | 成功，granteeLen=1 |

TrickyStore 只攔截帶 attestation 的產生請求。也就是說，**攔截層在 alias 路徑合成了一條鏈，
卻沒有在 grant 路徑後面留下一把真的非對稱金鑰。** 兩次讀取對「這把金鑰是否存在」都不一致，
在語意上比本檢測原本設想的「憑證摘要不同」更強；但當時的實作把任何例外都歸成
`available=false` → `INCONCLUSIVE`，**證據因此被丟掉**。

**攔截來源已證實：TrickyStore（2026-09-10）。** 2026-09-10 在該 Pixel 上把 TrickyStore
**移除**（而不是在管理程式中停用）並完整重開機後重測，結果如下：

| 欄位 | TrickyStore 在（八個 cell 全部） | 移除後 |
|---|:-:|:-:|
| attestation 憑證鏈長度 | **4** | **5** |
| 本檢測 | INCONCLUSIVE | **NOT_OBSERVED** |
| `available` | false | **true** |
| owner / grantee | 讀不到 | **5 / 5，五個 sha256 全等** |

`UnrecoverableKeyException` 消失，`split=false`。憑證鏈長度 4 → 5 正是從另一側看到的同一個
特徵：未被列入 `target.txt` 的 library 自測 App 一直都是兩條路徑各 5 張。

**重點在於「停用」不等於「移除」。** ablation 的八個 Pixel cell 中，`P0` 到 `P1u` 的
TrickyStore 在管理程式裡是 disabled，但攔截**始終在作用**；Duck-Detector 在同一批 cell 的
報告逐字一致，正是這一點讓成因無法從 TamperProbe 自己的資料判讀出來。對一個會安裝常駐攔截的
模組而言，管理程式裡的「停用」不是有效的對照條件。

同一次量測還顯示 TrickyStore 壓制了另一個檢測：`TEE_ATTESTATION` 從
NOT_OBSERVED 變成 OBSERVED（WEAK），因為 attested boot hash 不再與 `ro.boot.vbmeta.digest`
相符。完整紀錄見論文工作區的 `ablation_2026/trickystore_removal_diagnostic.md`。

**評級語意於 2026-09-24 修改。** 「alias 路徑成功、grant 路徑否認金鑰存在」現為獨立的具名結果
`grant_key_missing`，評為 MODERATE，與摘要不符（STRONG）分開，並以同一行程的非 attestation 對照
金鑰為前提。十三個 ablation cell 是在 `caf422b` 以舊規則擷取的，其中 Pixel 各 cell 的 INCONCLUSIVE
是舊規則下的正確紀錄，不回頭改寫。

### 量測時的陷阱：跑在哪一支 App 裡

本檢測的結果**取決於是哪一支 App 發問**，因為 Keystore 以 uid 為單位授權，而隱藏模組的目標
清單是以套件名設定的。`tamperprobe` library 的 instrumented test 是 self-instrumenting
（`target=io.leemikepop.tamperprobe.lib.test`），與 Sample App 是**不同的 App、不同的 uid**；
在 library 測試裡重現不出來的現象，不代表 Sample App 裡不存在。（截至 2026-09-24，Pixel 的
`target.txt` 也已列入 `io.leemikepop.tamperprobe.lib.test`，所以 library 測試不再是未被攔截的對照；
要看套件是否被攔截，直接讀 `target.txt`。）上述診斷一開始就是因為把三次
detector 集合二分法全做在錯誤的行程裡而繞了遠路。要量測整合者實際會遇到的行為，用 `app`
模組的 `DetectorSetProbeTest`：

    adb shell am instrument -w       -e class io.leemikepop.tamperprobe.lab.DetectorSetProbeTest       -e detectors KEYSTORE_GRANT_SPLIT       io.leemikepop.tamperprobe.lab.test/androidx.test.runner.AndroidJUnitRunner

## 建議處置

| 強度 | 建議 |
|---|---|
| STRONG | Keystore 的憑證鏈供應路徑存在攔截。建議將該裝置的所有 attestation 結果視為不可信，並與 `DRM_CREDENTIAL_COHERENCE`、掛載點與 root 管理程式訊號合併評估。 |
| MODERATE | 帶 attestation 的金鑰背後沒有真的金鑰，符合 attestation 攔截層（如 TrickyStore）的行為。同樣應視該裝置的 attestation 結果為不可信；在累積更多乾淨裝置量測之前，不建議單憑此項封鎖使用者。 |
| NOT_OBSERVED | 未觀察到分歧。**不代表 attestation 可信** —— 一致的偽造看不到。 |
| INCONCLUSIVE | 檢查未能執行，應視為缺乏證據而非乾淨。API 36 以下的裝置一律落在這一格。 |

## 成本

- 產生一把帶 attestation 的 EC 金鑰（實機上通常數十毫秒，是本檢測的主要成本）、兩次憑證鏈讀取、一次 grant 與一次 revoke、一次金鑰刪除。
- 需要一次 JNI 呼叫進入 Java 層。不 fork 子行程、不啟動 helper process、不需整合者修改 manifest。
- 金鑰 alias 唯一且在 `finally` 區塊刪除，不會在使用者的 Keystore 中累積殘留。

## Evidence units

### keystore-grant.chain-consistency

承載「同一把金鑰經由兩條查詢路徑取得的憑證鏈必須相同」這一條自我參照約束。payload 保留兩條鏈各自的長度與逐張摘要，以及分歧的種類與位置；憑證內容不會被輸出。
