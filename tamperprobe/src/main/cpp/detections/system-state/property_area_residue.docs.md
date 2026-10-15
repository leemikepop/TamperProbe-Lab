# Property Area Physical Residue Detection

直接解析行程記憶體中由 Bionic libc 對映的屬性區塊（`/dev/__properties__/*`），深入分析 `struct prop_info` 內部結構，檢驗唯讀屬性的更新計數器、值長度編碼與字串長度的一致性，並掃描屬性值緩衝區在第一個 `\0` 終止符之後是否殘留未清零的舊資料位元組（Trailing-Byte Residue）。這項檢測旨在從物理記憶體結構層面，捕捉以 `resetprop` 為代表的屬性原地竄改與偽造行為。

## 這個檢測在看什麼

檢測器透過 `/proc/self/maps` 定位行程位址空間中已映射的所有屬性區塊（Property Areas），遍歷其中所有的屬性節點（`PropertyInfo`），執行兩大物理完整性校驗：

1. **Serial 欄位與長度一致性審計**：
   - 在 Bionic 實作中，`serial` 的高 8 位元（`serial >> 24`）儲存屬性值的字串長度，低 24 位元為更新計數器與寫入鎖。
   - 檢查短屬性的 `serial >> 24` 是否與緩衝區內實際字串長度相符。若遭工具直接原地覆寫但未同步更新 `serial`，即觸發長度不符異常。
   - 檢查 `ro.*` 唯讀屬性的更新計數器（`serial & 0xffffff`）。在 Android 原生 `init` 流程中，唯讀屬性在開機加入後其計數器恆為 0；若計數器大於 0，代表該屬性在開機後曾被呼叫 `__system_property_update` 強行修改。
2. **緩衝區尾部殘留位元組掃描（Trailing-Byte Residue）**：
   - 每個短屬性在記憶體中配置固定的 `PROP_VALUE_MAX`（92 位元組）空間，原生開機時未使用的空間全數為零（`0x00`）。
   - 當 `resetprop` 等工具將長字串屬性（如 `ro.build.type = "userdebug"`）原地覆寫為較短字串（如 `"user"`）時，若僅寫入新字元與 `\0`，後續位元組將殘留舊字串的尾部碎片（如 `"ebug"`）。
   - 檢測器掃描第一個 `\0` 終止符之後的所有位元組，一旦發現非零位元組即標記為殘留特徵。

## 觸發代表什麼

| 判定 | 條件 | 代表意義 |
|---|---|---|
| STRONG | 敏感核心屬性（如 `ro.build.type`、`ro.build.tags`、`ro.boot.verifiedbootstate` 等）發現 Serial 長度不合、`ro.*` 更新計數器大於 0，或存在尾部殘留位元組。 | 系統中的核心唯讀安全屬性極高機率曾遭 `resetprop` 或記憶體修補工具原地竄改，以偽造開機或系統建置狀態。 |
| NOT_OBSERVED | 未在敏感屬性上發現 serial 異常或尾部殘留。 | 見下方「看不到什麼」的版本界線：這在 Magisk v30.2 以後的堆疊上是正確結果，不代表未被竄改。 |
| INCONCLUSIVE | 無法解析任何屬性區塊。 | 底層資料無法採集。 |

> 本檢測**只會**產生 STRONG、NOT_OBSERVED 或 INCONCLUSIVE。所有 finding 在程式中都硬編碼為
> `EvidenceStrength::STRONG`，且只有敏感安全屬性（`anomalyMayDriveOutcome()`）能提升
> `strongestFinding`；非敏感屬性的異常只進 telemetry，不影響判定。本表在 2026-09-12 之前
> 列有 MODERATE 與 WEAK 兩列，但程式碼從未產生這兩種結果。

不能推論的：
- **不能推論當前應用程式已遭受記憶體注入。** 屬性區的竄改通常發生在系統層級（如開機階段由 Magisk 執行），不代表當前 App 的私有堆疊被侵入。
- **不能推論裝置當下保有活躍的 root shell。** 屬性竄改可能在開機引導階段完成後即關閉 root 守護程序。

## 已知偽陽性來源

以下三項都是 2026-09-05 在兩台實機上量到的，不是推測。

- **`ro.*` 的更新計數器大於 0 不等於被竄改。** init 自己就會更新一部分 `ro.*` 屬性：
  Pixel 7 上的 `ro.boot.boottime`、`ro.boot.boottime_extra` 會隨開機階段逐步寫入；
  Redmi 13C 上的 `ro.netflix.channel`、`ro.facebook.partnerid` 是 OEM 合作夥伴屬性；
  `ro.build.version.known_codenames` 兩台都會出現。早期版本把任何 `ro.boot.*` 都視為
  安全敏感屬性，結果**兩台機器都因為 init 自己的記帳而被判 STRONG**。
  現在只有明確清單內、且 init 只寫一次的屬性可以左右結論。
- **尾部殘留是 bionic 的常態，不是竄改痕跡。** Pixel 7 上 881 個屬性有 **200 個**帶殘留
  （23%），Redmi 13C 上 1133 個中有 15 個。bionic 在原地覆寫時不會清空 value buffer 尾端，
  所以任何一次「用較短的值覆寫較長的值」都會留下殘留。因此只有 `ro.*` 屬性的殘留才計入判定
  —— 而實測顯示兩台機器上 `ro.*` 的殘留數都是 **0**。
- **正在被更新的屬性。** bionic 更新屬性時會先設置 dirty bit，此時 serial 與 value 本來就
  不一致。這個時間窗被明確排除，不會產生長度不符的誤判。

## 看不到什麼

- **本檢測沒有偵測到兩台機器上確實存在的屬性偽造。** Redmi 的 Play Integrity Fix 與 Pixel 的
  ReSukiSU 都在偽造屬性，但它們實際偽造的 `ro.build.fingerprint`、`ro.build.type`、
  `ro.boot.verifiedbootstate`、`ro.boot.flash.locked` 在兩台機器上**都沒有任何殘留或 serial 異常**。
  `SYSTEM_PROPERTIES_TAMPER` 的多來源交叉比對同樣回報 `mismatches=0`。
  換句話說，現代工具的屬性偽造不會留下這一類物理痕跡 —— 這是關於技術本身的否定結果。
- **這個沉默有明確的版本界線，而且是上游修補的結果，不是通道失效。** 兩個 unit 在十四格中
  `collectionStatus` 皆為 COMPLETE:屬性區掃描成功，只是沒有殘留可找。原因可以追到上游:
  serial counter 會被 `resetprop` 加一是公認的偵測向量（Magisk issue #7696，2024-01 提出），
  而 **Magisk v30.2（2025-08-06）的 changelog 明載 `[resetprop] Reduce property modification
  traces`**，並延續至 v30.4／v30.5／v30.6。本研究的 Redmi 跑的是 **Magisk 30.6**，也就是包含該
  修補的版本。更新的實作（例如 resetprop-rs）更進一步提供 stealth write:serial 歸零、不做
  global serial bump、不觸發 futex wake。
  因此本檢測**針對 Magisk v30.1 以前的堆疊仍然有效**，應予保留;在 v30.2 以後的堆疊上沉默是
  正確結果。在取得舊版 root 框架的裝置之前，本檢測沒有正對照。
- **透過重新分配 Trie 節點進行的修改。** 若竄改工具不是原地覆寫，而是重建節點並清零記憶體，
  本檢測看不到殘留。
- **等長或更長字串的覆寫。** 不會留下尾部殘留。
- **尚無乾淨機基線。** 目前兩台測試機都已 root，因此**不能引用本檢測的誤判率**，
  上述數字只界定了在這兩台 root 機器上觀察到的範圍。

## 建議處置

| 強度 | 建議 |
|---|---|
| STRONG | 核心開機與安全屬性存在原地竄改特徵，高度代表環境曾套用 `resetprop` 等提權隱藏工具。建議與其他核心或 attestation 訊號綜合評估。 |
| MODERATE | 唯讀屬性存在異常更新計數，建議作為風險評分依據，不建議單獨以此阻斷使用者。 |
| NOT_OBSERVED | 未發現屬性區物理殘留或 serial 異常。 |

## 成本

- 僅讀取與解析當前行程已映射之記憶體位址（`/proc/self/maps` 中的屬性分區）。
- 不執行 fork 子行程，不調用額外 shell 命令，耗時極短（通常 < 5 ms）。

## Evidence units

### system-property-residue.serial-anomaly

承載 Bionic `prop_info` 的 `serial` 字組物理結構審計。檢驗唯讀屬性（`ro.*`）的更新計數器是否大於 0（正常開機後唯讀屬性計數器恆為 0），以及屬性值長度與 `serial >> 24` 高位長度編碼是否相符。

### system-property-residue.trailing-bytes

承載屬性值緩衝區的尾部殘留位元組（Trailing-Byte Residue）掃描。檢驗 `PROP_VALUE_MAX` 緩衝區中第一個 `\0` 終止符之後是否殘留非零位元組，捕捉將長字串屬性（如 `userdebug`）原地覆寫為短字串（如 `user`）但未清零剩餘緩衝區的竄改痕跡。
