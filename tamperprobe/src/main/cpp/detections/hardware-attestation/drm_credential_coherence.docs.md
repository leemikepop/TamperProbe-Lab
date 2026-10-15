# DRM Credential and Boot State Coherence

比對「裝置自己宣稱的開機狀態」與「它的 Widevine 憑證」。Widevine L1 是 DRM trustlet 裡的逐機金鑰材料，解鎖 bootloader 會把它銷毀，而且**沒有任何 userspace 模組能把它重新佈建回來**。因此一台宣稱 bootloader 已上鎖、開機鏈已驗證，卻同時宣告 Widevine L1 且回報「未佈建」佔位系統 ID 的裝置，等於同時說了兩件不可能同時成立的話。這條檢測的價值在於它跨越了一個其他檢測跨不過的信任邊界：屬性可以被模組改寫、attestation 可以被 keybox 偽造，但憑證變不出來。

## 這個檢測在看什麼

分成兩邊讀，再比對：

**宣稱側（模組改得動）** —— `ro.boot.verifiedbootstate`、`ro.boot.flash.locked`、`ro.boot.vbmeta.device_state`。三者必須**一致地**指向「已上鎖」才算是宣稱上鎖（`green` + `1` + `locked`），只要有任何一個誠實地說 `orange` / `0` / `unlocked`，就視為裝置沒有在說謊，直接排除。

**憑證側（模組改不動）** —— 透過 `MediaDrm`（Widevine UUID）讀取：

| 欄位 | 意義 |
|---|---|
| `securityLevel` | 外掛宣告的安全等級，`L1` 才有可能有硬體憑證 |
| `systemId` | 佈建批次識別；值為 `2147483647`（`Integer.MAX_VALUE`）代表**沒有佈建身分**的佔位值 |
| `openSession()` 結果 | `not_provisioned` 進一步佐證憑證不存在 |
| `HW_SECURE_ALL` 支援度 | 遙測用 |

**只有在「宣稱上鎖」且「宣告 L1」時才進行判定。** 其餘情況一律標記 `comparable=false` 並附上原因，完整保留在 payload 作為遙測。

讀取範圍是刻意受限的：**不讀取** `deviceUniqueId` 與 `provisioningUniqueId`，那兩者是逐機唯一識別碼。`systemId` 識別的是佈建批次而非個別手機，且正是本檢測的判定依據，因此予以回報。DRM 例外只記錄類別名稱與發生階段，不記錄廠商錯誤字串，避免帶出裝置特定內容。

## 觸發代表什麼

| 判定 | 條件 | 代表意義 |
|---|---|---|
| MODERATE | 宣稱上鎖 + 宣告 L1 + `systemId` 是未佈建佔位值 | 裝置的開機狀態宣稱與其硬體憑證互相矛盾。最常見的成因是 bootloader 曾被解鎖，而屬性或 attestation 正在被偽裝成上鎖 |
| NOT_OBSERVED | 沒有矛盾，或不可比對 | 見下方「看不到什麼」—— 這**不**代表裝置未被竄改 |
| INCONCLUSIVE | `MediaDrm` 不可用或 JNI 環境缺失 | 通道沒有產出，不能視為乾淨 |

**目前上限刻意壓在 MODERATE，不會出現 STRONG。** 矛盾本身在邏輯上是成立的，但**尚未量測過任何一台上鎖未改機的對照裝置**，所以「正常裝置出現這個組合的機率」是未知數。等有乾淨對照之後才會考慮提高等級。

不能推論的：
- **不能推論是哪個工具造成的。** 主機板更換、RMA、某些從未出貨 L1 佈建的機型，都可能呈現相同外觀。
- **不能推論 bootloader 現在是解鎖的。** 憑證一旦被抹除就不會因為重新上鎖而回來，所以這是「曾經解鎖過」的證據，不是當下狀態的證據。

## 已知偽陽性來源

- **沒有乾淨對照，偽陽性率完全未知。** 這是本檢測目前最大的限制。
- **主機板更換或維修。** 換過主機板的裝置可能失去原本的 L1 佈建，但 bootloader 從未被使用者解鎖。
- **佈建延遲。** 少數裝置的 DRM 佈建是在首次使用 DRM 內容時才完成；在那之前 `systemId` 可能就是佔位值。目前無實機資料佐證這個情境會不會發生在宣告 L1 的機器上。
- **OEM 自訂的 Widevine 外掛。** 若某廠商的外掛以非標準方式回報 `systemId`，本檢測會誤判。已知常數 `2147483647` 是 Widevine 通用佔位值，但不排除例外。

## 看不到什麼

- **誠實回報解鎖的裝置。** 只要 `ro.boot.*` 任何一項說解鎖，就直接排除 —— 這是刻意的，這種裝置沒有在說謊，不是本檢測的目標。
- **只有 L3 的裝置。** 從來沒有 L1 憑證可以失去，因此結構上不可比對。大量中低階機種屬於這一類，在那些機器上這條檢測永遠是 NOT_OBSERVED。
- **從未解鎖過的 root。** 透過漏洞取得 root 而未動 bootloader 的裝置（例如 exploit 型 root），Widevine 憑證完好，本檢測看不到。
- **憑證被偽造的可能性。** 本檢測假設模組無法重新佈建 L1。若未來出現能偽造 `MediaDrm` 回應的模組（例如 hook `getPropertyString`），這條就會失效；Duck 另外比對 Java 與 NDK 兩側讀值以偵測單邊 hook，TamperProbe 目前只讀 Java 側。

## 建議處置

| 強度 | 建議 |
|---|---|
| MODERATE | 裝置的開機狀態宣稱不可信。建議與 attestation、掛載點、root 管理程式訊號合併評估；若您的風險模型依賴 verified boot 判斷裝置完整性，此時不應採信該宣稱。不建議單獨以此阻斷使用者，尤其在偽陽性率尚未量測之前。 |
| NOT_OBSERVED | 未觀察到矛盾。注意 `comparable=false` 也會落在這一格，payload 中的 `notComparableReason` 才說明原因（該欄位目前**不在** UnitPlan 的 `payloadKeys` 內，因此只出現在 payload，不會成為 evidence 屬性）。 |
| INCONCLUSIVE | DRM 堆疊不可用，應視為缺乏證據而非乾淨。 |

## 成本

- 建立一個 `MediaDrm` 實例、讀三個字串屬性、開關一次 session，隨即釋放；另加三次屬性讀取。
- 需要一次 JNI 呼叫進入 Java 層。不 fork 子行程，不需整合者修改 manifest。
- `openSession()` 在少數裝置上可能較慢（數十毫秒），且若其他 App 正持有 DRM 資源會回報 `resource_busy`（視為暫時性狀況，不列入判定）。

## Evidence units

### drm-credential.boot-state-coherence

承載「宣稱的開機狀態」與「Widevine 憑證是否存在」之間的一致性。只有在裝置同時宣稱上鎖且宣告 L1 時才成為可比對；其餘情況以 `comparable=false` 與 `notComparableReason` 完整記錄於 payload，不影響判定。
