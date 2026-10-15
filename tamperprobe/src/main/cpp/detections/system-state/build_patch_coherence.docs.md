# Security Patch and Build Timestamp Coherence

比對每個分割區「自己宣告的 Android 安全性修補等級」與「自己被編譯出來的時間戳」。修補等級是發佈時人工設定的旗標，與編譯時間無關，而且 OEM 在公告發佈前至少一個月就會拿到修補，所以原廠映像檔本來就可能宣告晚於自己編譯日期的修補等級；但這個超前幅度有限，宣告值遠遠超前編譯時間，就代表該值是在映像檔產出之後才被寫上去的。這條比對完全在屬性集合內部完成，不依賴金鑰認證（key attestation），所以在 TrickyStore 之類的 keybox 偽造工具已經讓認證資料失去可信度時仍然成立。

## 這個檢測在看什麼

檢測器讀取數組成對的系統屬性，每一對的兩半都描述**同一個分割區**：

| 分割區 | 修補等級屬性 | 編譯時間屬性 |
|---|---|---|
| system | `ro.build.version.security_patch` | `ro.build.date.utc` |
| vendor | `ro.vendor.build.security_patch` | `ro.vendor.build.date.utc` |
| boot | `ro.vendor.boot.security_patch` | `ro.bootimage.build.date.utc` |
| odm | `ro.odm.build.security_patch` | `ro.odm.build.date.utc` |
| product | `ro.product.build.security_patch` | `ro.product.build.date.utc` |
| system_ext | `ro.system_ext.build.security_patch` | `ro.system_ext.build.date.utc` |

刻意**不做**跨分割區比對。system 與 vendor 的建置日期本來就可能相差數個月，那是正常的混合分割區出貨方式，拿來互比一定誤判。任何一半缺席或格式不符（修補等級不是 `YYYY-MM-DD`、時間戳不是 epoch 秒數）的分割區，一律標記為「不可比對」，不參與判定。

**實際可比對的分割區比表格少很多，而且隨 Android 版本改變。** 2026-09-06 實測（`event=partition_probe` 遙測）：

| 分割區 | Redmi 13C（Android 13） | Pixel 7（Android 17） |
|---|---|---|
| system | 可比對 | 可比對 |
| vendor | 可比對 | **修補等級讀不到** |
| boot | 兩半都讀不到 | 兩半都讀不到 |
| odm / product / system_ext | 只有時間戳 | 只有時間戳 |

`ro.vendor.build.security_patch` 與 `ro.bootimage.build.date.utc` 在 shell 底下讀得到，但在 `untrusted_app` 網域讀不到 —— 屬性讀取由 SELinux 屬性網域授權，App 看得到的屬性集合比 `adb shell` 窄。因此在 Android 17 上這條檢測實際只靠 system 分割區成立。這不影響命中率：`system.prop` 型的偽造工具改的正是 `ro.build.version.security_patch`。

判定依據是 `skew = 修補等級日期 − 編譯日期`。合法的正向落差來自 OEM 提前宣告即將發佈的資安公告。這在 Pixel 上是常態：社群 build.prop dump 中 245 個 Pixel 原廠正式版 build（2026-10-07 統計），skew 範圍為 −467 至 **+66 天**，中位數 +28，93% 為正值；同一批樣本中 Samsung / Xiaomi 的 23 個 build 則從未超過 0。這是非隨機樣本，只代表這批資料的分佈，不是誤判率。

## 觸發代表什麼

| 判定 | 條件 | 代表意義 |
|---|---|---|
| STRONG | 任一分割區 skew > 365 天 | 該分割區的修補等級不可能來自這個映像檔本身，屬性在出廠後被改寫。實測 Redmi 13C 上安裝 Play Integrity Fix `v4.7-1-inject-s` 後為 **+701 天** |
| MODERATE | 任一分割區 skew 介於 180 到 365 天 | 落差已遠超原廠樣本中觀察到的提前宣告範圍（最大 +66 天），但尚未大到足以單獨定論 |
| NOT_OBSERVED | 所有可比對分割區的 skew 皆 ≤ 180 天 | 未觀察到不可能的順序關係。實測未安裝 PIF 的 Pixel 7 為 **+20 天**，屬正常型態 |
| INCONCLUSIVE | 沒有任何分割區同時提供兩半 | 通道沒有產出，不能視為乾淨 |

可以推論的：**這個修補等級是在映像檔產出之後才被設定的。**

不能推論的：
- **不能推論是哪個工具做的。** 任何寫入 `system.prop` 的 Magisk / KernelSU 模組、重新打包的第三方 ROM，甚至 OEM 自己的錯誤設定，都會產生同樣的證據。
- **不能推論裝置目前處於 root 狀態。** 屬性可能是刷入 ROM 時就被寫死的。
- **不能推論真實的修補等級是什麼。** 本檢測只證明宣告值不自洽，無法還原原值。

## 已知偽陽性來源

- **OEM 提前宣告公告。** 這是主要的合法正向落差，實測 Pixel 7 為 +20 天（六月中編譯、宣告七月公告），Pixel 原廠樣本最大 +66 天。門檻設在 180 天，留下相當寬的緩衝。代價是：被偽造的 Pixel 7 落差 +51 天、+82 天（`2026-08-05`、`2026-09-05`）都在門檻以下，其中 +51 天本身就落在原廠 Pixel 的正常範圍內，任何門檻都無法區分。
- **只做安全性修補的小型 OTA。** 若 OEM 僅更新修補等級屬性而未重建映像檔，落差會逐月累積。理論上一年後就可能觸發 MODERATE。目前沒有實機觀察到這種出貨方式，但它是本檢測最可能的真實偽陽性來源。
- **門檻尚未校準。** 180 / 365 天這兩個數字只有兩台實機支撐（+20 與 +701），不是量測出來的分佈。
- **非標準的修補等級格式。** 某些 OEM 會寫入 `2024-09` 或自訂字串；這些一律視為不可比對，不會被判為異常。

## 看不到什麼

- **同時改寫編譯時間戳的攻擊者。** 只要把 `ro.build.date.utc` 一併往後調，這條比對就完全失效。之所以現在有效，純粹是因為現行工具不改它 —— 改了會與其餘所有建置屬性互相矛盾。
- **只在行程內偽造 `android.os.Build` 的模組。** Play Integrity Fix 的 `spoofBuild=true` 路徑只改 Java 層欄位，不寫屬性；本檢測讀的是屬性，看不到那一層。實測 Redmi 之所以會觸發，是因為該模組另外透過 `system.prop` 寫了兩行修補等級屬性。
- **完全一致的重新打包 ROM。** 重建整個映像檔並讓所有時間戳自洽的 ROM，不會留下這個矛盾。
- **App 讀不到的分割區。** 見上表：在 Android 17 上 vendor 的修補等級對 App 不可見，所以只改 vendor 而不改 system 的工具在該版本上看不到。
- **修補等級被調低的情況。** 負向落差（宣告值早於編譯時間）是正常的，不列入判定。

## 建議處置

| 強度 | 建議 |
|---|---|
| STRONG | 裝置宣告的安全性修補等級不可信，代表系統屬性曾被改寫以偽裝更新狀態。建議與 attestation、掛載點與 root 管理程式訊號合併評估；若您的風險模型依賴修補等級來判斷已知漏洞是否已修補，此時應視為未修補。 |
| MODERATE | 落差超出合理範圍但未達定論門檻，建議計入風險分數，不建議單獨阻斷使用者。 |
| NOT_OBSERVED | 未觀察到不可能的順序關係。注意這**不**代表裝置未被偽造 —— 見「看不到什麼」。 |
| INCONCLUSIVE | 屬性不可用，應視為缺乏證據而非乾淨。 |

## 成本

- 最多 12 次 `__system_property_get` 呼叫，無檔案 I/O、無 fork、無子行程、不需整合者修改 manifest。
- 耗時可忽略（< 1 ms）。

## Evidence units

### build-patch.security-patch-plausibility

承載「宣告的安全性修補等級不得晚於自身編譯時間」這一條順序約束。每個同時提供修補等級與編譯時間戳的分割區各產生一筆比對；`skewDays` 超過門檻者成為 finding，其餘分割區的比對結果（含不可比對的原因）仍完整保留在 payload 中作為遙測。
