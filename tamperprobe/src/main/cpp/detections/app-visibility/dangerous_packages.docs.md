# Dangerous Package Indicators

透過 Android `PackageManager` 與原生 `fstatat` 系統呼叫，雙向探測維護清單中的危險或 root 相關應用程式套件。一方面在 Java/JNI 層查詢套件資訊、啟動 Intent 與 Intent Filter 解析；另一方面在 Native 層直接探測 `/data/data/<pkg>` 與 `/data/user/0/<pkg>` 等私有資料路徑。由於套件的存在可能為非作用中、被改名或來自多使用者環境的良性殘留，本檢測的判定強度固定為 WEAK。

## 這個檢測在看什麼

檢測器以兩個獨立通道對維護清單中的目標套件進行觀測：

1. **套件身分可見性（Framework PackageManager 通道）**：
   - 從資產檔（`package_indicators.txt` 與 `package_intent_actions.txt`）讀取維護的套件名稱與 Intent 動作規則。
   - 透過 JNI 呼叫 Android Framework 的 `PackageManager`：
     - 首先呼叫 `getApplicationInfo(packageName, 0)`。
     - 若未回傳，接著呼叫 `getLaunchIntentForPackage(packageName)`。
     - 針對定義了 Intent Action 的套件，建構 Intent 並呼叫 `queryIntentActivities(intent, 0)` 查詢是否有相符的 Activity 解析結果。
2. **應用程式資料路徑可見性（Native VFS 通道）**：
   - 對清單中的每個套件，組合出 2 個規範資料路徑：
     - `/data/data/<packageName>`
     - `/data/user/0/<packageName>`
   - 直接呼叫原生系統呼叫 `fstatat`（64 位元架構使用 `__NR_newfstatat`，32 位元使用 `__NR_fstatat64`，見 `probePathStatus()`），繞過 Java 框架層。
   - 分類探測結果：成功（`Exists`）、不存在（`NotFound`，`ENOENT`）、權限不足（`Inaccessible`，`EACCES` / `EPERM`）或系統錯誤（`Error`）。
   - 探測目標之前先跑兩個控制組：本 App 自己的資料目錄（必須可見），以及 `com.android.settings` 的資料目錄（一定已安裝、從不是隱藏目標，而且不在 app data isolation 的例外名單內）。只有兩者都可見時，目標的 `NotFound` 才算已作答；否則計入 `unconfirmedNotFoundCount`。自身可見而 Settings 不可見即判定為 app data isolation。

## 觸發代表什麼

- WEAK：只要在 PackageManager 中查到目標套件存在／Intent 可解析，或在原生檔案系統中確認目標私有目錄存在（`aggregateDangerousPackageAssessment()`），即評定為 WEAK。

不能推論的：
- **不能推論該套件正在運行或已取得 root 權限。** 安裝了危險套件（如 BusyBox 安裝器、舊版 SuperSU app 或模組管理介面）不代表目前設備已被提權。
- **不能推論當前應用程式受到攻擊。** 目標套件可能處於凍結或未啟用狀態。

## 已知偽陽性來源

- **已卸載套件的資料目錄殘留。** 使用者在卸載應用程式時若勾選「保留應用程式資料」，其目錄仍會留在 `/data/data/<packageName>` 或 `/data/user/0/<packageName>`，導致 Native 路徑探測回報 `Exists`（`collectAppDataPathVisibility()` 的 `Exists` 分支）。在啟用 app data isolation 的裝置上其他 App 的目錄本來就看不到，因此此來源預期只會出現在未隔離的裝置上（推論，未量測）。
- **多使用者或工作設定檔（Work Profile）痕跡。** 在多使用者環境下，主使用者（User 0）若曾安裝相關套件，可能在檔案系統路徑上留下痕跡。
- **套件名稱碰撞。** 維護名單中的特定套件名稱可能被良性應用程式偶然同名使用。
- **寬鬆的 Intent Filter 比對。** 若特定 Intent Action 被其他良性應用程式宣告支援，`queryIntentActivities` 可能回傳非空的解析結果，導致該套件被誤判為可見。

## 看不到什麼

- **隨機化套件名稱（Repackaged APK）。** 現代 root 管理工具（如 Magisk App 的「隱藏 Magisk 應用程式」功能）會隨機生成完全隨機的 package name 與隨機簽章進行重新打包，固定名稱清單完全無法命中。
- **Android 11+（API 30+）套件可見性限制。** Android 限制了應用程式查詢其他套件的能力。雖然本 SDK 的 manifest 生成器會在宿主 App 自動合併 `<queries>` 宣告，但若名單未涵蓋該套件或整合者清除了清單，PackageManager 將直接回報找不到。
- **主動的套件隱藏框架（Hide My AppList 一類）。** 這是實測到的主要盲區，而且**不會**表現成錯誤。
  2026-09-05 在一台 Pixel 7（Android 17）上量到：裝置 user 0 共有 366 個套件，本 detector
  只列舉得到 361 個，而缺少的正好是 `com.termux`、`moe.shizuku.privileged.api`、
  `com.resukisu.resukisu`、`com.alex193a.rootmypixel`、`org.frknkrc44.hma_oss` 這五個
  —— 全部都在我們的目標清單內，全部 `installed=true hidden=false suspended=false`、
  APK 也在磁碟上。即使替 App 授予 `QUERY_ALL_PACKAGES` 結果仍相同，而同一時間
  `getApplicationInfo("android")` 與查詢自身套件都成功。換句話說**查詢機制是好的，
  是套件本身被從我們的視野裡拿掉了**。這種情況下「沒找到」不代表「沒安裝」。
  請務必搭配 `visiblePackageCount` 一起判讀。
- **App data isolation 讓資料路徑通道在現行 Android 上看不到任何目標。** 本節先前寫的是：其他 App 的目錄會回傳 `EACCES` 並歸類為 `Inaccessible`。**實測並非如此。** 2026-09-11 在 Redmi 13C（Android 13）與 Pixel 7（Android 17）上從 Sample App 行程量測：`/data/data/`、`/data/user/0/`、`/data/user_de/0/` 底下，本 App 自己的目錄可見，`com.android.settings` 以及確實已安裝的 `com.topjohnwu.magisk`、`me.weishu.kernelsu` 等一律回傳 `ENOENT`，與不存在無從區分；唯一的例外是 `com.google.android.gms`，兩台都可見。
  由於 `ENOENT` 當時被當成「已確認不存在」並計入 `completedPathCount`，`ablation_2026` 十四格裡本 unit 每一格都回報 156/156 已作答、全部不存在——包括同一次掃描中 package unit 已查到 Magisk 已安裝的 `R0`。自 2026-09-11 起，控制組偵測到這種情形時本 unit 回報 UNAVAILABLE 並附 `app-data-isolated`，但**不會**因此讓整個 detector 變成 INCONCLUSIVE：本 detector 在十四格中的判定本來就全部來自 package unit，沒有任何一格因此改變。

## 建議處置

| 強度 | 建議 |
|---|---|
| WEAK | 僅代表裝置上安裝過或殘留相關套件，屬於環境特徵輔助信號，不可單獨用作封鎖使用者的決策依據，應與核心完整性訊號關聯判讀。 |
| NOT_OBSERVED | 未在維護清單中發現可見的套件或路徑，不代表未安裝（套件可能已隨機化名稱或受系統隱藏）。 |
| INCONCLUSIVE | JNI 上下文不可用或資產檔讀取失敗導致無法執行完整查詢；兩個 unit 皆回報 UNAVAILABLE 並附 `target-list-unavailable`。另外，若本 App 看不見自己的資料目錄（`app-data-self-control-failed`），代表路徑通道本身壞了，也會導致 INCONCLUSIVE——這與 app data isolation 不同，後者不會。 |

## 成本

- 依據維護清單中的套件數量（`package_indicators.txt`）：
  - 每個套件在 Java 端呼叫 1~2 次 PackageManager 方法，並遍歷 Intent 規則。
  - 每個套件在 Native 端發起 2 次 `fstatat` 系統呼叫。
- 需要傳入 Android `Context` 與 JNI 環境。
- **整合者注意清單合併**：SDK 會自動透過 Manifest Merger 注入 `<queries>` 標籤，整合者一般無須手動配置，但須注意不可在最終 manifest 中移除這些 `<queries>`。
- 不 fork 行程。

## Evidence units

### dangerous-packages.package-identity-visibility

本 unit 會先跑兩個控制組再開始比對：查詢自身套件（永遠可見），以及查詢 `android`
（在每台裝置上都是 forceQueryable）。任一控制失敗就代表查詢機制本身壞了，此時
「查不到任何目標」不具意義，會記為 `package-query-control-failed` 收集問題。
payload 另外輸出 `visiblePackageCount`，也就是本行程實際列舉得到的套件總數：
數字正常卻一個目標都沒命中，才是有意義的陰性結果。

記錄透過 PackageManager 查詢到的已安裝危險套件名稱清單（`detectedPackages`）與查詢期間產生的各類 issue（如 Intent 查詢失敗等）。

### dangerous-packages.app-data-path-visibility

記錄透過原生 `fstatat` 系統呼叫確認存在的私有資料路徑清單（`foundPaths`），以及因權限不足而無法確定的路徑清單（`inaccessiblePaths`）。

另外記錄兩個控制組的結果（`selfControl`、`crossPackageControl`，值為 `exists`／`not_found`／`inaccessible`／`error`／`not_attempted`）、`isolationDetected`，以及因控制組未通過而不計為作答的 `NotFound` 數量（`unconfirmedNotFoundCount`）。在啟用 app data isolation 的裝置上——兩台實測裝置皆是——本 unit 沒有任何作答，狀態為 UNAVAILABLE，控制組結果記錄在 `app-data-isolated` 收集問題的屬性中。
