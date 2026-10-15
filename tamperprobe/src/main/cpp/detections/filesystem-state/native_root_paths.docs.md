# Native Root Paths

針對 KernelSU、APatch、Magisk 及相關提權工具的 21 個關鍵檔案系統路徑進行探測。每個路徑必須同時通過 `stat`、`lstat` 與 `open(O_PATH)` 中至少 2 種彼此獨立的原生呼叫確認，才認定該路徑物件真實存在。若確認存在專屬的 KernelSU、APatch 或 Magisk 管理路徑，評定為 STRONG；若僅確認通用的框架目錄或暫存殘留路徑，則評定為 WEAK。

## 這個檢測在看什麼

檢測器以編譯期常數陣列定義了 21 個關鍵路徑（`native_root_paths.cpp` 的 `rules[]`），分為四大類：

- **KernelSU 專屬路徑**（4 個，`ksu`）：`/data/adb/ksud`、`/data/adb/ksu`、`/data/adb/ksu/bin`、`/data/adb/ksu/modules`。
- **APatch 專屬路徑**（5 個，`apatch`）：`/data/adb/apd`、`/data/adb/ap`、`/data/adb/ap/bin`、`/data/adb/ap/modules`、`/data/adb/apatch`。
- **Magisk 專屬路徑**（5 個，`magisk`）：`/data/adb/magisk`、`/data/adb/magisk/magiskd`、`/sbin/.magisk`、`/system/bin/magisk`、`/system/xbin/magisk`。
- **通用與其他工具殘留路徑**（7 個，`other`）：`/data/adb`、`/data/adb/modules`、`/data/local/stryker`、`/data/local/tmp/luckys`、`/data/local/tmp/resetprop`、`/data/local/tmp/mount_mask`、`/data/local/tmp/mount_mark`。

針對每個路徑，依序執行三種獨立的原生系統呼叫：
1. `stat(path, &st)`：檢查目標路徑是否存在。
2. `lstat(path, &lst)`：感知符號連結，檢查原始連結節點。
3. `open(path, O_RDONLY | O_PATH)`：以 `O_PATH` 描述符驗證檔案系統節點的可開啟性。

只有當該路徑獲得至少 2 種方法確認成功（`confirmations >= 2`；程式以 `if (confirmations < 2) continue;` 排除其餘）時，才會被視為有效命中。

## 觸發代表什麼

依命中的工具類型分級：

| 強度 | 觸發條件 | 代表意義 |
|---|---|---|
| STRONG | 命中 KernelSU、APatch 或 Magisk 的專屬路徑（`ksuFound || apatchFound || magiskFound`） | 存在明確的現代 root 框架核心目錄或執行檔。 |
| WEAK | 僅命中通用目錄（如 `/data/adb`）或 `/data/local/tmp` 殘留檔（`hitCount > 0` 且無專屬框架命中） | 存在疑似 root 工具殘留或除錯產物，但缺乏特定框架的直接關聯。 |

不能推論的：
- **不能推論該框架當前正對本行程授權。** 檔案路徑的存在可能是過往安裝殘留，或是僅對其他特定應用程式提供服務。
- **不能推論當前處於提權執行狀態。** 這裡只證明檔案節點在檔案系統中可見。

## 已知偽陽性來源

- **歷史安裝卸載不完全的殘留檔案。** 使用者若曾安裝過 Magisk、APatch 或 KernelSU，隨後透過非標準方式卸載（例如僅移除 Manager APK 而未還原 boot 映像檔或未格式化 `/data` 分區），`/data/adb` 下的目錄依然存在，將持續觸發 STRONG 判定（`ksuFound || apatchFound || magiskFound` 的評級分支）。
- **開發者於 `/data/local/tmp` 的除錯測試殘留。** 測試工程師透過 adb push 放置於 `/data/local/tmp` 的工具（如 resetprop 測試程式或 mount 標記），會觸發分類為 `other` 的 WEAK 判定。
- **SELinux 政策異常放寬的客製韌體。** 標準 Android 裝置上，一般應用程式存取 `/data/adb` 會直接被 SELinux 阻擋（回傳 `EACCES`）。若某客製韌體錯誤地對一般 App 放行了 `/data/adb` 的查詢權限且恰好存在對應路徑，將造成誤判。

## 看不到什麼

- **權限邊界下的靜默阻擋——21 條規則中有 13–14 條在實機上結構性地無法作答。** 一般 App 的 uid 無法搜尋 `/data/adb` 目錄，而核心解析路徑時必須先取得上層目錄的搜尋權限，才會查詢最後一個元件；因此查 `/data/adb/magisk` 時在 `/data/adb` 那一步就被拒，回傳 `EACCES`，**不論該項目是否存在**。這類探針對目標攜帶的資訊量是零。
  實測（2026-09-11，Redmi 13C，Android 13，Magisk 30.6，`/data/adb/magisk` 確實存在）：21 條中 `/data/adb` 底下 13 條加上 `/system/xbin/magisk` 共 14 條回傳 `EACCES`，其餘 7 條回傳 `ENOENT`，成功 0 條。能作答的只剩較不具指向性的 `/sbin`、`/system/bin` 與 `/data/local/tmp` 殘留路徑。本量測未區分阻擋來自 DAC 或 SELinux。
  Pixel 7（Android 17，KernelSU v3.3.0，`/data/adb/ksu` 確實存在）上結論相同：`/data/adb` 底下 13 條全部回傳 `EACCES`，其餘 8 條回傳 `ENOENT`。與 Redmi 的差別只在 `/system/xbin/magisk`：Redmi 有 `/system/xbin` 但 App 無法搜尋（`EACCES`），Pixel 則沒有這個目錄（`ENOENT`）。兩台裝置、兩種 root 框架、兩個 Android 版本，`/data/adb` 的 13 條規則都無法作答。
  自 2026-09-11 起，報告以 `completedPathCount`（真正作答的規則數：Redmi 7、Pixel 8）與 `inaccessiblePaths`（被拒的路徑清單：Redmi 14 條、Pixel 13 條）公開這一點；若沒有任何規則能作答，檢測回報 INCONCLUSIVE 並附收集錯誤，而不是 NOT_OBSERVED。
- **核心層路徑隱藏會把「無法作答」偽造成「作答且不存在」（SUSFS `sus_path`）。** 實測（2026-09-17，Pixel 7，KernelSU-Next + SUSFS v2.3.0，追加實驗 E2 的 `K1`→`K2`）：把 `/data/adb` 加入 `sus_path` 後，原本回傳 `EACCES` 的 13 條規則全部改回傳 `ENOENT`，舊版據此把 `completedPathCount` 從 8 算成 21。從 App 行程以 `stat`、`lstat`、`access`、`mkdir`、`open(O_CREAT|O_EXCL)` 與 `symlink` 逐一量測，被隱藏的 `/data/adb` 與真正不存在的名稱回應完全相同，沒有任何呼叫能分辨。AOSP 的 `init.rc` 也不建立 `/data/adb`，所以無法以「它必定存在」當作錨點。
  自 2026-09-17 起，`/data/adb`（含其下）回傳 `ENOENT`／`ENOTDIR` 的規則**不再計入** `completedPathCount` 與 `notFoundPathCount`，改列於 `concealableNotFoundPaths`／`concealableNotFoundPathCount`。在 `/data/adb` 存在的裝置上 App 本來就收到 `EACCES`，行為不變；在被隱藏的裝置上，隱藏不再能提高報告宣稱的覆蓋率。代價是：在真的沒有 `/data/adb` 的未 root 裝置上，覆蓋率同樣只算 `/data/adb` 以外的規則。本檢測仍無法察覺隱藏本身。
- **Mount namespace 隱藏（DenyList / Shamiko）。** 若隱藏模組在目標應用的掛載命名空間中卸載了 `/data/adb` 或掛載遮蔽目錄，`/data/adb` 底下回傳 `ENOENT`，依上述規則列入 `concealableNotFoundPaths`；`/data/adb` 以外被遮蔽的路徑則無法察覺。
- **隨機化或非標準安裝路徑。** 使用者自行修改源碼編譯、安裝至自訂目錄的 root 工具。

## 建議處置

| 強度 | 建議 |
|---|---|
| STRONG | 偵測到明確的現代 root 框架專屬路徑（KernelSU/APatch/Magisk），為高風險環境訊號，建議與執行期注入檢測結合判讀。 |
| WEAK | 僅命中通用路徑或 tmp 殘留檔，可能為測試環境或歷史殘留，不建議單獨作為封鎖依據。 |
| NOT_OBSERVED | 未在 21 個固定路徑中確認到框架產物，不保證設備未 root（可能被權限正常阻擋或受 namespace／核心層隱藏）。判讀時以 `completedPathCount` 為準：它是真正作答的規則數，在兩台實測裝置上分別只有 7（Redmi）與 8（Pixel）；`concealableNotFoundPathCount` 大於 0 表示 `/data/adb` 底下收到的是隱藏也能產生的「不存在」。 |
| INCONCLUSIVE | 沒有任何規則能從本行程作答，應視為缺乏證據而非乾淨。 |

## 成本

- 嚴格遍歷 21 個固定路徑。
- 每個路徑固定執行 1 次 `stat`、1 次 `lstat` 與 1 次 `open(O_PATH)`，`open` 成功時再加 1 次 `close`。
- 全程最多 63 次輕量原生系統呼叫，不讀取檔案內容，不建立背景行程。
- 整合者無須任何設定。

## Evidence units

### native-root-paths.framework-artifact

記錄所有通過至少 2 次呼叫確認的路徑清單，包含路徑名稱、工具分類標籤（ksu, apatch, magisk, other）、確認次數與成功的系統呼叫組合（如 `stat, lstat, open`）。同時記錄覆蓋率：`attemptedPathCount`（定義的規則數）、`completedPathCount`（真正作答的規則數）、`notFoundPathCount`、`errorPathCount`、`inaccessiblePaths`，以及 `concealableNotFoundPaths`／`concealableNotFoundPathCount`（`/data/adb` 底下回傳「不存在」、不計為作答的規則）；命名與 `DANGEROUS_PACKAGES` 的路徑探測一致。`checkedCount` 為相容而保留，其值等於規則數，不代表成功檢查的數量。
