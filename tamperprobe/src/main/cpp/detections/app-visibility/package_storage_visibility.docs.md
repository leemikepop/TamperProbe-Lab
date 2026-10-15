# Package Storage Visibility

針對外部共用儲存空間（`/storage/emulated/<userId>/Android/data` 與 `.../obb`），測試危險套件目錄在規範路徑、大小寫混淆及 17 種 Unicode 特殊字元變形下的可見性。此檢測探討 Android Scoped Storage、FUSE 與 FUSE-BPF 檔案系統在處理路徑別名時是否存在視角差異或隔離穿透。本檢測沒有乾淨機基準線，判讀前必須先在目標裝置族群上收集基準線。

## 這個檢測在看什麼

檢測器以規範路徑與變形路徑對外部儲存空間進行交叉探測：

1. **路徑範圍**：
   - 取得當前行程 UID 並計算 `userId`（`uid / 100000`）。
   - 對目標套件清單中的每個套件，分別探測 `data` 與 `obb` 兩個目錄。
   - 規範路徑（Canonical）：`/storage/emulated/<userId>/Android/<data|obb>/<packageName>`。
2. **變形路徑建構（共 69 種變體）**：
   - 大小寫混淆組（1 種）：`aNdRoId/DaTa/<pkg>` 或 `aNdRoId/ObB/<pkg>`。
   - Unicode 特殊字元別名（68 種）：挑選 17 種代表性 Unicode 代碼（軟連字號 `U+00AD`、零寬度空格 `U+200B`、韓文填空符 `U+115F`、`U+3164`、`U+FFA0`、字元連接號 `U+2060`、零寬度非中斷空格 `U+FEFF` 等，`package_storage_visibility.cpp` 第 36-54 行），分別插入 4 個位置（`android_prefix`、`android_inside`、`protectedRoot_prefix`、`protectedRoot_inside`）。
3. **多重原生系統呼叫驗證**：
   - 首先透過 `fstatat` 取得基礎狀態。
   - 若狀態異常（不為 `NOT_FOUND` 或與規範路徑不同），啟動交叉確認（Corroboration）：
     - `probeAccess`：呼叫 `faccessat2`（若為 `ENOSYS` 則 fallback 至 `faccessat`）。
     - `probeOpen`：呼叫 `openat(..., O_PATH | O_DIRECTORY | O_CLOEXEC)`。
     - `probeList`：呼叫 `openat(..., O_RDONLY | O_DIRECTORY)` 搭配 `getdents64` 嘗試讀取目錄項目。

## 觸發代表什麼

依結果分類：
- WEAK（`canonical_package_data`）：規範路徑直接回報存在，代表該危險套件的儲存目錄直接曝露在應用程式視角中。
- WEAK（`unicode_alias`）：規範路徑被系統隱藏（回報 `NOT_FOUND`），但 Unicode 別名路徑卻成功回報存在或存取受拒（`DENIED`），揭露了底層目錄的存在。
- Telemetry（`platform_oracle`）：規範路徑與變體路徑產生系統行為分歧，僅作為儲存堆疊隔離特性的遙測資料，不影響整體 outcome。

不能推論的：
- **不能推論裝置已 root 或套件被啟動。** 外部儲存目錄可能為未清除的歷史快取。
- **不能推論此別名為通用繞過。** 這反映的是底層 FUSE/BPF 的路徑解析特性，不能直接推論套件本身的特權狀態。

## 已知偽陽性來源

- **解除安裝後的外部儲存殘留。** Android 系統在使用者卸載 App 時，經常保留 `/sdcard/Android/data/<package>` 目錄。良性使用者若曾短暫安裝測試工具後卸載，殘留目錄將導致 `canonical_package_data` 觸發（`package_storage_visibility.cpp` 第 393-404 行）。
- **FUSE / FUSE-BPF 與不同 Android 版本的 Unicode 規範化分歧。** 各 OEM 或不同 Android 版本的核心與 FUSE 模組對 Unicode 字元的大小寫折疊（case folding）或正規化邏輯不一，可能對不存在的目錄回傳非 `ENOENT` 的代碼，引發虛假的分歧訊號。
- **缺乏乾淨機基準線。** 變體組合與門檻尚未在大量乾淨機型上完成校準，因此在未知 OEM 裝置上極易產生雜訊。

## 看不到什麼

- **未建立外部儲存目錄的目標。** 許多 root 模組與提權工具只存在於 `/data/adb`，從未在外部儲存空間建立任何檔案。
- **Scoped Storage 徹底阻斷且無別名漏洞的裝置。** 在修復了別名解析並嚴格啟用 Scoped Storage 的 Android 裝置上，所有路徑皆回報 `EACCES` 或 `ENOENT`，本檢測無法看出端倪。
  實測（`ablation_2026`，兩台裝置十四格）：每格 10,764 次變形探測加 156 次規範基線，**0 個 finding、0 筆 telemetry**，包括回報 FUSE-BPF 的 Pixel 7（Android 17）與未回報 FUSE-BPF 的 Redmi 13C（Android 13）。基線探測每格 156/156 完成，所以這是正確的沉默而非通道失效，與本段描述一致。
- **未列於維護清單的套件。**

## 建議處置

| 強度 | 建議 |
|---|---|
| WEAK | 此結果僅代表外部儲存路徑可見或存在 Unicode 別名分歧。正式採用前請務必先在你的使用者族群上收集分佈並建立基線，切勿直接用於封鎖或處置。 |
| NOT_OBSERVED | 目標套件的共用儲存目錄未呈現可見性或別名穿透。 |
| INCONCLUSIVE | 外部儲存根目錄不可讀取（如未掛載或無權限），或基準測試未完成。 |

## 成本

- **系統呼叫量極大**：每個受測套件在 `data` 與 `obb` 兩個根目錄下各自測試 69 種變體，單一套件即產生 138 次 `fstatat`；若有候選路徑出現，還會追加 `faccessat`、`openat` 與 `getdents64`。若受測套件有數十個，系統呼叫總量可達數千次。
- 程式內部對保留記錄數設有上限（最多 16 筆觀測記錄與錯誤），避免記憶體膨脹。
- 不 fork 任何行程。
- 整合者無須特殊權限設定，但需評估大量 I/O 對背景掃描時間的影響。

## Evidence units

### package-storage.path-visibility

記錄規範路徑或 Unicode 別名路徑直接確認存在的事件（`canonical_package_data` 或 `unicode_alias`），包含命中的套件名稱、目標保護目錄（data 或 obb）、使用的 Unicode code point 與插入位置。

### package-storage.path-representation-differential

記錄規範路徑與 Unicode/大小寫變體之間的平台行為分歧（`platform_oracle`）。本 unit 僅作為儲存堆疊（FUSE/BPF）行為分析之遙測資料，不直接提升安全風險等級。
