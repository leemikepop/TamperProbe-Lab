# 危險套件檢測 (Packages Detections)

這個目錄包含兩個 published detector，並由 `package_targets.cpp` 直接從 native
asset manager 載入同一份 generated package target 與 Intent rule assets。

## `dangerous_packages.cpp`

檢測來源包含：

- C++ 透過 Android framework JNI 執行的 PackageManager 查詢
- C++ 透過 Android framework JNI 執行的已知 Intent action 探測
- 由 package name 衍生的 `/data/data/<package>` 與 `/data/user/0/<package>` 路徑探測

Core SDK 與 standalone RASP 不再各自提供 Kotlin/Java scanner；兩種部署路徑都由
同一份 native detector 載入 `package_indicators.txt` 與
`package_intent_actions.txt`，因此 collection 與 assessment 行為一致。

Detector-level ownership uses the canonical `app-visibility` Evidence Domain ID. Its two
co-located sidecars declare direct unit `domainId` values; v1 has no dependent-domain field.

payload 為簡單 evidence 類型：

- `foundPackages`
- `foundPaths`
- `inaccessiblePaths`

用途：

- `foundPackages` 表示 PackageManager 或已知 Intent 直接找到的套件
- `foundPaths` 表示 native `stat` 成功、可直接確認存在的 path indicator
- `inaccessiblePaths` 只表示 `EACCES`/`EPERM`，轉成 Observation 或 unit issue，不參與
  `OBSERVED` 判定；Android sandbox、SELinux 或一般目錄權限都可能合法產生拒絕

舊 `ROOT_INDICATOR_PATHS` 不再屬於這個 detector。`/data/adb`、
`/data/adb/modules` 與兩個 Magisk binary paths 已移到
`NATIVE_ROOT_PATHS`；`scene_*` 與 shared-storage tool directories 因缺乏足以支持
root-provider finding 的特異性而不再發布為 finding。

`DANGEROUS_PACKAGES` 只有 `foundPackages` 或 `foundPaths` 非空時回傳
`OBSERVED/WEAK`。FuseFixer 所涉及的 `Android/data`、`Android/obb` package
artifact visibility 由下方的 `PACKAGE_STORAGE_VISIBILITY` 負責；該 surface 的
Unicode/casefold/FUSE 行為不會把 `/data/adb` 或其他私有路徑的權限拒絕提升成
dangerous-package finding。

## `package_storage_visibility.cpp`

`PACKAGE_STORAGE_VISIBILITY` 沒有乾淨機基準線。它從目前 UID
推導 Android user，對每個 target package 的 `Android/data` 與 `Android/obb`
執行：

- canonical `newfstatat`
- mixed-case control
- 17 個 default-ignorable Unicode representative 在 `Android` 與 `data`/`obb`
  segment 前方、內部的變形
- 只針對 non-`ENOENT` 或 differential candidate 追加 access、`O_PATH` open 與
  bounded `getdents64`

Runtime 不建立、改名或刪除任何 path，也不保存 directory entry names。Canonical
artifact 或 canonical `ENOENT` 加上至少兩個一致的 Unicode success/permission
boundary observation 才產生 WEAK Signal；casefold、單一操作差異、FUSE-BPF 與
app-data-isolation 狀態只作 Research/Observation。

有副作用的 errno 與 held/unheld dentry 實驗只存在
`test-fixtures/storage-owner` 和 Android instrumentation harness。
