# LSPosed/Xposed Maps Scan

掃描當前行程的 `/proc/self/maps` 虛擬檔案，逐列比對記憶體映射路徑中是否包含 LSPosed、Xposed、EdXposed 或 Riru 等常見 Android 執行期 Hook 框架的 11 個特徵關鍵字。若在行程記憶體映射中發現這些專屬框架檔案或載入路徑，即表示當前行程已被注入此類框架，檢測器將發出 STRONG 等級的警告。

## 這個檢測在看什麼

檢測器透過 `fopen` 讀取 `/proc/self/maps`，解析每一列記憶體映射的位址區間、權限與檔案路徑，並比對路徑字串是否包含以下 11 個寫死在程式碼中的框架特徵字串（`lsposed_maps.cpp` 第 23-35 行）：

- `lspd`
- `libxposed`
- `xposed_art`
- `edxposed`
- `lsposed`
- `riru`
- `libriruloader`
- `liblspd`
- `de.robv.android.xposed`
- `/lspd/`
- `XposedBridge`

比對邏輯對路徑逐一執行 `strstr(path, marker) != nullptr`（第 71 行）。若有任何一行映射路徑包含上述任一子字串，即將該路徑去重後記錄於 `findings` 清單，並累計命中總數 `hitCount`。

## 觸發代表什麼

OBSERVED 代表在當前行程的記憶體映射空間中，明確發現了屬於 LSPosed、Xposed 或 Riru 框架的動態函式庫、JAR 套件或工作目錄路徑，整體判定為 STRONG。這表示應用程式行程已經被注入 Hook 框架，行程內的 Java 與 Native 邏輯隨時可能被外部模組攔截或竄改。

不能推論的：
- **不能推論具體啟用了哪些 Xposed 模組。** 本檢測僅能確認框架核心載入，無法得知模組的具體行為或作用目標。
- **不能推論系統整體的 root 狀態。** 某些免 root 虛擬環境或沙盒容器亦可能載入 Xposed 相容框架。

## 已知偽陽性來源

- **包含關鍵字子字串的良性檔案或套件路徑。** 比對邏輯採用 `strstr(path, marker) != nullptr`（`lsposed_maps.cpp` 第 71 行），為單純的子字串比對而未限制單詞邊界。若應用程式本身、第三方合法 SDK 或快取檔案的路徑名稱恰好包含較短的關鍵字（如 `riru` 或 `lspd`，例如名為 `com.example.harirunner` 的套件、包含 `libriruri.so` 的音效庫、或包含洛聖都警局代稱的遊戲資產 `.../lspd/...`），皆會造成誤判並直接升級為 STRONG。
- **資安掃描或防毒 SDK 的特徵庫映射。** 若 App 內部整合了其他本機安全掃描工具，且該工具將包含上述特徵字串的特徵規則檔以 `mmap` 載入記憶體，且檔名直接含有特徵名稱，亦會觸發比對。

## 看不到什麼

- **具備 maps 隱藏能力的現代隱藏工具。** 現代 Zygisk 模組（如 Shamiko、Zygisk Next）或 Magisk DenyList，能夠在應用程式行程中攔截 `/proc/self/maps` 的讀取或透過 mount namespace 隔離，使相關模組映射在 maps 中被過濾或抹除。
- **匿名記憶體與 memfd 注入。** 若框架或模組透過 `memfd_create` 建立匿名檔案描述符載入，或將動態函式庫直接手動映射至匿名記憶體（顯示為 `[anon:...]` 或空路徑），本檢測無法透過路徑字串識別。
- **重新命名或自行編譯的框架。** 攻擊者若自行從原始碼編譯 LSPosed/Xposed 並替換所有函式庫檔名與路徑字串（不在上述 11 個標記中），本檢測無法察覺。

## 建議處置

| 強度 | 建議 |
|---|---|
| STRONG | 行程內已載入明確的 Xposed/LSPosed/Riru 框架特徵路徑，屬於極高風險的執行期竄改訊號。建議檢查 `findings` 中的具體路徑與標記，若確認非套件名稱碰撞，應將其納入核心風控處置（如拒絕敏感交易或限制存取）。 |
| NOT_OBSERVED | 在 `/proc/self/maps` 的路徑中未發現 11 個特徵標記。不能保證環境未受 Hook 框架影響（可能使用了 maps 隱藏技術）。 |
| INCONCLUSIVE | 無法開啟或讀取 `/proc/self/maps`（通常是權限遭極端限縮），應視為收集失敗。 |

## 成本

- 僅透過 `fopen` 循序讀取 `/proc/self/maps` 一次，逐行進行字串解析與比對。
- 不 fork 任何子行程，不執行外部指令。
- 整合者無須在 `AndroidManifest.xml` 中宣告任何權限或服務。

## Evidence units

### lsposed-maps.framework-marker

承載 `/proc/self/maps` 掃描結果。當發現匹配 11 個框架特徵字串的映射路徑時，在此 unit 記錄命中的特徵標記（`marker`）與完整映射路徑（`path`），並產出 STRONG 等級的 finding。
