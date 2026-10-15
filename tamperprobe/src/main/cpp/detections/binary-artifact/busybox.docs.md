# BusyBox Checking

針對 Android 常見的 6 個 BusyBox 候選路徑，依序透過 `access`、`lstat`、`open(O_PATH)`、`fstat` 與 ELF 標頭讀取（`pread` 前 4 位元組）確認是否存在可見檔案。BusyBox 本身是一套 Linux 命令列工具集，其存在僅代表檔案系統中有該執行檔或相容產物，不能直接等同於裝置已被 root 或當前行程已取得提權能力；因此本檢測最高僅會產出 WEAK 判定。

## 這個檢測在看什麼

檢測器以編譯期常數固定檢查以下 6 個候選路徑：

- `/system/bin/busybox`
- `/system/xbin/busybox`
- `/sbin/busybox`
- `/data/local/busybox`
- `/data/local/bin/busybox`
- `/data/local/xbin/busybox`

對每一個候選路徑，依序執行多階段原生系統呼叫：

1. `access(path, F_OK)`：確認檔案路徑是否可見。
2. `lstat(path, &linkStat)`：取得符號連結自身的中繼資料，防止解析被重導向。
3. `open(path, O_PATH | O_CLOEXEC)` + `fstat(fd, &resolvedStat)`：安全取得實際目標檔案的類型（`regular`、`symlink` 等）、權限模式 `mode`、UID、GID、`st_dev` 與 `st_ino`。
4. 若解析後的目標為常規檔案（`regular`），進一步嘗試以 `open(path, O_RDONLY | O_CLOEXEC)` 開啟，先以 `fstat` 比對 `st_dev` 與 `st_ino` 確認與 `O_PATH` 所指為同一個實體物件，再透過 `pread` 讀取檔案開頭 4 個位元組，檢查是否符合 ELF 格式魔術數字（`\x7fELF`）。

## 觸發代表什麼

OBSERVED 代表在上述 6 個路徑中至少發現一個存在的檔案系統物件。依據評估邏輯，BusyBox 檔案不屬於特權提權工具本身，因此不會產出 STRONG finding，所有被偵測到的路徑皆歸類為 `weak` 強度的 `visible_artifact`，整體評估結果最高為 WEAK。

不能推論的：
- **不能推論裝置已 root。** BusyBox 是標準的實用工具集，部分第三方韌體、開發板系統或原廠工程映像檔可能內建，但不提供提權通道。
- **不能推論當前行程具備 root 權限。** 檔案存在不代表當前應用程式有權限執行它，也不代表能藉此切換為特權身分。
- **不能推論特定 root 方案。** 本檢測不包含特定框架的特徵指紋。

## 已知偽陽性來源

- **良性自訂韌體或工程用 ROM。** 部分客製化韌體或測試韌體為方便維護，會在 `/system/xbin/busybox` 預載 BusyBox，但並未開放 root 授權，此時會觸發 WEAK 判定——前提是該裝置的 `/system/xbin` 可被一般 App 搜尋，見「看不到什麼」。
- **非 root 的開發測試工具殘留。** 開發者手動透過 adb push 放置於 `/data/local/`、`/data/local/bin/` 或 `/data/local/xbin/` 的公用程式（`busybox.cpp` 候選清單中的三個 `/data/local` 路徑），若檔名命名為 busybox 即會被標記。
- **空檔案或非執行檔佔位。** 判斷路徑可見性時（`binary_artifact_probe.cpp` 的 `isVisibleArtifact()`），只要 `access`、`lstat`、`openPath` 或 `fstat` 任一呼叫回報 `present` 即視為存在；即使該檔案是大小為 0 的空檔案或無法執行的文字檔，亦會被列入 finding。

## 看不到什麼

- **非標準路徑下的 BusyBox。** 例如放置於 `/data/adb/`、Termux 私有目錄，或是安裝於自訂目錄且未置於上述 6 個寫死路徑中的 BusyBox（本檢測不讀取 `$PATH` 環境變數）。
- **`/system/xbin` 在部分裝置上對 App 不可搜尋。** 實測（2026-09-11，`ablation_2026`）：Redmi 13C（Android 13）上 `/system/xbin/busybox` 在**所有**格子都回傳 `EACCES`，包括完全沒有啟用隱藏的 `R0`——這是權限邊界，不是隱藏。該候選因此無法作答，報告以 `unavailableCandidateCount=1`、`deniedOperationCount=3` 如實呈現；6 個候選中實際作答的是 5 個。Pixel 7（Android 17）上 6 個全部可作答。
- **Mount namespace 遮蔽。** Magisk DenyList、Shamiko 或 KernelSU 若在應用的掛載命名空間中卸載或遮蔽候選所在目錄，候選會呈現為不存在，本檢測無法與真正的不存在區分。此項為推論：本機隊沒有觀察到 BusyBox 被遮蔽的案例。
- **Syscall Hook。** 若執行環境透過 libc hook 或 seccomp 阻擋並將相關路徑的 `access`、`lstat` 或 `open` 偽造回傳 `ENOENT`，本檢測會直接判定為未觀察到。

## 建議處置

| 強度 | 建議 |
|---|---|
| WEAK | 僅代表系統中存在 BusyBox 檔案，不具備直接提權意涵。建議與 `su-binary` 或 `mount-integrity` 等其他領域結果交叉比對，不可單獨作為阻斷或處置使用者的依據。 |
| NOT_OBSERVED | 在 6 個固定路徑中未觀察到 BusyBox，不代表設備乾淨或未被 root。判讀時以 `availableCandidateCount`（真正作答的候選數）為準。 |
| INCONCLUSIVE | 6 個候選路徑在存取時皆遭遇非 `ENOENT` 的異常（如權限徹底拒絕且無從取得中繼資料），應視為收集失敗。 |

## 成本

- 僅探測 6 個編譯期常數路徑。
- 每個路徑最多進行 1 次 `access`、1 次 `lstat`、最多 2 次 `open`（`O_PATH` 與唯讀）與最多 2 次 `fstat`，常規檔案最多讀取 4 位元組標頭。
- 不 fork 任何行程，不執行任何外部程式，全在行程內完成。
- 整合者不需要在 `AndroidManifest.xml` 中配置任何權限或設定。

## Evidence units

### busybox.visible-artifact

記錄在 6 個候選路徑中探測到的檔案物件屬性（POSIX mode、UID、GID、inode、device、檔案類型）與 ELF magic 判定。若路徑存在，finding id 為 `visible_artifact`、強度為 `weak`、分類為 `busybox_artifact`，作為環境二進位產物的輔助證據。
