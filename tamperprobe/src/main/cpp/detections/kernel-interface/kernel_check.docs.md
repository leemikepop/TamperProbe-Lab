# Kernel Integrity Check

透過 `uname()`、`/proc/version`、`/proc/cmdline` 與 `/proc/kallsyms` 檢查當前執行中 Linux 核心的編譯特徵與啟動完整性。非官方或第三方定製核心常會在版本字串留下記錄（如社群作者標記、CJK 字符、Emoji、Telegram 連結）、在開機命令列暴露 Bootloader 解鎖狀態（`verifiedbootstate=orange` / `yellow`），或因除錯需求而關閉 `kptr_restrict` 導致核心符號位址外洩。本檢測整合這些低階特徵，評估核心是否偏離出廠標準。

## 這個檢測在看什麼

本檢測從四個核心與開機資料來源收集證據：

- **核心版本與編譯字串**：讀取 `uname()`（`uts.release`、`uts.version`）與 `/proc/version`（前 4096 位元組），拼接後掃描五類特徵：
  1. CJK 統一表意文字與擴展區（0x4E00-0x9FFF、0x3400-0x4DBF、0xF900-0xFAFF、0x20000-0x2FA1F）
  2. Emoji 表情符號（0x2600-0x27BF、0x1F300-0x1FAFF、0x1F1E0-0x1F1FF）
  3. Telegram 宣傳連結（`t.me/`、`telegram.me/`、`tg://`、`" tg "`、`" tg-"`、`"@tg"`、`" telegram "`）
  4. 開發者 `@` 提及（如 `@username`，字長 >= 3）
  5. 27 個社群定製核心與 Root 關鍵字：`arter97`, `franco`, `elementalx`, `blu_spark`, `sultan`, `caf-`, `SilkSmoothKernel`, `NetHunter`, `dirty`, `custom`, `perf+`, `overclock`, `xiaoxiaow`, `qdykernel`, `shirkneko`, `aptkernel`, `sukisu`, `KernelSU`, `APatch`, `numbers`, `cctv`, `mirinfork`, `brokestar`, `Glow-v`, `coolzyd9107`, `aptusitu`，以及大小寫相符的 `OKI`。
- **開機參數（`/proc/cmdline`）**：讀取前 4096 位元組，檢查 Bootloader 解鎖與驗證啟動參數：
  - `androidboot.verifiedbootstate=orange`（已解鎖）
  - `androidboot.verifiedbootstate=yellow`（使用自簽開機映像檔）
  - `androidboot.flash.locked=0`（刷機鎖定已關閉）
  - `androidboot.vbmeta.device_state=unlocked`（vbmeta 狀態為解鎖）
  - 命令列中含有 `magisk`、`ksu` 或 `apatch` 的字串特徵。
- **核心符號位址隱藏（`kptr_restrict`）**：解析 `/proc/kallsyms` 前 20 行，計算位址非零的比例；若非零行數超過掃描行數的一半（`> 50%`），視為指標保護失效。
- **root 框架符號名比對**：對 `/proc/kallsyms`（前 128 KiB）、`/proc/modules`（前 32 KiB）與核心識別字串掃描 root 框架符號 token（`ksu_`、`kernelsu`、`apatch`、`kpatch`、`supercall`、`magisk`，token 清單抄自 Duck-Detector 的 `kernel_probe.cpp`）。**這是舊機技術**：kallsyms 與 modules 只在較舊的 Android 對 app 可讀，在機隊的 API 33 與 API 37 上皆為 EACCES，因此本掃描在現行機隊上無正對照，僅為較舊的 root 堆疊保留。

## 觸發代表什麼

- `hitCount >= 2`：判定為 STRONG。代表同時觀察到多個指標（例如既有解鎖開機參數，核心字串又匹配社群作者特徵，或符號位址完全洩漏）。
- `hitCount > 0`：判定為 MODERATE。代表單一指標命中（例如單純的開機解鎖參數或單一編譯標籤）。

不能推論的：
- **不能推論應用程式已取得 Root 權限。** 開發者可能僅解鎖 Bootloader 或刷入第三方省電/效能核心，但未安裝 Root 授權管理器。
- **不能推論是特定的惡意軟體。** 核心特徵可能來自開源定製韌體或玩家 ROM。

## 已知偽陽性來源

- **一般開源編譯產生的合法字串**（`scanCustomKeywords`）：關鍵字列表包含通用的 Linux 核心構建標籤，如代表未乾淨 commit 的 `dirty`、一般編譯設定 `custom`、Qualcomm 晶片官方開源基準分支 `caf-`，以及常見子字串 `numbers`，官方 OEM 或第三方良性韌體若包含此類標籤會觸發命中。
- **亞洲 OEM 產線機器名稱**（`scanCjkGlyphs`）：若 OEM 官方在編譯核心時，構建伺服器主機名稱、使用者帳號或內部版本備註中含有中日韓字元（CJK），會被 `scanCjkGlyphs` 判定為自訂標記。
- **核心維護者電子郵件格式**（`scanAtMentions`）：`scanAtMentions` 會比對長度 3 以上的 `@` 識別字；若官方 build 字串包含維護者 email 帳號，可能被誤判。
- **良性解鎖或開發者裝置**（cmdline bootloader-state 分支）：使用者合法解鎖 Bootloader 或刷入由使用者自簽的系統（`verifiedbootstate=yellow` / `orange`），在沒有任何 Root 的情況下亦會產生 finding。
- **OEM 預設未開啟指標限制**（kptr 分支）：部分非標準或低階晶片廠的工程建置中，`/proc/kallsyms` 未啟用嚴格的 `kptr_restrict=2`，導致位址直接暴露。

## 看不到什麼

- **偽裝為原廠官方字串的定製核心**：KernelSU 或第三方核心編譯者若刻意將 `/proc/version` 與 `utsname` 抹除為原廠 release 字串，不包含任何特殊關鍵字或 CJK/Emoji/Telegram 標籤，字串比對即完全沉默。
- **核心層或掛載層遮蔽**：KernelSU / susfs 或 eBPF 攔截若在掛載命名空間中掛載偽造的 `/proc/version`、`/proc/cmdline`，或攔截 `uname` 系統呼叫，本檢測無法穿透核心層的主動欺瞞。
- **權限鎖定讓四個子檢查中的三個在現行 Android 上無法執行——不是乾淨，是看不到。** 標準 `untrusted_app` 原則下，`/proc/kallsyms`、`/proc/modules` 與 `/proc/cmdline` 都直接回傳 EACCES。實測（`ablation_2026` 十四格，兩台裝置)：這三者每一格都讀不到，只有 `uname()`（供核心橫幅字串掃描）與 `/proc/self/attr` 可用。因此 kptr 檢查、符號名比對、以及 cmdline bootloader-state 檢查在現行機隊上**結構上無法作答**；只有 uname 橫幅掃描真的執行了，並回報乾淨。
  自 2026-09-12 起，每一個讀不到的來源（kallsyms、modules、cmdline）都會記成 collection issue，使該 unit 標為 **PARTIAL**。整體 outcome 維持 NOT_OBSERVED——因為那個唯一活著的子檢查確實作答了——但 PARTIAL 讓「四個檢查只有一個跑得動」這件事在報告裡看得見，而不是被當成乾淨。

## 建議處置

| 強度 | 建議 |
|---|---|
| STRONG | 觀察到多項核心或 Bootloader 異常（例如解鎖狀態疊加社群核心特徵），代表底層系統安全邊界已遭更動。建議結合執行時期行為（如 `runtime-integrity`）綜合評估，提高風控分數。 |
| MODERATE | 單項特徵命中（例如僅解鎖 Bootloader，或僅單一關鍵字匹配），可能是合法玩家機或 OEM 構建標籤特徵，不建議單獨作為阻斷服務之依據。 |
| NOT_OBSERVED | 在可見的渠道中未發現異常標記，但若底層核心具備隱藏機制或 procfs 受 SELinux 限制，不保證核心絕對純淨。 |
| INCONCLUSIVE | `/proc/kallsyms`、`/proc/version`、`/proc/cmdline` 皆無法讀取且 `uname()` 失敗，視為底層資料無法採集。 |
| NOT_OBSERVED（PARTIAL） | uname 橫幅掃描作答為乾淨，但 kallsyms／modules／cmdline 至少一項讀不到。這是現行 Android 上的常態，unit 會標為 PARTIAL 並附 collection issue，判讀時須注意大部分子檢查其實沒有執行。 |

## 成本

- 執行 1 次 `uname()` 系統呼叫。
- 嘗試讀取 4 個 procfs 節點：`/proc/version`（最多 4096 位元組）、`/proc/cmdline`（最多 4096 位元組）、`/proc/kallsyms`（kptr 檢查讀前 20 行，符號比對再讀前 128 KiB）與 `/proc/modules`（符號比對讀前 32 KiB）。在現行 Android 上 kallsyms／modules／cmdline 皆 EACCES，會立即失敗。
- 全程於當前行程內部完成字串解析，不 fork 子行程，不建立新執行緒。
- 整合者不需要在 `AndroidManifest.xml` 中配置任何權限或設定。

## Evidence units

### kernel-check.integrity-posture

記錄核心版本、`uname` 輸出、`/proc/version`、`/proc/cmdline` 啟動參數、`/proc/kallsyms` 符號指標暴露狀態，以及 kallsyms／modules／banner 的 root 符號名比對（`kernelSymbolMatches`、`modulesReadable`）。若有命中，finding 的 check 類型包含 `custom_kernel_signature`、`bootloader_state`、`flash_locked`、`vbmeta_device_state`、`cmdline_root_marker`、`kptr_restrict_disabled` 或 `kernel_symbol_token`。讀不到的來源記為 collection issue。
