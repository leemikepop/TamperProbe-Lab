# Kernel Integrity Check

透過 `uname()`、`/proc/version`、`/proc/cmdline` 與 `/proc/kallsyms` 檢查當前執行中 Linux 核心的編譯特徵與啟動完整性。非官方或第三方定製核心常會在版本字串留下記錄（如社群作者標記、CJK 字符、Emoji、Telegram 連結）、在開機命令列暴露 Bootloader 解鎖狀態（`verifiedbootstate=orange` / `yellow`），或因除錯需求而關閉 `kptr_restrict` 導致核心符號位址外洩。本檢測整合這些低階特徵，評估核心是否偏離出廠標準；另外把行程從 Zygote 繼承的核心 release（`os.version`）與即時的 `uname()` 及 procfs 匯出值交叉比對，抓出只改寫其中一處的核心版本偽裝。

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
- **核心身分一致性（`kernel-check.identity-coherence`）**：比對同一個核心 release 字串的四個來源：
  1. **Zygote 快照**：`System.getProperty("os.version")`，於原生端以掃描時的 `JNIEnv` 經 JNI 取得。libcore 在 Zygote 初始化時以 `uname().release` 填入這個系統屬性，之後每個從 Zygote fork 出來的 App 行程都繼承同一個值，所以它記錄的是「App 啟動前」的 release。
  2. **即時 syscall**：本次掃描 `uname()` 的 `release`。
  3. **`/proc/sys/kernel/osrelease`**（盡力讀取，最多 256 位元組）。
  4. **`/proc/version` 解析出的 release**：只接受 `Linux version <release> ...` 開頭，其他格式視為讀不到，避免截斷或改版的橫幅自己製造不一致。

  每個值只去除前後空白後逐字比較。核心在執行中不會換 release，所有來源都由同一份 utsname 複製而來，未修改的裝置上必然一致。比對邏輯是純函式 `kernel_identity::compareReleases`（`kernel_identity_coherence.{h,cpp}`），由原生 fixture 直接驅動。概念改編自 Duck-Detector（eltavine/Duck-Detector-Refactoring）的 `KernelIdentityConsistencyUtils.kt`（Apache-2.0），程式碼為本專案自行撰寫，未複製其原始碼。
- **root 框架符號名比對**：對 `/proc/kallsyms`（前 128 KiB）、`/proc/modules`（前 32 KiB）與核心識別字串掃描 root 框架符號 token（`ksu_`、`kernelsu`、`apatch`、`kpatch`、`supercall`、`magisk`，token 清單抄自 Duck-Detector 的 `kernel_probe.cpp`）。**這是舊機技術**：kallsyms 與 modules 只在較舊的 Android 對 app 可讀，在機隊的 API 33 與 API 37 上皆為 EACCES，因此本掃描在現行機隊上無正對照，僅為較舊的 root 堆疊保留。

## 觸發代表什麼

- `hitCount >= 2`：判定為 STRONG。代表同時觀察到多個指標（例如既有解鎖開機參數，核心字串又匹配社群作者特徵，或符號位址完全洩漏）。
- `hitCount > 0`：判定為 MODERATE。代表單一指標命中（例如單純的開機解鎖參數或單一編譯標籤）。
- **核心身分不一致**（任兩個可讀來源的 release 不同，finding `check=kernel_identity_mismatch`）：判定為 MODERATE，且讓整個 KERNEL_CHECK 成為 OBSERVED。它不計入 `hitCount`；與 posture 命中並存時取兩者較強者（一個 posture 命中加上不一致仍是 MODERATE，兩個以上 posture 命中為 STRONG）。強度與 `BUILD_PATCH_COHERENCE`、`DRM_CREDENTIAL_COHERENCE` 一致地定為 MODERATE 而非 STRONG：矛盾本身在邏輯上成立（release 不會在核心執行中改變），但 Zygote 快照是 Java 層的值，行程內對 `System.getProperty` 的 hook 也能改寫它，而且 Lab 版尚未在乾淨裝置上量測過對照；取得乾淨對照前不提高等級。
  實例：Pixel 7、blu_spark 自編核心（`6.1.162+blu-spark`）加 susfs4ksu 模組，在 Zygote 啟動**之後**才以 SUSFS 偽裝 `newuname`。App 的 `os.version` 仍是 `6.1.162+blu-spark`，即時 `uname()` 卻回傳原廠字串 `6.1.162-android14-11-g2ec90535fa34-ab15810641`，兩者不一致。舊版只掃橫幅，對這支手機回報 NOT_OBSERVED。

不能推論的：
- **不能推論應用程式已取得 Root 權限。** 開發者可能僅解鎖 Bootloader 或刷入第三方省電/效能核心，但未安裝 Root 授權管理器。
- **不能推論是特定的惡意軟體。** 核心特徵可能來自開源定製韌體或玩家 ROM。
- **不能推論哪一個來源是假的、由哪個工具造成。** 身分不一致只證明至少一個來源被改寫。

## 已知偽陽性來源

- **一般開源編譯產生的合法字串**（`scanCustomKeywords`）：關鍵字列表包含通用的 Linux 核心構建標籤，如代表未乾淨 commit 的 `dirty`、一般編譯設定 `custom`、Qualcomm 晶片官方開源基準分支 `caf-`，以及常見子字串 `numbers`，官方 OEM 或第三方良性韌體若包含此類標籤會觸發命中。
- **亞洲 OEM 產線機器名稱**（`scanCjkGlyphs`）：若 OEM 官方在編譯核心時，構建伺服器主機名稱、使用者帳號或內部版本備註中含有中日韓字元（CJK），會被 `scanCjkGlyphs` 判定為自訂標記。
- **核心維護者電子郵件格式**（`scanAtMentions`）：`scanAtMentions` 會比對長度 3 以上的 `@` 識別字；若官方 build 字串包含維護者 email 帳號，可能被誤判。
- **良性解鎖或開發者裝置**（cmdline bootloader-state 分支）：使用者合法解鎖 Bootloader 或刷入由使用者自簽的系統（`verifiedbootstate=yellow` / `orange`），在沒有任何 Root 的情況下亦會產生 finding。
- **行程內改寫 `os.version`**（身分一致性分支）：Android 的 libcore 會忽略對 `os.version` 這類不可變屬性的 `System.setProperty`（AOSP `libcore/ojluni/src/main/java/java/lang/System.java` 的 `PropertiesWithNonOverrideableDefaults`），但 Xposed 類模組 hook `System.getProperty`、或以反射改寫屬性表，都能讓快照與 `uname()` 不一致。這仍代表行程被竄改，卻不是核心版本偽裝。尚未觀察到良性來源。
- **OEM 預設未開啟指標限制**（kptr 分支）：部分非標準或低階晶片廠的工程建置中，`/proc/kallsyms` 未啟用嚴格的 `kptr_restrict=2`，導致位址直接暴露。

## 看不到什麼

- **偽裝為原廠官方字串的定製核心**：KernelSU 或第三方核心編譯者若刻意將 `/proc/version` 與 `utsname` 抹除為原廠 release 字串，不包含任何特殊關鍵字或 CJK/Emoji/Telegram 標籤，字串比對即完全沉默。
- **只看得到 `uname` 的橫幅掃描是可被隱藏的否定（Rule 3）。** SUSFS 的 `spoof_uname` hook `newuname`，回傳不含任何標記的原廠字串。當 `/proc/version` 讀不到（現行 Android 的常態）時，橫幅掃描的「沒找到」與被偽裝的結果無法區分。自本版起，這種情況的否定列在 `bannerConcealableNegatives`（`custom_kernel_signature`；kallsyms 與 modules 也讀不到時再加上 `kernel_symbol_token`），NOT_OBSERVED 時各自發佈為 `KERNEL_CHECK.integrity-posture.concealable-negative` OBSERVATION record，不再當成可信的作答。與 `NATIVE_ROOT_PATHS` 的 `concealableNotFoundPaths`、SELinux policy oracle 的 `concealableNegatives` 同一套作法。
- **身分一致性取決於偽裝發生的時間點（Zygote 快照的時序限制）。** 快照在 Zygote 初始化時定格：
  - 偽裝在 Zygote 啟動**之後**才套用（例如 SUSFS 在較晚的開機階段才設定 `set_uname`）：快照保留真實 release，即時 `uname()` 回傳偽裝值 → 不一致 → OBSERVED（上面 blu_spark 的實例）。
  - 偽裝在 Zygote 初始化**之前**就套用（SUSFS 參考模組在 `post-fs-data.sh` 呼叫 `set_uname`）：快照本身就是偽裝值，與 `uname()` 一致 → 本 unit 為 NOT_OBSERVED，但這是可被隱藏的否定，列在 `identityConcealableNegatives` 並發佈為 `KERNEL_CHECK.identity-coherence.concealable-negative` record。同一支 Pixel 7 把 SUSFS 的 uname 偽裝移到 post-fs-data 之後就是這種情況。此時只有 procfs 來源還可能露出真實值，但 App 通常讀不到。
- **核心層或掛載層遮蔽**：KernelSU / susfs 或 eBPF 攔截若在掛載命名空間中掛載偽造的 `/proc/version`、`/proc/cmdline`，或攔截 `uname` 系統呼叫，本檢測無法穿透核心層的主動欺瞞。
- **權限鎖定讓四個子檢查中的三個在現行 Android 上無法執行——不是乾淨，是看不到。** 標準 `untrusted_app` 原則下，`/proc/kallsyms`、`/proc/modules` 與 `/proc/cmdline` 都直接回傳 EACCES。實測（`ablation_2026` 十四格，兩台裝置)：這三者每一格都讀不到，只有 `uname()`（供核心橫幅字串掃描）與 `/proc/self/attr` 可用。因此 kptr 檢查、符號名比對、以及 cmdline bootloader-state 檢查在現行機隊上**結構上無法作答**；只有 uname 橫幅掃描真的執行了，並回報乾淨。
  自 2026-09-12 起，每一個讀不到的來源（kallsyms、modules、cmdline）都會記成 collection issue，使該 unit 標為 **PARTIAL**。整體 outcome 維持 NOT_OBSERVED，但 PARTIAL 讓「四個檢查只有一個跑得動」這件事在報告裡看得見，而不是被當成乾淨；那個唯一跑得動的 uname 橫幅掃描，其否定如上所述是可被隱藏的。
- **procfs 身分來源通常讀不到。** 一般 App 的 SELinux 網域讀不到 `/proc/version` 與 `/proc/sys/kernel/osrelease`，讀不到時各記一筆 collection issue（`proc_version` 同時影響兩個 unit，其餘只標在身分一致性 unit），所以身分一致性 unit 在現行裝置上通常是 **PARTIAL**，實際只比對 Zygote 快照與 `uname()` 兩個來源。可讀來源少於兩個時，本 unit 為 **UNAVAILABLE**（附 `kernel_identity` issue，讀到的值放在 issue 屬性中），絕不當成否定。

## 建議處置

| 強度 | 建議 |
|---|---|
| STRONG | 觀察到多項核心或 Bootloader 異常（例如解鎖狀態疊加社群核心特徵），代表底層系統安全邊界已遭更動。建議結合執行時期行為（如 `runtime-integrity`）綜合評估，提高風控分數。 |
| MODERATE | 單項特徵命中（例如僅解鎖 Bootloader，或僅單一關鍵字匹配），可能是合法玩家機或 OEM 構建標籤特徵，不建議單獨作為阻斷服務之依據。 |
| NOT_OBSERVED | 在可見的渠道中未發現異常標記，但若底層核心具備隱藏機制或 procfs 受 SELinux 限制，不保證核心絕對純淨。 |
| INCONCLUSIVE | `/proc/kallsyms`、`/proc/version`、`/proc/cmdline` 皆無法讀取且 `uname()` 失敗，且身分來源也沒有一致的兩個，視為底層資料無法採集。 |
| NOT_OBSERVED（PARTIAL） | uname 橫幅掃描未找到標記，但 kallsyms／modules／cmdline 至少一項讀不到。這是現行 Android 上的常態，unit 會標為 PARTIAL 並附 collection issue，判讀時須注意大部分子檢查其實沒有執行。 |
| NOT_OBSERVED（含 concealable-negative） | 結論只建立在可被隱藏的否定上：橫幅只來自 `uname`，且身分來源一致。核心層 uname 偽裝（尤其在 Zygote 之前套用者）會產生完全相同的報告，不可視為乾淨核心的證據。 |
| OBSERVED（identity-coherence 訊號） | 核心 release 在不同來源間不一致，代表至少一個來源被改寫（常見為 Zygote 之後才套用的 SUSFS uname 偽裝）。MODERATE；建議與 `NATIVE_ROOT_SUSFS` 等核心層檢測一起判讀。 |

## 成本

- 執行 1 次 `uname()` 系統呼叫。
- 1 次 JNI 呼叫 `System.getProperty("os.version")`，以及 1 次 `/proc/sys/kernel/osrelease` 讀取（最多 256 位元組，通常 EACCES）。
- 嘗試讀取 4 個 procfs 節點：`/proc/version`（最多 4096 位元組）、`/proc/cmdline`（最多 4096 位元組）、`/proc/kallsyms`（kptr 檢查讀前 20 行，符號比對再讀前 128 KiB）與 `/proc/modules`（符號比對讀前 32 KiB）。在現行 Android 上 kallsyms／modules／cmdline 皆 EACCES，會立即失敗。
- 全程於當前行程內部完成字串解析，不 fork 子行程，不建立新執行緒。
- 整合者不需要在 `AndroidManifest.xml` 中配置任何權限或設定。

## Evidence units

### kernel-check.integrity-posture

記錄核心版本、`uname` 輸出、`/proc/version`、`/proc/cmdline` 啟動參數、`/proc/kallsyms` 符號指標暴露狀態，以及 kallsyms／modules／banner 的 root 符號名比對（`kernelSymbolMatches`、`modulesReadable`）。若有命中，finding 的 check 類型包含 `custom_kernel_signature`、`bootloader_state`、`flash_locked`、`vbmeta_device_state`、`cmdline_root_marker`、`kptr_restrict_disabled` 或 `kernel_symbol_token`。讀不到的來源記為 collection issue。`bannerSources` 記錄橫幅掃描實際用到的來源（`uname`、`proc_version`）；只用到 `uname` 時，未命中的否定列在 `bannerConcealableNegatives`，NOT_OBSERVED 時逐筆發佈為 `concealable-negative` OBSERVATION record。

### kernel-check.identity-coherence

記錄 `identityCoherence`：`state`（`agree`、`disagree`、`unavailable`）、`readableSourceCount`、`distinctReleaseCount`、每個來源（`zygote_os_version`、`uname_release`、`proc_sys_kernel_osrelease`、`proc_version_release`）的 `readable` 與讀到的值，以及 `unreadableSources`。不一致時有一筆 `check=kernel_identity_mismatch`、`unitId=kernel-check.identity-coherence` 的 finding，本 unit 發佈 MODERATE SIGNAL；一致時於 NOT_OBSERVED 發佈 `identityConcealableNegatives` 的 concealable-negative record；可讀來源少於兩個時 unit 為 UNAVAILABLE，只有 `kernel_identity` issue（讀到的值在 issue 屬性中）。`zygote_os_version`、`proc_sys_kernel_osrelease` 讀不到的 issue 只標在本 unit。
