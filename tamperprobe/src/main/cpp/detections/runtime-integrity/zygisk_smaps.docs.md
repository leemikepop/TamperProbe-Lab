# Zygisk Dirty Pages Scan

解析 `/proc/self/smaps` 虛擬檔案，找出系統函式庫的可執行程式碼被切成「單頁、且帶有髒頁」的區段 —— 這是就地修補程式碼（inline hook）留下的形狀；同時記錄逐區段髒頁量與 `mallinfo2` 的 Heap 碎裂比例作為情境遙測。由於系統唯讀程式碼區段在正常情況下不應被寫入，被寫過而且被單獨改過保護的頁面，就是執行期代碼被就地修補的具體物理痕跡。

## 這個檢測在看什麼

檢測器由兩個核心觀測維度組成：

1. **系統函式庫可執行區段髒頁掃描（`execute` 的 smaps 解析迴圈）**：
   循序讀取 `/proc/self/smaps`，鎖定滿足以下條件的記憶體映射：
   - 權限字串包含執行權限 `x`（`currentExec`）
   - 路徑以前綴 `/system/`、`/vendor/`、`/apex/` 或 `/product/` 開頭（`currentSystem`）
   逐函式庫加總各區段的 `Private_Dirty` 與 `Shared_Dirty`（`systemLibraryDirt`），並計算**長度恰為一頁、且帶有髒頁**的區段數 `singlePageDirtyRegionCount`。這個數字是本檢測唯一影響評估的通道。
   另外保留舊的逐區段判斷：單一區段髒頁 ≥ **8 kB** 時記錄於 `dirtyMappings` 並累加 `hitCount`，僅作遙測（`dirtyMappingImpact: "telemetry_only"`）。
2. **Heap 記憶體碎裂比例遙測（`checkHeapEntropy`）**：
   透過 `dlsym` 呼叫 `mallinfo2()`（Android API >= 30），取得已分配空間（`uordblks`）與保留之閒置空間（`fordblks`），計算閒置比例 `freeRatio`。若符合特定門檻（閒置空間 `>= 256 KB` 且比例 `>= 20%`，或閒置空間 `>= 512 KB` 且比例 `>= 35%`），標記 `heapEntropyAnomaly`。程式碼特別註明此門檻為未校準常數，僅作為研究情境遙測，**完全不影響評估結果**（見 `execute` 末段註解）。

**評估只取決於單頁髒區段（2026-09-18 起，語意變更）：**
- `singlePageDirtyRegionCount >= 1`：OBSERVED / MODERATE（`singlePageDirtyImpact: "moderate"`）
- `singlePageDirtyRegionCount == 0`：NOT_OBSERVED
- `/proc/self/smaps` 無法開啟或讀到一半失敗：INCONCLUSIVE

2026-09-12 至 09-18 之間本檢測只會回報 NOT_OBSERVED 或 INCONCLUSIVE，因為兩個通道都是遙測；更早的
`hitCount >= 3` 為 STRONG、`1–2` 為 WEAK 的規則因下方「已知偽陽性來源」第一項而停用，至今仍停用。

## 觸發代表什麼

- **MODERATE（至少一個單頁髒區段）**：某個系統函式庫的程式碼頁被寫過，而且那一頁的保護被單獨改過。這是 inline hook 的形狀：改寫程式碼必須先把該頁設為可寫，對映射的一部分改保護會把映射切開，所以每個被改的頁面都成為獨立的單頁區段。

為什麼良性來源不會產生這個形狀：
- **文字重定位（text relocation）** 是 linker 對整個程式碼段改保護後填值，區段不會被切成單頁；而且 64 位元 Android 不允許文字重定位。
- **PLT/GOT hook**（Magisk 內建 Zygisk 的 LSPlt 即屬此類）寫的是 GOT 資料，不是可執行頁。
- **以 `process_vm_readv` 讀自身程式碼**在 Linux 4.19 上會弄髒頁面，但不改保護、不切區段；TamperProbe 自己的讀取已改用 `SelfMemoryReader`。

實測（2026-09-18 彙整）：帶有此遙測的每一份擷取中，沒有 hook 時皆為 0 —— 三支沒有可見 root 的手機（乾淨的 Xiaomi 12 與 Xiaomi 13T Pro，以及已解鎖的 Pixel 7）、SUSFS 階梯 `K0`–`K4`、兩個陽性對照研究中沒有 hook 的格子（`M0`、`Z1`、`Z2`）；有 hook 時為 8（Pixel，`M1`、`M2`）或 9（Redmi，`Z0`、`Z3`），兩支手機、兩種 Zygisk 實作皆然，重複掃描之間完全一致。`Z3` 尤其關鍵：在 Magisk 內建 Zygisk 下，注入的函式庫不在 maps 中留下名稱，依名稱辨識 LSPosed 的三個檢測器（含 `LSPOSED_MAPS`）都看不到 hook。另有 `ZYGISK_NAMESPACE` 在該格回報兩個以 `/memfd:jit-cache (deleted)` 為後端的 linker 物件，只出現在 Zygisk 模組被載入本 App 的那一格（`Z2` 沒有），取決於載入器留下什麼；本檢測看的是程式碼被修補這件事本身，不取決於注入工具怎麼命名或隱藏它載入的函式庫。

不能推論的：
- **不能推論是誰改的。** 單頁髒區段只說明程式碼被就地修補，無法區分注入框架（LSPosed/LSPlant、Frida、Dobby）與宿主 App 自己整合的 inline-hook SDK。這是評為 MODERATE 而非 STRONG 的原因。
- **不能推論裝置層級的 root 狀態。** 行程內的程式碼段修改亦可能由免 root 的注入機制觸發。

## 已知偽陽性來源

- **本檔第 33 行原本預測的偽陽性已經被實際觀測到，而且比預測更糟。** 2026-09-12 修復 smaps
  區段標頭解析後（原本的判斷式要求標頭行不含冒號，但每一行 smaps 標頭都有 `fd:07` 這樣的裝置
  欄位，因此 `hitCount` 自本檢測寫成以來**結構上恆為 0**，十四格消融實驗全部印證），在一台**普通的
  Redmi 13C** 上立刻得到 `hitCount = 3`:`libart.so`（8416 kB private dirty）、bionic `libc.so`
  （768 kB）與 `libinput.so`（228 kB）。**後續實驗證明這些髒頁是 TamperProbe 自己造成的。**
  2026-09-14 以 `DetectorSetProbeTest` 單獨執行各檢測器、並從行程外以 root 讀取 smaps:對照組
  檢測器前後皆為 0 kB;**只執行 `ELF_TEXT_INTEGRITY`**，三個函式庫由 0 變成**恰好** 8416 / 768 /
  228 kB —— 正是它拿來與磁碟檔案比對的三個目標;只執行 `PROLOGUE_SCANNER` 則使 `libc.so` 多出
  28 kB。兩者都以 `process_vm_readv` 讀取自身程式碼，而在該裝置的核心上，這樣讀過的頁面會變成
  Private_Dirty。同一台手機上**真正被注入**的行程 —— 載入了 Zygisk 的 `zygote64`、被 Play Integrity
  Fix 注入的 `com.google.android.gms.unstable` —— 反而是 0 kB。在 Pixel 7 上重做同一實驗，三組皆為
  0 kB，因此這是核心相依的現象:Redmi 的 Linux 4.19 會發生，Pixel 的 6.1 不會。
  也就是說：檢測器在同一行程中依序執行，本通道看到的是**排在它前面的完整性檢查留下的足跡**。
  若照修好的 parser 出貨，全目錄掃描會因 `ELF_TEXT_INTEGRITY` 報 STRONG，也會因
  `PROLOGUE_SCANNER`（28 kB > 8 kB）報 WEAK。因此髒頁通道維持遙測，待檢測器間的干擾
  排除、且建立乾淨裝置基線後再議。
  **干擾已於同日排除:** 三個自讀記憶體的檢測器改用 `SelfMemoryReader`（寫入 pipe 再讀回，不經 GUP），
  同一台 Redmi 的全目錄掃描 `hitCount` 由 3 變為 0，而那些檢測器仍完成了全部比對。通道仍維持遙測，
  理由剩下兩個:尚無 inline-hook 框架的正對照，以及 8 kB 門檻沒有乾淨裝置基線。
- **Zygisk 本身不會觸發這個通道。** Magisk 內建 Zygisk 以 PLT hook（LSPlt）攔截，改寫的是可寫的
  GOT 資料而非程式碼頁;上述實測中載入 Zygisk 的 `zygote64` 可執行頁髒頁為 0。本通道針對的是
  **inline hook**（改寫函式開頭機器碼，例如 LSPosed/LSPlant、Dobby、Frida、ShadowHook），這取決於
  模組採用的 hook 技術，而不是 Zygisk 的新舊版本。本研究尚無 inline-hook 框架的正對照。
- **OEM 專有 Vendor 驅動庫中的文字重定位（Text Relocations）。** 許多 OEM 裝置（尤其是搭載聯發科或高通晶片的機型）在 `/vendor/` 或 `/system/` 下的專有相機、圖形或感測器函式庫中，存在編譯期遺留的重定位需求。在動態連結時，linker 必須將這些程式碼頁面標記為可寫並填入重定位位址，留下合法產生的髒頁。檢測器採用的 **8 kB** 門檻（`finalizeRegion`）為編譯期常數且未在多樣化乾淨裝置上完成校準；若某台良性 OEM 裝置載入了 3 個包含重定位的 vendor 函式庫，`hitCount >= 3` 便會直接在乾淨手機上誤判為 STRONG —— **這件事後來真的發生了，見上方第一項。**
- **合法 Crash/APM 監控 SDK 的 Inline Hook。** 整合於 App 內的效能監控或崩潰防護套件（例如部分 native crash 收集或 I/O 監控 SDK），若對 `/apex/.../libc.so` 中的函式安裝 inline hook，會留下與注入框架**相同**的單頁髒區段，本檢測會回報 MODERATE。這不是解析錯誤：該行程的程式碼確實被改了。整合者若自己使用這類 SDK，應在政策層把本檢測的權重調低或排除，而不是期待本檢測分辨。**本研究的機隊沒有測過任何這類 SDK。**
- **Heap 碎裂規則的常態觸發。** 雖然 Heap 異常目前不影響 outcome，但普通應用程式在處理大型點陣圖（Bitmap）或大量網路資料後，`mallinfo2` 的保留閒置空間極易超過 256 KB 且比例超過 20%，屬於正常分配器行為。

- **逐區段門檻看不到它要抓的技術（2026-09-14 以正對照實測）。** 在 Redmi 13C 上以只 hook
  Sample App 的 Xposed 對照模組（`test-fixtures/xposed-control`，實驗 `lsposed_control_2026` 的
  L2／L3 格）製造真實的 inline hook:LSPlant 改寫了 `libart.so` 程式碼中的 9 個頁面。改寫程式碼
  必須先變更頁面保護，而對映射的一部分變更保護會把映射切開，所以**每個被改的頁面都變成獨立的
  單頁區段，髒頁恰好 4 kB**。舊的判斷是「單一區段 `Private_Dirty + Shared_Dirty` ≥ 8 kB」，不論改了
  幾頁都不會觸發 —— `hitCount` 維持 0，而 `ELF_TEXT_INTEGRITY` 同時比對出 libart 的位元組已被修改。
  Duck-Detector 的 `smaps_probe.cpp` 使用相同的逐區段 8 kB 門檻，有同樣的盲點。
  現在另外發布**逐函式庫加總**的遙測:`systemLibraryDirt`（每個有髒頁的系統函式庫之可執行區段數、
  髒區段數、單頁髒區段數、髒頁總量、最大髒區段）與總數 `singlePageDirtyRegionCount`。同一台
  hook 仍在的 Redmi 上回報 `libart.so` 19 個可執行區段、9 個單頁髒區段、共 36 kB;沒有 hook 的
  L1 格與 Pixel 7 皆為 0。「系統函式庫程式碼段被切成一格一格的單頁髒區段」這個形狀，是 hook 的特徵。
  2026-09-18 起此形狀成為評估依據（見上方「這個檢測在看什麼」），那時已有兩台裝置、兩種 Zygisk 實作的正對照與三支手機的乾淨基線。框架仍只有 LSPosed/LSPlant 一種。
  改版後的實機結果（`followup_2026` E4，commit `403d5e1`）：Redmi 13C 在 Magisk 內建 Zygisk 下載入 hook，debug 與 release 共 140 次掃描全部回報 MODERATE；同時段沒有 hook 的 Pixel 7 共 140 次全部 NOT_OBSERVED。

## 看不到什麼

- **非系統目錄下的注入函式庫。** 檢測僅檢查路徑開頭為 `/system/`、`/vendor/`、`/apex/`、`/product/` 的映射。若 Zygisk 或 Frida 模組將惡意程式碼放置於 `/data/` 目錄或匿名記憶體中執行，其髒頁完全不被計入。
- **不改頁面保護的寫入。** 以 `ptrace`（除錯器軟體斷點）或 `/proc/self/mem` 寫入程式碼，核心會強制做寫入時複製而不改 VMA 保護，區段不會被切開；髒頁只會出現在大區段中，屬於遙測的 `hitCount`，不影響評估。
- **修補後合併回原區段。** 若 hook 工具在改寫後把保護還原並讓核心合併相鄰 VMA，單頁區段會消失（實測 LSPlant 改寫的 9 個頁面在保護還原後仍各自是獨立區段，但其他工具未測）。
- **PLT/GOT Hook。** PLT/GOT 攔截僅修改非可執行（`r--` 或 `rw-`）的資料段，因為 `currentExec` 為 false 而完全不被檢查。
- **核心層抹除髒頁標記。** 具備進階特權的核心模組若透過 EPT/影子頁面或直接清除頁表 Dirty 位元，`/proc/self/smaps` 的計數將為 0。

## 建議處置

| 強度 | 建議 |
|---|---|
| MODERATE | 系統函式庫的程式碼被就地修補。檢視 `systemLibraryDirt` 找出是哪個函式庫；`libart.so` 被切成多個單頁區段是 Xposed 類框架（LSPlant）的典型形狀。先確認宿主 App 沒有整合 inline-hook SDK，再與 `runtime-integrity` 其他檢測器交叉比對；不建議單獨作為封鎖依據。 |
| NOT_OBSERVED | 系統函式庫的可執行區段沒有單頁髒區段。不排除 PLT/GOT hook、非系統路徑下的注入，或不改頁面保護的寫入。 |
| INCONCLUSIVE | `/proc/self/smaps` 無法開啟或讀取，應視為收集失敗。 |

## 成本

- 循序開啟並讀取 `/proc/self/smaps` 全文（在 Android 應用程式中該檔案可能達數 MB，逐行解析需消耗一定的 CPU 時間與 I/O）。
- 呼叫一次 `mallinfo2`（若系統支援）。
- 不 fork 任何子行程。無須任何 AndroidManifest 設定。

## Evidence units

### zygisk-smaps.dirty-executable-page

承載逐函式庫的髒頁統計（`systemLibraryDirt`：可執行區段數、髒區段數、單頁髒區段數、髒頁總量、最大髒區段）、總數 `singlePageDirtyRegionCount`、遙測用的逐區段命中（`dirtyMappings`、`hitCount`）與 `mallinfo2` 的 Heap 遙測。`singlePageDirtyRegionCount >= 1` 時產出 MODERATE 訊號。
