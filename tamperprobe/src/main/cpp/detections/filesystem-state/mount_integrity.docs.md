# Mount Table Integrity

解析 `/proc/self/mountinfo` 掛載表，辨識 Magisk、KernelSU 與 Magic Mount 等 root 框架特徵標記，同時比對行程自身的 mount namespace 與 init（PID 1）是否異常共用。此外，本檢測進一步透過 `statx` 系統呼叫查詢 7 個關鍵路徑的核心 mount ID 是否存在於掛載表，並以 `statfs` 檢查 5 個系統路徑是否被 OverlayFS 覆蓋卻在掛載表中被隱藏，以雙重核心觀測通道揪出掛載竄改。

## 這個檢測在看什麼

檢測器從四個獨立視角分析掛載完整性：

1. **掛載表特徵標記與一般啟發式規則**：
   - 專屬框架標記（STRONG）：搜尋 Magisk（`.magisk`、`magisk/mirror`、掛載點 `/data/adb/modules`）、KernelSU（`kernelsu`、單詞邊界 `ksu`、`overlayfs_loop`）、Magic Mount / Meta-Hybrid（`magic_mount`、`.magic_mount`、`meta-hybrid`、`meta_hybird`、掛載選項包含 `workdir=/data/adb`）。
   - 通用啟發式規則（WEAK）：6 個系統分區（`/system`、`/system_root`、`/vendor`、`/product`、`/system_ext`、`/odm`）具備可寫選項 `rw`（`system_rw`）；系統路徑以 loop 裝置為來源（`system_loop_source`）；敏感路徑（`/sbin`、`/.magisk`、`/patch_hw`）掛載為 `tmpfs`（`sensitive_tmpfs`）。系統分區掛載為 overlay 時僅作為遙測記錄（`assessmentImpact: "telemetry_only"`）。
2. **Mount namespace 隔離性檢查**：
   - 讀取 `/proc/self/ns/mnt` 與 `/proc/1/ns/mnt` 的符號連結。正常情況下 Android 應用程式由 Zygote fork 時會建立獨立的 mount namespace；若兩者連結目標完全相同（`sharesInitNamespace`），代表當前行程直接與 init 共用根命名空間（STRONG）。
3. **Mount ID 序列缺口（僅遙測）**：
   - 記錄 `/apex/com.android.art` 與 `/data_mirror` 兩個錨點之間的 mount ID 序列（`mountIdSequence`：可見 ID 數、遺失 ID 總數 `missingCount`、最大連續缺口 `maximumGap`、缺口區間）。**自 2026-09-18 起不再產生 finding、不影響評估**（`mountIdSequence.assessmentImpact: "telemetry_only"`），原因見「已知偽陽性來源」。在那之前，`missingCount > 10` 或 `maximumGap > 5` 評為 WEAK，`missingCount > 20` 或 `maximumGap > 10` 評為 MODERATE（finding `mount_id_gap`）。
4. **核心與掛載表視角一致性交叉比對**：
   - `statx` 檢測：對 7 個關鍵路徑（`/data/data`、`/system`、`/system/bin`、`/vendor`、`/vendor/bin`、`/product`、`/apex`）呼叫 `statx` 取得 `stx_mnt_id`，若核心回傳的 mount ID 不在 `mountinfo` 的已知 ID 集合中，判定為掛載被隱藏（`statx_mount_id_missing`，STRONG）。
   - `statfs` 檢測：對 5 個系統路徑（`/system`、`/system/bin`、`/vendor`、`/product`、`/system_ext`）呼叫 `statfs` 檢查檔案系統類型代碼是否為 OverlayFS（`0x794c7630`）。若為 OverlayFS 但掛載表中未宣告任何 overlay，判定為隱藏掛載（`hidden_overlayfs`，STRONG）。

## 觸發代表什麼

依結果強度分級：

| 強度 | 觸發條件 | 代表意義 |
|---|---|---|
| STRONG | 命中 Magisk/KernelSU/Magic Mount 專屬標記、行程共用 init mount namespace，或 `statx`/`statfs` 與掛載表產生矛盾 | 高可信度的掛載竄改或命名空間隔離失效（`magisk_mount`、`shared_init_namespace`、`statx_mount_id_missing`、`hidden_overlayfs`）。 |
| WEAK | 系統分區出現可寫掛載（`system_rw`）、loop 來源，或敏感路徑掛載為 tmpfs | 環境設定偏離標準或存在輕微異常。 |

本檢測目前沒有任何規則評為 MODERATE；`moderateFindingCount` 為保持 payload 穩定而保留，恆為 0。

不能推論的：
- **不能推論特定單一套件名稱。** 檢測結果著重於檔案系統掛載結構與核心命名空間狀態，而非特定應用程式的身分。

## 已知偽陽性來源

- **非標準容器或自動化測試環境共用 init 命名空間。** 若應用程式在 CI/CD 測試容器、部分模擬器或未經 Zygote 隔離的除錯環境中運行，`/proc/self/ns/mnt` 與 `/proc/1/ns/mnt` 可能合法相同（`sharesInitNamespace` 判定），觸發 `shared_init_namespace`（STRONG）。
- **Mount ID 序列缺口規則在乾淨手機上觸發，因此已改為遙測（2026-09-18，語意變更）。** 這條規則原本預測的偽陽性真的發生了：
  - 一支乾淨、bootloader 鎖定、從未 root 的 **Xiaomi 12**（Android 15）三次掃描都回報 `missingCount = 160`，評為 MODERATE，使論文評估中產品版預設選集的參考分數達到 3（門檻 4）。缺口是真的，但在這支手機上不可能是 root 工具隱藏的掛載。
  - 同一支 Xiaomi 12 在**同一次開機**的下午重掃（只換了 Sample App 版本）：區間內仍是同樣 49 個掛載、mountinfo 仍是 196 筆，但 ID 從橫跨 210 個號碼變成 50 個，`missingCount` 由 160 變 0。缺口取決於掃描**何時**執行（本行程 mount namespace 建立時，其他 namespace 是否同時在配發 ID 屬推測，未驗證），而不是手機的組態。
  - 在 Redmi 13C 上，同一組態在不同日期擷取的兩格（`lsposed_control_2026` 的 `L3` 與 `followup_2026` 的 `Z0`：Zygisk Next「僅還原掛載」、Sample App 在 DenyList、hook 已載入）一格沒有缺口、一格 MODERATE；`L0`、`L2` 也有缺口，`L1`、`Z1`–`Z3` 與消融 `R0`–`R4` 則沒有。缺口的有無找不到與組態對應的規律。
  - 反方向：DenyList 確實把掛載從本 App 視圖移除的消融 `R1`，序列毫無缺口（見「看不到什麼」）。
  一條會在未修改的手機上觸發、在修改過的手機上又無法連結到隱藏行為的規則，不構成證據，所以它不再產生 finding。序列統計仍完整發布，供研究使用。受影響的既有擷取：Xiaomi 12、`Z0`、`L0`、`L2` 的 `MOUNT_INTEGRITY` 都只靠這條規則成立，改版後會回報 NOT_OBSERVED。
- **OEM 特製韌體中的唯讀分區 rw 掛載。** 少數原廠客製韌體或工程韌體將 `/vendor` 或 `/odm` 以 `rw` 掛載，會觸發 `system_rw`（WEAK）。
- **關鍵字字串包含邊界。** 規則搜尋如 `ksu` 雖已做單詞邊界限制，但在非常特殊的 OEM 路徑名稱下仍存在潛在名稱碰撞風險。

## 看不到什麼

- **Mount ID 序列缺口:這個技巧在 app 視角下抓不到現代的逐 App 卸載。** 視角三的前提是
  「核心單調配發 mount ID,所以把掛載從我的視圖移除會留下號碼的洞」。實測顯示這個前提在
  應用程式的視角下**不成立**:app 的 mount namespace 是在 zygote fork 時 clone 出來的,
  而 clone 本身就會配發一整塊**全新且連續**的 ID,所以 app 看到的是自己 namespace 的重新
  編號,不是被挖過洞的原始編號。

  `ablation_2026` 十四格的證據:每一格都滿足 `dataMirrorMountId − artMountId − 1 ==
  visibleCount`,亦即區間內每一個整數 ID 都在,`missingCount` 與 `maximumGap` 恆為 0。
  ID 的絕對值逐格上升(Redmi `R0` 的 20317 → `R4` 的 175913)也符合「每次都是全新配發」。
  這在 `R1` 尤其關鍵——該格 Magisk 的 DenyList 確實把掛載從本 App 的視圖移除了
  (`MOUNT_INTEGRITY` 的表格標記與 `SU_BINARY` 同時失效),序列卻毫無缺口。

  **這是正確的沉默,不是死通道。** Duck-Detector 實作了同一個技巧且判準更嚴格(相鄰項缺
  一個就報,無門檻),在同一批十二份報告中同樣一次都沒有觸發。兩個獨立實作的一致結果,是
  目前對「此技巧無法對抗現行 Magisk / KernelSU」最強的證據。

  **後來的擷取推翻了「缺口恆為 0」。** 2026-09-14 之後的擷取在 Redmi 13C 的部分格子與一支乾淨的
  Xiaomi 12 上都出現了缺口（見「已知偽陽性來源」），但沒有一次能對應到隱藏行為。因此這個技巧
  既沒有正對照，又有乾淨裝置上的反例，已於 2026-09-18 改為遙測。

- **與 Duck 不同的選擇。** Duck 在相鄰 mount ID 缺一個時即報 DANGER。本檢測原本要求
  `missingCount > 10` 或 `maximumGap > 5` 才評級，2026-09-18 起完全不評級。這是**刻意的取捨**:
  本專案偽陽性控制的優先序高於靈敏度，而乾淨的 Xiaomi 12 上就有 160 個 ID 的缺口。記錄於此以免
  日後被誤認為疏漏。

- **核心層全面一致性竄改。** 若隱藏工具在核心內部同時攔截修改 `statx`、`statfs` 與 `/proc/self/mountinfo`，使三者答案一致，本檢測無法看出矛盾。
- **未受監控的路徑。** `statx` 僅監控 7 個路徑，`statfs` 僅監控 5 個路徑，不在清單上的路徑若被單獨掛載覆蓋則無法透過核心交叉比對捕捉。
- **核心不提供 `STATX_MNT_ID` 的裝置。** 這裡有**兩道**不同的門檻，先前本節只寫了第一道：`statx` 系統呼叫本身自 Linux 4.11 起提供，但本檢測需要的 `stx_mnt_id` 欄位是 **Linux 5.8** 才加入的。核心版本落在兩者之間的裝置會讓 `statx` 回傳成功，卻不填入 mount ID，因此視角四的 mount ID 交叉比對無法執行。
  實測案例：機隊中的 Redmi 13C（Android 13、核心 `4.19.191`）在 `ablation_2026` 的 `R0`–`R4` 五格中，三個 unit 全部回報 `PARTIAL`（當時 adapter 把偵測器層級的錯誤貼到每個 unit；自 2026-10-05 起 `source=statx` 的錯誤只歸屬 `kernel-view-consistency`，另兩個 unit 不再因此降為 `PARTIAL`，而 `/proc/self/mountinfo` 讀取失敗仍以 `.shared` issue 標記全部三個 unit），並附帶 `errno=38`（`ENOSYS`）的收集錯誤「statx syscall or libc symbol is unavailable; mount-ID cross-check was skipped.」；同批的 Pixel 7（核心 `6.1.157`）則為 `COMPLETE` 且 `presentInMountInfo` 正常回報。**這是設計上正確的降級**——證據契約把平台限制表達為 `PARTIAL` 加收集錯誤，而不是表達為乾淨。但要注意 `statxChecks[].succeeded` 記錄的是「系統呼叫回傳 0」，在這類裝置上為 `true`，判讀時應以 unit 的 `collectionStatus` 為準。

## 建議處置

| 強度 | 建議 |
|---|---|
| STRONG | 觀察到明確的 root 框架掛載特徵、procfs 與核心矛盾或缺乏 Zygote 隔離，建議作為高風險環境指標納入安全決策。 |
| WEAK | 系統分區具備可寫掛載或一般性啟發式特徵，可能為 OEM 韌體特性或一般客製 ROM，僅供遙測參考。 |
| NOT_OBSERVED | 掛載表與核心視角一致且未見已知特徵，但不排除完全一致的進階核心掛載隱藏。 |
| INCONCLUSIVE | 無法讀取 `/proc/self/mountinfo` 且核心一致性檢測無法執行時回報。 |

## 成本

- 解析 `/proc/self/mountinfo` 一份文字檔。

**本檢測的成本由掛載表大小決定，而掛載表大小是隱藏堆疊的性質，不是裝置的性質。** 2026-09-07 實測：Pixel 7（KernelSU，170 筆掛載）耗時 8.0 ms；Redmi 13C（Magisk，**1,673 筆**掛載，因為 bind mount 全在表裡）耗時 851 ms —— 相差 98 倍。

拆解之後，成本幾乎全部不在我們這邊：

| 階段 | Redmi 13C |
|---|---:|
| `read()` 系統呼叫（核心產生 procfs 內容） | 623 ms |
| 解析與 tokenise | 12 ms |
| 標記比對與判定 | 36 ms |

也就是說**這個 detector 的耗時主要是核心把 `/proc/self/mountinfo` 交給本行程的成本，應用層優化的空間有限**。同一份檔案用 `adb shell cat` 只需 24 ms，差異來自本行程 namespace 的內容而非 procfs 本身。

`/proc/self/mounts` **刻意不讀取**。它描述的是同一個 namespace 中的同一批掛載點，欄位是 mountinfo 的嚴格子集，唯一曾經的貢獻是 `overlayDeclared`，而 mountinfo 迴圈已經用同一個檔案系統型別算出該值。讀它在 Redmi 上約需 250 ms 而不產生任何 mountinfo 沒有的資訊，因此於 2026-09-07 移除。**這是語意變更**：payload 不再有 `mountsReadable` 與 `mountsEntryCount` 欄位；`hidden_overlayfs` finding 的守衛條件也從「兩張表任一可讀」改為「mountinfo 可讀」，因為 `overlayDeclared` 現在只來自 mountinfo。
- 執行 2 次 `readlink`（查詢 self 與 init 的 namespace 符號連結）。
- 執行 7 次 `statx` 與 5 次 `statfs` 系統呼叫。
- 不 fork 任何子行程，完全在當前行程內完成。
- 不需要任何整合者權限或 AndroidManifest 配置。

## Evidence units

### mount-integrity.table-marker

記錄掛載表中發現的特徵列，包括 Magisk、KernelSU、Magic Mount 等明確框架標記（STRONG），以及系統分區 rw、loop 備份等通用啟發式結果（WEAK）。

### mount-integrity.kernel-view-consistency

記錄 `statx` 的 `stx_mnt_id` 與掛載表比對結果，以及 `statfs` 偵測到的 OverlayFS magic 與掛載表宣告是否相符。任何核心回傳存在但掛載表消失的現象（`statx_mount_id_missing`、`hidden_overlayfs`）均在此 unit 回報為 STRONG。

### mount-integrity.namespace-observation

記錄 mount namespace 結構與遙測資料，包括與 init namespace 的比對狀態（`shared_init_namespace`，唯一會讓本 unit 產生訊號的規則）、ART 到 data_mirror 之間的 mount ID 序列統計（`mountIdSequence`，僅遙測）、直接 block 掛載統計與系統 overlay 聚合資料。
