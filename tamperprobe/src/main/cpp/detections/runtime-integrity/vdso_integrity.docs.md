# VDSO Integrity

交叉檢驗核心映射至行程內的虛擬動態共用物件（VDSO），驗證其記憶體映射區間、輔助向量（`AT_SYSINFO_EHDR`）、ELF 載入區段邊界、動態連結器歸屬以及核心輔助符號解析位址是否保持嚴格一致。藉由多重通道比對，偵測針對 VDSO 的異常重定向、替換或結構竄改。

## 這個檢測在看什麼

檢測器從五個面向驗證 VDSO 的結構一致性：

1. **Maps 映射計數與權限（`vdso_integrity.cpp` 第 86-106 行）**：
   解析 `/proc/self/maps`，尋找路徑標籤為 `[vdso]` 的條目。驗證其條目總數必須剛好為 1（`mappingCount == 1`），且權限必須嚴格為可讀、可執行、**不可寫**（`r-x`）。若出現多個 VDSO 映射或包含可寫權限，發出 finding。
2. **輔助向量一致性（第 108-124 行）**：
   呼叫 `getauxval(AT_SYSINFO_EHDR)` 取得核心傳遞進來的 VDSO 基底位址，驗證該位址必須與 maps 中 `[vdso]` 的起始位址 `vdso->start` 完全吻合。若不一致則發出 `auxv_mapping_mismatch`。
3. **ELF 標頭合法性（第 126-143 行）**：
   透過 `process_vm_readv` 讀取 VDSO 起始位址的 ELF 標頭，驗證 ELF 魔術數字（`\x7fELF`）、類別（32 或 64 位元）、型態為共享物件（`ET_DYN`），以及 Program Header 數量大於 0 且小於等於 256。
4. **PT_LOAD 區段邊界檢查（第 144-181 行）**：
   走訪所有 Program Header，確保至少存在一個 `PT_LOAD` 區段，且所有載入區段的記憶體位址範圍完全落在 `[vdso]` 映射區間內，不得向外溢出（`invalid_vdso_load_range`）。
5. **Linker 歸屬與符號位址驗證（第 186-213 行）**：
   - 透過 `dl_iterate_phdr` 檢查動態連結器的模組清單中，是否存在基底位址等於 VDSO 基底位址的物件（`vdso_linker_owner_missing`）。
   - 透過 `dlsym(RTLD_DEFAULT, ...)` 嘗試解析 3 個核心輔助符號（`__kernel_clock_gettime`、`__kernel_gettimeofday`、`__kernel_rt_sigreturn`），驗證解析出的函式位址必須座落在 `[vdso]` 記憶體範圍內（`vdso_symbol_owner_mismatch`）。

## 觸發代表什麼

OBSERVED 代表上述五項檢查中至少發現一項不一致，整體判定為 MODERATE。這表明當前行程內的 VDSO 記憶體映射遭受到非預期的干預，例如記憶體被重映射、符號被外力掛鉤替換、或核心與使用者空間的映射基底脫節。

不能推論的：
- **不能推論具體的竄改手法。** 一致性違規僅反映結構異常，無法識別是由特定的注入工具、核心模組還是相容層所引起。
- **不能推論裝置已 root。** 特殊的沙盒環境或架構轉譯層亦可能打亂 VDSO 的常規配置。

## 已知偽陽性來源

- **動態連結器未登記 VDSO（Linker Owner Missing）。** 在部分較舊的 Android 版本、特定 32 位元架構或客製化 bionic 實作中，動態連結器在啟動時不會將核心映射的 VDSO 加入 `dl_iterate_phdr` 的鏈結清單中。這會導致 `owner.found` 為 false（`vdso_integrity.cpp` 第 190 行），直接觸發 `vdso_linker_owner_missing`（MODERATE）。
- **Libc 覆蓋或封裝核心輔助符號。** 程式碼透過 `dlsym(RTLD_DEFAULT, ...)` 尋找 `__kernel_gettimeofday` 等符號（第 201 行）。在某些 OEM 韌體或 libc 實作中，libc 本身若直接導出同名封裝函式，符號解析可能優先解析至 `libc.so` 的位址，導致位址落在 `[vdso]` 區間之外（第 207-210 行），引發 `vdso_symbol_owner_mismatch`。
- **雙重映射或非典型核心 VVAR/VDSO 版面。** 少數客製核心或相容環境可能將 VDSO 拆分為多個 VMA 或使用不同的標籤，導致 `mappingCount != 1`。

## 看不到什麼

- **核心就地修補實體頁面。** 若特權模組直接在核心空間改寫物理記憶體頁面中的 VDSO 程式碼，且不改變映射位址、權限與 ELF 標頭結構，本檢測無法察覺指令內容變化。
- **與 VDSO 無關的系統呼叫攔截。** VDSO 在 Linux/Android 上僅用於加速時間查詢（如 `clock_gettime`）與訊號返回（`rt_sigreturn`）。攔截常規檔案系統、網路或行程控制系統呼叫的行為完全不觸碰 VDSO。
- **全面偽造。** 若注入工具在替換 VDSO 的同時同步修改了 auxv、maps 以及 linker 內部結構，維持表象一致，本檢測無法看出分歧。

## 建議處置

判讀前必須在目標裝置族群上進行充分的良性裝置基線收集。

| 強度 | 建議 |
|---|---|
| MODERATE | 發現 VDSO 映射或符號歸屬存在結構性分歧。建議檢查 `findings` 清單中的具體違規類型（如 `vdso_linker_owner_missing` 常見於舊版相容性問題，而 `auxv_mapping_mismatch` 則具備較高的異常可信度），並與其他 domain 結果綜合判定。 |
| NOT_OBSERVED | VDSO 映射結構、輔助向量、ELF 區段與符號歸屬完全自洽。 |
| INCONCLUSIVE | `/proc/self/maps` 無法讀取、找不到 `[vdso]` 條目、`AT_SYSINFO_EHDR` 不可得或 ELF 標頭無法讀取，視為收集失敗。 |

## 成本

- 讀取 `/proc/self/maps` 一次。
- 呼叫 1 次 `getauxval` 系統呼叫。
- 透過 `process_vm_readv` 讀取行程記憶體中的 ELF 標頭與 Program Header。
- 呼叫 `dl_iterate_phdr` 列舉模組一次。
- 最多執行 3 次 `dlsym` 符號解析。
- 不 fork 任何子行程。無須任何 AndroidManifest 設定。

## Evidence units

### vdso.mapping-ownership-consistency

承載 VDSO 映射與歸屬的一致性檢查結果。記錄條目計數、權限、auxv 與 maps 比對狀態、ELF/PT_LOAD 區段合法性、linker 歸屬狀態與符號位址驗證。任何違規皆在此 unit 回報為 finding，推動 MODERATE 判定。
