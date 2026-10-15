# Native Root Interface Probe

直接向 Linux 核心介面探測原生 Root 框架（KernelSU、APatch、KernelPatch）的通訊協定與系統狀態，包含發送 `prctl(0xDEADBEEF)` 指令、在 ARM64 架構上基準評測 Supercall（`syscall(45)`）延遲差值、檢查行程的 cgroup 分組階層（`/proc/self/cgroup`），以及掃描自身 SELinux context 與 KernelSU 驅動檔案描述符。這些框架透過改動核心以繞過傳統使用者空間偵測，但其客製化的核心介面與特殊呼叫延遲仍會留下獨特的通訊特徵。

## 這個檢測在看什麼

本檢測整合四項原生核心與行程特徵探測：

- **KernelSU `prctl` 協定探測**：
  - 呼叫 `prctl(0xDEADBEEF, 2, 0, 0, 0)`（版本查詢指令）。若回傳值 > 0，直接識別為 KernelSU 並取得其版本號。
  - 若未成功，檢查 errno 是否非預期的 `EINVAL` 或 `ENOSYS`；並嘗試備用指令集 `{0, 1, 3, 4, 10}`，若回傳值 >= 0 且 `errno == 0`，代表 KernelSU 核心通訊介面存在。
- **APatch / KernelPatch Supercall 延遲基準（ARM64）**：
  - 在 fork 出的子行程中，利用硬體計時暫存器 `cntvct_el0` 與 `cntfrq_el0`，執行 2 輪各 100,000 次的 `syscall(45, buffer, 0x1000)`。
  - 一輪傳遞填滿 'A' 的有效字串緩衝區，另一輪傳遞全為 0 的空緩衝區。若兩者平均耗時差值 `diffUs > 3.0` 微秒，標記為 Supercall 延遲異常（`supercall_latency_deviation`）。
- **cgroup 行程分配檢查**：
  - 讀取 `/proc/self/cgroup`（前 2048 位元組）。當 App UID >= 10000 時，正常 App 應隸屬於含有 `uid_<uid>` 的控制群組；若缺乏 UID 標記且落入根層級切片（`0::/`）、或含有 `/magisk/`、`/ksud` 路徑，標記為 cgroup 分配異常。
- **自我行程身分與驅動描述符**：
  - 讀取 `/proc/self/attr/current`，檢查自身 SELinux context 是否為 `u:r:su:s0` 或含有 `:su:`。
  - 走訪 `/proc/self/fd`，檢查是否持有指向 `[ksu_driver]` 或 `[ksu_fdwrapper]` 的開啟描述符。

## 觸發代表什麼

- **STRONG**：若確認 `ksuDetected`（`prctl` 協定確認）、自身處於 `su` SELinux domain，或持開啟的 `[ksu_driver]` / `[ksu_fdwrapper]` 描述符。此類直接協定或硬標記代表高度確定存在提權環境。
- **MODERATE**：若僅觀察到 `apatchDetected`（Supercall 延遲差值 > 3.0 us）、`cgroupAnomaly`，或非預期的 prctl errno。

不能推論的：
- **不能將 Supercall 延遲單獨視為絕對存在 APatch。** 延遲檢測未做 CPU 核心綁定或頻率鎖定，受動態調頻與系統負載干擾，因此代碼中明確僅給予 MODERATE，不作為硬性憑據。
- **不能推論當前應用已被授予 Root。** 介面存在代表核心具備此能力，不代表授權清單已放行當前 App。

## 已知偽陽性來源

- **未校準的 Supercall 延遲門檻**（`native_root_prctl.cpp` 第 51-69、215 行）：3.0 微秒的延遲差值門檻為 Duck-Detector 沿用的編譯期常數，尚未在各晶片組的乾淨裝置上進行基線校準；在 CPU 頻率劇烈縮放（DVFS）、大小核動態排程或系統背景負載極高時，100,000 次系統呼叫可能因排程抖動產生超過 3.0 微秒的延遲差。
- **非典型容器或虛擬化 cgroup 階層**（`native_root_prctl.cpp` 第 253-258 行）：部分自訂 ROM、車載系統、Waydroid、WSA（Windows Subsystem for Android）或測試沙盒將所有應用掛載於單一根 cgroup（`0::/`），缺乏 Android 專屬的 `uid_<uid>` 標籤，會誤觸發 `cgroup_allocation_anomaly`。
- **非標準核心對未支援 prctl 的 errno 實作**（`native_root_prctl.cpp` 第 168-177 行）：少數 OEM 客製核心在收到未知的 `prctl` option 時回傳 `EFAULT` 或 `EPERM` 而非標準的 `EINVAL` 或 `ENOSYS`，會產生 WARNING 等級的非預期錯誤碼記錄。

## 看不到什麼

- **自訂 Magic 的 KernelSU 構建**：若使用者自行修改 KernelSU 核心原始碼，將 `kKernelSuMagic`（`0xDEADBEEF`）改為自訂數值，`prctl` 探測將完全無效。
- **非 ARM64 架構上的 APatch 延遲探測**：Supercall 延遲探測受編譯巨集 `#if defined(__aarch64__)` 保護；在 x86_64 模擬器或 32 位元 ARM 環境中該項直接略過。
- **Seccomp 阻擋 `syscall(45)`**：若系統或容器環境設定了嚴格的 Seccomp 規則直接阻擋未使用的 syscall 45，子行程會收到 `SIGSYS` 終止，檢測僅記錄 INFO 訊息而無法測量延遲。
- **良好隔離的 Root 行程**：若 Root 框架在專屬命名空間執行且完全隔離了 `/proc/self/fd` 與 cgroup，檢測器無法在 App 行程內看到殘留。

## 建議處置

| 強度 | 建議 |
|---|---|
| STRONG | KernelSU `prctl` 協定應答、自身 su context 或持有 ksu 驅動描述符，為確定性的核心 Root 訊號，建議立即納入高風險處置。 |
| MODERATE | APatch 延遲偏離或 cgroup 結構異常，可能受硬體負載或客製系統影響，建議作為輔助評估資訊，結合其他 Native/Kernel 領域檢測綜合判斷。 |
| NOT_OBSERVED | 未觀察到 KernelSU 協定應答或異常延遲，不保證無其他修改了 Magic Code 的自編核心。 |

## 成本

- 執行 1 次 `prctl(0xDEADBEEF, 2)` 系統呼叫；若未命中則額外執行最多 5 次備用指令。
- 在 ARM64 裝置上會 **fork 一個子行程**，在子行程中執行 2 輪各 100,000 次的 syscall 45 延遲測量，並透過 pipe 將結果回傳給父行程 `waitpid` 同步接收。
- 讀取 `/proc/self/cgroup`（2048 位元組）、`/proc/self/attr/current`（256 位元組），並遍歷 `/proc/self/fd`。
- 整合者不需要在 `AndroidManifest.xml` 中配置任何權限或設定。

## Evidence units

### native-root-prctl.kernelsu-protocol

記錄原生 Root 協定探測結果，涵蓋 KernelSU `prctl(0xDEADBEEF)` 應答與版本號、APatch Supercall（syscall 45）延遲微秒差值、`/proc/self/cgroup` 分配狀態、自身 SELinux context、以及 `/proc/self/fd` 是否持有 `[ksu_driver]` 或 `[ksu_fdwrapper]` 描述符。
