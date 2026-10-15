# Emulator Hardware Indicators

利用離屏 OpenGL ES 渲染器比對虛擬化驅動與軟體點陣化特徵、以 ARM64 虛擬計數器暫存器與單調時鐘比對時鐘漂移，並分析 32 次執行緒排程讓出（sched_yield）之延遲抖動分佈。這項檢測旨在從底層硬體與排程行為辨識 Android 虛擬化與模擬器環境。

## 這個檢測在看什麼

檢測器整合三項相互獨立的硬體與核心行為探針：

1. **離屏 OpenGL ES 渲染器探針**（第 42-138 行）：
   初始化 EGL 1.4，建立 1x1 pbuffer surface（`EGL_PBUFFER_BIT`、`EGL_OPENGL_ES2_BIT`）與 OpenGL ES 2.0 context，查詢 `glGetString(GL_RENDERER)`，比對是否包含以下 8 個模擬器特徵字串（第 109-118 行）：
   `swiftshader`、`llvmpipe`、`mesa`、`android emulator opengl es translator`、`vmgl`、`virtualbox`、`vmware`、`software rasterizer`。命中則輸出 STRONG。
2. **ARM64 硬體計時暫存器探針**（僅支援 `__aarch64__`，第 151-208 行）：
   透過組合語言讀取 `cntfrq_el0` 虛擬計數器頻率與 `cntvct_el0` 計數器值，比對 `clock_gettime(CLOCK_MONOTONIC)`。執行 256 次 `getpid()` 迴圈後再次取樣，計算經過的牆上時間（`wallNs`）與計數器換算時間（`counterNs`）。若計數器倒退、計數差為 0，或在 `wallNs >= 5000` 奈秒且兩者絕對漂移超過牆上時間的 75%（`absDiff > (wallNs * 3) / 4`，第 199 行），判定為異常（MODERATE）。
3. **排程讓出抖動探針**（第 220-265 行）：
   執行 32 次 `sched_yield()` 迴圈，每次以 `CLOCK_MONOTONIC` 量測延遲並歸入 1 微秒分桶（`elapsedNs / 1000`）。計算平均延遲、標準差與變異係數（`cv = stdDev / mean`）。若變異係數極低（`cv < 0.03`）且微秒分桶數小於等於 2 個、平均延遲小於 250,000 奈秒（第 259 行），判定排程呈現虛擬 Hypervisor 之確定性排程特徵（WEAK）。

## 觸發代表什麼

| 判定 | 條件 | 代表意義 |
|---|---|---|
| STRONG | EGL 渲染器命中 8 個模擬器特徵字串之一 | GPU 渲染環境明確由虛擬機器驅動程式（如 VirtualBox、VMware）或軟體點陣化庫（如 SwiftShader、LLVMpipe）提供。 |
| MODERATE | ARM64 計時器暫存器異常（頻率為 0、計數倒退或漂移 > 75%） | CPU 虛擬計數器頻率與核心單調時鐘嚴重脫節，提示底層存在 Hypervisor 攔截或計時器虛擬化失真。 |
| WEAK | 排程延遲變異係數過低（cv < 0.03 且桶數 <= 2） | 執行緒讓出延遲呈現人造之確定性分佈，缺乏實體多核心硬體常見之微觀排程抖動。 |

不能推論的：
- **不能推論裝置已 root。** 模擬器或虛擬機器可能是官方標準開發映像檔。
- **不能精準標識虛擬化廠商。** 除了渲染器字串直接匹配外，計時與排程異常僅表示虛擬化行為特徵，無法定位具體軟體品牌。

## 已知偽陽性來源

- **實體機回退至軟體渲染（EGL 偽陽性）。** 部分極低階實體裝置、GPU 驅動異常損壞、或在背景進行特定圖形相容性測試時，若系統改以 `mesa`、`llvmpipe` 或 `swiftshader` 作為點陣化後端（`emulator_hardware_indicators.cpp` 第 122 行），會直接引發 STRONG 誤判。
- **核心頻率動態調整與高優先權排程中斷（計時器偽陽性）。** 在實體 ARM64 晶片上，256 次 `getpid()` 期間若遭遇 CPU 頻率劇烈縮放（CPU frequency scaling）或重度中斷搶佔，使極短時間（大於 5 微秒）內牆上時間與計數器換算時間落差超過 75%（`emulator_hardware_indicators.cpp` 第 199 行），將產出 MODERATE 判定；此 75% 門檻為編譯期常數，尚未在大量乾淨機上校準。
- **極度靜止之單核心/低負載實體系統（排程抖動偽陽性）。** 若實體設備處於完全靜止、無其他活躍執行緒搶佔之狀態，`sched_yield()` 可能迅速回傳且延遲高度一致，使得變異係數 `cv < 0.03` 且微秒桶數不超過 2 個（`emulator_hardware_indicators.cpp` 第 259 行），觸發 WEAK；該啟發式門檻尚未在異質 Android 硬體上校準。

## 看不到什麼

- **主機 GPU 直通或自訂 Renderer 名稱。** 若模擬器採用主機 GPU 穿透（例如直接呈現 NVIDIA、AMD 或 Qualcomm 實體 GPU 字串），8 個寫死關鍵字探針將完全失效。
- **非 ARM64 架構之計時器分析。** x86、x86_64 架構或 32 位元 ARM 模擬器無法執行 `cntfrq_el0` 暫存器讀取，該探針直接標記為不支援（第 204 行）。
- **具備抖動注入機制之現代 Hypervisor。** 虛擬化平台若刻意在時鐘讀取與排程讓出加入亂數雜訊，排程抖動探針將無法識別。

## 建議處置

| 強度 | 建議 |
|---|---|
| STRONG | EGL 渲染器明確指向模擬器驅動或軟體點陣化。正式採用前請先在你的使用者族群上收集分佈並校準基線；確認無誤後可作為模擬器風控阻斷依據。 |
| MODERATE | ARM64 虛擬計數器異常。建議與 `EMULATOR_SYSTEM_PROFILE` 之屬性結果合併研判。 |
| WEAK | 排程抖動過低。僅為統計啟發式特徵，絕不可單獨作為阻斷依據。 |
| NOT_OBSERVED | 各項探針均未觀察到虛擬化特徵。不保證一定是未加固的實體硬體。 |
| INCONCLUSIVE | EGL 初始化失敗、CPU 不支援計時暫存器，且排程樣本數為 0（三個通道全滅）。 |

> 三個探針各自支撐一個 evidence unit。任一探針無法執行時，該通道會記入 collection issue，
> 使對應的 unit 標為 **PARTIAL** —— 探針跑不動不等於觀察到乾淨的結果。
> 2026-10-05 以前這句只在 native 端成立：adapter 把整份 `collectionErrors` 貼到全部三個 unit，
> 一個探針失效就讓三個 unit 一起變 PARTIAL。現在每條錯誤依 `source`（`egl`／`timer`／`sched`）
> 只落在自己的 unit，其餘兩個維持 COMPLETE；無法辨識的 `source` 仍以 `.shared` issue 貼到全部 unit。
> 兩點於 2026-09-12 修正：(1) EGL 不可用時，只有在帶有錯誤訊息的情況下才會被記錄，其餘情況
> 靜默略過；計時器不支援則從未被記錄。(2) 排程探針的 `clock_gettime` 回傳值未被檢查，
> `sampleCount` 恆等於迭代次數 32，使得上列 INCONCLUSIVE 條件中的 `sampleCount == 0`
> **在數學上不可能成立**，整條分支是無法到達的死碼。現在時鐘失敗的樣本會被跳過，該條件才真正可達。

## 成本

- 初始化 EGL Display、建立 1x1 pbuffer surface 與 GLES2 context，呼叫 3 次 `glGetString` 並釋放清理。
- 執行 ARM64 組合語言暫存器讀取，執行 256 次 `getpid()` 系統呼叫。
- 執行 32 次 `sched_yield()` 與 64 次 `clock_gettime(CLOCK_MONOTONIC)`。
- 行程內完成，無 process fork，無外部命令，無需 Android 權限。

## Evidence units

### emulator-hardware.egl-renderer

記錄離屏 EGL/OpenGL ES 渲染器資訊（`GL_RENDERER`、`GL_VENDOR`、`GL_VERSION`）。若命中 8 個模擬器特徵字串之一，產出 finding id `egl_renderer_indicator`，強度為 STRONG。

### emulator-hardware.timer-register-deviation

記錄 ARM64 虛擬計數器暫存器（`cntfrq_el0`、`cntvct_el0`）之讀取結果、換算納秒與單調時鐘牆上時間漂移量（`driftNs`）。若頻率為 0、計數倒退或漂移超過 75% 門檻，產出 finding id `timer_register_deviation`，強度為 MODERATE。

### emulator-hardware.sched-jitter

記錄 32 次 `sched_yield()` 延遲之統計指標（平均納秒、標準差、變異係數 `cv` 與微秒分桶數）。若滿足低抖動確定性啟發式規則，產出 finding id `sched_jitter_anomaly`，強度為 WEAK。
