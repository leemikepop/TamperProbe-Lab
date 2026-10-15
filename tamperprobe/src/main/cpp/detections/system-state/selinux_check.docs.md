# SELinux Global Enforcement

交叉比對 selinuxfs 節點與 libselinux 函式庫回報的強制模式（Enforcing / Permissive / Disabled）；當 enforce 節點的讀取被以 `EACCES` 拒絕時，由「核心讓所有 uid 都能通過 DAC 讀取這個節點」推論出 app 自身網域受到強制（read-denial inference）；以唯寫模式（O_WRONLY）探測 enforce 節點之權限邊界（絕不寫入資料），並記錄行程目前之安全性網域。這項檢測旨在確認 Android 核心強制存取控制（MAC）的基礎保護是否處於正常啟用狀態。

## 這個檢測在看什麼

檢測器自多個來源收集 SELinux 狀態與檔案系統權限：

1. **檔案系統類型驗證**（`selinux_check.cpp` 第 284-304 行）：
   透過 `statfs("/sys/fs/selinux", &statfs)` 檢查掛載魔術數字是否為 `SELINUX_MAGIC`（`0xf97cff8c`）。
   這個檢查同時是 read-denial inference 的前提（見第 3 點）。
2. **多來源強制模式比對**（第 306-362 行）：
   - `selinuxfs_enforce`：以 `open` 讀取 `/sys/fs/selinux/enforce` 前 512 位元組，`"1"` 代表 ENFORCING，`"0"` 代表 PERMISSIVE（第 66-83 行）。
   - `selinuxfs_read_denial`：上一個來源的讀取以 `EACCES` 失敗時才會作答的**推論來源**，見第 3 點。
   - `libselinux`：呼叫 `is_selinux_enabled()` 與 `security_getenforce()`（`readLibselinux`）。
     符號解析先走 `dlsym(RTLD_DEFAULT, ...)`，取不到才以 `dlopen("libselinux.so", RTLD_NOW | RTLD_NOLOAD)`
     要求**行程內已載入**的那份映像。這點很關鍵:framework 早已把 libselinux 載進每個 app 行程，
     但 app 的 linker namespace 拒絕重新載入它，所以普通的 `dlopen` 會以「library not found」失敗。
     2026-09-12 之前這裡用的是 `RTLD_NOW | RTLD_LOCAL`。同樣的修法早已存在於 `policy_oracle.cpp`，
     Duck-Detector 的 selinux 探針也是這樣解析符號的。
     **但實測顯示這個修正在機隊上不會改變結果，原因比 dlopen 旗標更根本。** 2026-09-12 於兩台
     裝置量測:`/system/lib64/libselinux.so` 確實存在，但它**不在任何 `public.libraries*.txt`**
     之中，也就是不屬於應用程式的公開 linker namespace。`RTLD_NOLOAD` 只在該函式庫已載入**且
     呼叫者的 namespace 看得見該 soname** 時才有用;對 app 而言 libselinux 位於系統 namespace，
     因此連 `RTLD_NOLOAD` 也一樣回報 library not found。Duck-Detector 有相同限制，其 audit probe
     的失敗訊息即為「libselinux callback symbols unavailable in this app process」。
     修正仍予保留:它在形式上是正確的解析順序、成本為零，且在 libselinux 可見的環境
     （較舊的 Android，或 namespace 不同的載體行程）能真正作答。
3. **讀取拒絕推論（read-denial inference，`runReadDenialInference` 第 194-255 行；判定邏輯在
   `property_detector_logic.cpp` 的 `inferSelinuxReadDenial`）**：
   核心建立 selinuxfs 時把 `enforce` 的模式**寫死**為 `S_IRUGO|S_IWUSR`（0644），擁有者 root:
   Linux `security/selinux/selinuxfs.c` 的 `sel_fill_super()` 檔案表
   `[SEL_ENFORCE] = {"enforce", &sel_enforce_ops, S_IRUGO|S_IWUSR}`
   （<https://github.com/torvalds/linux/blob/dc67c654bc9c9a742e82b5f19acb2f3a00b44cf5/security/selinux/selinuxfs.c#L1833>；
   v5.4、v6.1 與 Android Common Kernel `android14-6.1` 內容相同）。AOSP `init.rc` 只對
   `/sys/fs/selinux/policy` 做 `chmod 0444`，沒有改動 `enforce`。因此 **DAC 允許任何 uid 讀取它**，
   `sel_read_enforce()` 本身也不做額外檢查。當 app 的 `O_RDONLY` 開啟或讀取仍然回傳 `EACCES`，
   唯一能拒絕它的就是 SELinux 對 app 自己的網域執行了 denial。依 `security/selinux/avc.c` 的
   `avc_denied()`，只有在「全域 enforcing **且**該網域不是 permissive」時 AVC 才會回傳 `-EACCES`;
   全域 permissive 或 app 網域 permissive 時讀取會成功並回傳 `"0"` 或 `"1"`。Disabled 的 SELinux
   在現代 Android 上無法開機。具體條件（全部成立才推論）:
   - 讀取的 errno **必須是 `EACCES`**。`EPERM`、`ENOENT`、`EIO` 等一律不推論
     （`reason=read_errno_not_eacces`）。
   - `statfs` 必須確認是 selinuxfs（`SELINUX_MAGIC`）;否則該路徑可能是 bind mount 或替身 tmpfs，
     核心模式的論證不適用（`reason=selinuxfs_not_verified`）。
   - 接著對節點做 `stat()`:
     - 成功時以**量測到的** mode/uid/gid 依 `generic_permission()` 的方式（owner → group → other，
       只套用一類）評估 DAC;對一般 app（非 owner、不在 gid 0）即等於要求 `S_IROTH`。
       `dacBasis=measured_mode`。若 DAC 本身就不允許讀取（例如 OEM 把節點改成 0640），
       拒絕可以完全由 DAC 解釋，**不推論**，記錄 `anomaly=enforce_node_dac_not_kernel_default`
       作為遙測，不產生 finding（理由:模式被改只說明 OEM/ROM 與上游不同，不等於竄改）。
       不是一般檔案（`anomaly=enforce_node_not_regular_file`）同樣不推論。
     - `stat()` 本身也以 `EACCES` 被拒（app 沒有對該節點的 getattr）時，退回核心的固定值 0644、
       root:root，並記錄 `dacBasis=kernel_constant`、`kernelMode=0644`——**這是常數，不是量測**。
     - `stat()` 以其他 errno 失敗時不推論（`reason=stat_failed`）。
   推論成立時 `selinuxfs_read_denial` 回報 ENFORCING，payload 的 `readDenialInference` 記錄
   `state=inferred`、`scope=app_domain`、`readErrno`、`readStep`（`open` 或 `read`）、`stat` 結果與
   `dacBasis`。此時 `selinuxfs_enforce` 的讀取失敗**不再**列為 collection error，因為這次拒絕本身
   已經是答案。讀取成功時本推論為 `not_applicable`;讀到 `"1"` 維持原行為，**讀取意外被允許**
   不產生任何 finding（不同 API level 的 policy 本來就不同），只留在遙測中。
4. **Enforce 節點權限探測**（第 364-381 行）：
   嘗試以 `open("/sys/fs/selinux/enforce", O_WRONLY | O_CLOEXEC)` 開啟。若開啟成功，立即關閉且不寫入任何資料；在正常 SELinux 策略下，未授權應用程式絕不可能具備寫入權限，若能開啟即證明策略已被穿透。若遭遇 `EACCES` 或 `EPERM` 則記錄為 denied。
   注意寫入被拒**不**當作答案:非 root 的寫入無論 SELinux 狀態如何都會被 DAC（`S_IWUSR` 只給 root）拒絕。
5. **行程安全性網域**（第 383-392 行）：
   讀取 `/proc/self/attr/current` 記錄當前 SELinux context（如 `u:r:untrusted_app...`）作為情境資訊。

在 `assessSelinux` 中比對：若節點可寫入，或兩個**讀取**來源說法衝突，產出 STRONG；若任一來源回報 Permissive 或 Disabled，產出 MODERATE；推論來源與讀取來源衝突時產出 MODERATE（見下表）。任一來源（含推論來源）回報出模式即算作答;沒有任何 finding 時回報 NOT_OBSERVED。

## 觸發代表什麼

| 判定 | 條件 | 代表意義 |
|---|---|---|
| STRONG | `open(O_WRONLY)` 成功，或兩個讀取來源（`selinuxfs_enforce`、`libselinux`）回報之強制模式彼此衝突 | Enforce 節點存取權限失控（`enforce_node_writable`），或核心與使用者空間函式庫說法矛盾（`enforcement_source_contradiction`），高度代表核心安全性策略遭到人為破壞或 Hook。 |
| MODERATE | 任一可用來源回報 `PERMISSIVE` 或 `DISABLED` | 全域 SELinux 未處於 Enforcing 狀態（`selinux_permissive` 或 `selinux_disabled`），系統強制存取控制已實質失效。 |
| MODERATE | 推論來源（`selinuxfs_read_denial` = ENFORCING）與讀取來源（實務上只可能是 `libselinux`）衝突 | `inferred_enforcement_contradiction`。同一行程讀同一個節點，一條路徑被拒、另一條路徑卻讀到非 Enforcing，代表至少一條路徑被攔截。**刻意不升為 STRONG**:推論比直接讀取多一個前提（「能拒絕 DAC 可讀節點的只有 SELinux」），誤報成本高於多一級強度的收益。對方若回報 Permissive，`selinux_permissive` 也會同時成立，整體仍為 MODERATE。 |

不能推論的：
- **不能推論特定 root 工具。** 任何核心修改、自訂 ROM 關閉 SELinux 或 Hook 行為皆會造成相同現象。
- **不能證明細部策略無損。** 全域處於 Enforcing 僅代表大門未開，不能保證個別 domain 未被注入 allow 規則。
- **推論來源回答的是「app 自己的網域是否受到強制」，不是嚴格意義的全域模式。** 由 `avc_denied()`
  的語意可推得當下全域也必然是 Enforcing（全域 permissive 下 SELinux 不會拒絕任何存取），但它
  **完全無法**說明其他網域（例如 `su`、`magisk`、`ksu`）是否被設為 permissive。

## 已知偽陽性來源

- **原廠開發/工程韌體手動設為 Permissive。** 開發者或測試機韌體透過 `setenforce 0` 將全域模式切換為 Permissive（`property_detector_logic.cpp` 第 658 行 `selinux_permissive`），會觸發 MODERATE 判定。
- **非典型 Android 容器執行環境。** 在 Waydroid、Anbox 等環境中，SELinux 可能被全域關閉（`is_selinux_enabled() == 0`，`property_detector_logic.cpp` 第 650 行 `selinux_disabled`），觸發 MODERATE。
- **中介安全軟體 Hook 導致來源矛盾。** 若外部防護工具僅 Hook 了 `libselinux.so` 的 API 回傳 Enforcing，卻未攔截直接對 `/sys/fs/selinux/enforce` 的讀取（讀到 0），兩來源說法衝突會觸發 STRONG（`property_detector_logic.cpp` 第 645 行）。
- **量測期間有人執行 `setenforce`。** 兩個來源分別讀取，中間若切換模式會造成一次性的衝突;重複擷取即可排除。

## 看不到什麼

- **特定網域的 Permissive 注入（Domain-level Permissive）。** Magisk、KernelSU 或 APatch 等現代 Root 工具通常保持全域 SELinux 為 Enforcing（`/sys/fs/selinux/enforce` 仍為 1），僅將自身行程所屬網域設為 permissive 或透過 sepolicy 注入 allow 規則。此類針對性竄改無法由本檢測察覺;讀取拒絕推論只看得到 app **自己的**網域。
- **系統呼叫層級 Hook。** 若攻擊者透過 seccomp 或 libc hook 攔截 `open`，在讀取 enforce 節點時固定回傳 `"1"`、嘗試寫入時固定回傳 `EACCES`，此檢測將回報 `NOT_OBSERVED`。
  同理，**讓 `open()` 對 enforce 節點固定回傳 `EACCES` 的 hook 會直接擊敗讀取拒絕推論**:推論無法分辨
  SELinux 的拒絕與偽造的 `EACCES`——這和它擊敗其他每一個來源的方式相同，不是推論特有的弱點。
  同一前提下，若裝置另外堆疊了會以 `EACCES` 拒絕此讀取的 LSM（例如 BPF LSM），推論也會把它歸因於
  SELinux;機隊上未見此配置。
- **推論前提不成立的設備。** 讀取被拒的 errno 不是 `EACCES`、`statfs` 無法確認 selinuxfs、`stat()`
  顯示 DAC 不允許讀取、或 `stat()` 以 `EACCES` 以外的 errno 失敗，且 `libselinux.so` 也無法作答時，
  回報 `INCONCLUSIVE`。`readDenialInference.reason` 記錄是哪一個前提不成立。
- **現行 Android 上兩個讀取來源通常都無法作答;全域模式現在靠推論來源回答。** 標準 `untrusted_app`
  原則下 `/sys/fs/selinux/enforce` 回傳 EACCES，而 libselinux 不在 app 的公開 linker namespace 中，
  **兩個讀取來源都無法作答**（2026-09-12 於兩台裝置量測，不是推測）。在加入讀取拒絕推論之前，
  這使本 detector 在每一支手機（rooted 或乾淨）上都回報 `INCONCLUSIVE`;現在同一個 `EACCES`
  經由推論回答 ENFORCING，預期結果改為 `NOT_OBSERVED`。這個 NOT_OBSERVED 的意思是
  「app 自己的網域受到強制、節點不可寫」，**不是**「SELinux 沒問題」:在機隊的 rooted 手機上它也會是
  NOT_OBSERVED，因為現代 root 工具不動全域模式。新規則尚待實機確認;在確認前，請以
  `readDenialInference` 遙測核對 `readErrno=13` 與 `stat` 結果。
  值得注意的是，寫入探測被拒（EACCES/EPERM）是任何裝置（無論是否 root）都會有的正常結果，
  它不回答強制模式。2026-09-12 之前這個被拒的寫入探測會單獨令
  `hasReliableObservation` 成立，使 detector 在**零個強制模式來源作答**的情況下仍回報
  `NOT_OBSERVED`（讀起來像「SELinux 沒問題」）—— 十四格全部如此。現已改為只有真正回報了模式的
  來源（含推論來源）才算作答;enforce 節點**可寫**仍然是 STRONG，不受影響。

## 建議處置

| 強度 | 建議 |
|---|---|
| STRONG | 觀察到 enforce 節點可寫入或讀取來源衝突。核心安全保護已被實質破壞，強烈建議納入高風險決策並中斷敏感操作。 |
| MODERATE | 全域 SELinux 處於 Permissive 或 Disabled，或推論來源與讀取來源衝突。系統可能失去 MAC 保護，建議限制重要功能。 |
| NOT_OBSERVED | 至少一個來源（含讀取拒絕推論）回報 Enforcing、沒有來源衝突，且節點權限正常。若答案來自推論，只代表 app 自己的網域受到強制。不代表個別 domain 策略未遭竄改。 |
| INCONCLUSIVE | 沒有任何來源回報出模式，推論前提也不成立。判讀時**不可**當成 SELinux 正常;`readDenialInference.reason` 說明原因。 |

## 成本

- 1 次 `statfs` 系統呼叫。
- 1 次以 `O_RDONLY` 開啟、讀取並關閉 `/sys/fs/selinux/enforce`。
- 僅在讀取以 `EACCES` 失敗時:1 次 `stat`、2 次 `getgroups`、`geteuid`/`getegid` 各 1 次。
- 2 次 `dlsym(RTLD_DEFAULT, ...)`;僅在符號未解析時才額外 1 次 `dlopen(RTLD_NOLOAD)` + `dlsym` + `dlclose`。
- 1 次以 `O_WRONLY` 嘗試開啟 `/sys/fs/selinux/enforce` 並立即關閉（絕不寫入）。
- 1 次讀取 `/proc/self/attr/current`。
- 1 行 `component=SelinuxCheck event=read_denial_inference` logcat 遙測。
- 無 process fork，無寫入操作，無需 Android 權限。

## Evidence units

### selinux.enforcement-state

記錄各可用來源所回報之強制狀態，以及 `readDenialInference` 遙測（推論是否成立、DAC 依據為量測或核心常數）。若發現模式為 Disabled 或 Permissive，產出 `selinux_disabled` 或 `selinux_permissive` finding，強度為 MODERATE。本 unit 的命題是「至少一個來源回報出模式」，因此任一來源（含推論來源）作答即為 COMPLETE;單一來源失敗不會讓它變成 PARTIAL，只有在**沒有任何來源**作答時 native 才送出 `enforcement_sources` collection error 標記本 unit。

### selinux.enforce-node-access

記錄 `/sys/fs/selinux/enforce` 節點之唯寫開啟探測狀態（`opened`、`denied` 或 `unavailable`），以及讀取被拒時 `stat()` 量到的 mode/uid/gid（或其 errno）。若開啟成功，產出 `enforce_node_writable` finding，強度為 STRONG。`stat()` 顯示非核心預設模式只記錄為 `anomaly` 遙測，不產生 finding。

### selinux.cross-source-consistency

交叉比對各來源的強制狀態。兩個讀取來源衝突（例如一者為 Enforcing、另一者為 Permissive）產出 `enforcement_source_contradiction`，強度為 STRONG;需要推論來源才成立的衝突產出 `inferred_enforcement_contradiction`，強度為 MODERATE。`selinuxfs_enforce`、`libselinux` 任一個未作答都會讓本 unit 成為 PARTIAL，因為比對少了一個視角——在現行機隊上 libselinux 永遠不可見，所以本 unit 預期為 PARTIAL。
