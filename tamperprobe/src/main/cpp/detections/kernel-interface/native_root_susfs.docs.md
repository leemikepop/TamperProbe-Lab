# SUSFS Side-Channel Probe

利用系統呼叫側信道（side-channel）特徵偵測 SUSFS（KernelSU 的核心檔案隱藏模組）。當一般未提權行程嘗試呼叫 `setresuid` 切換為其他使用者身分時，正常 Linux 核心應回傳 `EPERM`（Operation not permitted）錯誤碼；然而特定版本的 SUSFS 核心補丁在攔截未經授權的 `setresuid` 呼叫時，會直接向發起行程發送 `SIGKILL` 信號強制終止該行程。本檢測透過 fork 子行程進行探測，比對子行程的終止狀態。

## 這個檢測在看什麼

檢測流程如下：

- 首先檢查當前行程 UID，若為 root（`currentUid == 0`）則直接回報 INCONCLUSIVE 略過。
- 計算目標 UID（`targetUid`）：若當前 UID >= 10000（標準 Android 應用 UID），取 10000（若當前即為 10000 則取 9999）；若 0 < UID < 10000，取 `currentUid - 1`。
- `fork()` 一個臨時子行程。
- 子行程呼叫系統呼叫 `syscall(__NR_setresuid, targetUid, targetUid, targetUid)`：
  - 若 `setresuid` 異常成功（回傳 0），子行程以狀態碼 100 退出（`_exit(100)`）。
  - 若 `setresuid` 正常失敗（核心回傳非 0，即標準 EPERM），子行程以狀態碼 0 退出（`_exit(0)`）。
- 父行程呼叫 `waitpid` 收集子行程結束狀態：
  - 若子行程被信號殺死且終止信號為 `SIGKILL`（`WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL`），代表觸發了 SUSFS 核心防禦側信道。
  - 若子行程正常退出且退出狀態碼為 100（`WEXITSTATUS(status) == 100`），代表非預期地成功切換 UID，存在提權漏洞。

## 觸發代表什麼

- 若觀察到 `SIGKILL` 終止：判定為 STRONG（`strongObserved()`），代表偵測到 SUSFS 側信道。
- 若觀察到非預期的 UID 切換成功（退出碼 100）：判定為 STRONG，代表直接提權異常。
- 若子行程正常以 0 退出（`setresuid` 被拒，標準沙箱行為）：判定為 NOT_OBSERVED，`result` 記為「Normal behavior (setresuid refused)」。
- 若子行程被 `SIGKILL` 以外的其他信號終止（例如 `SIGSEGV`）：判定為 NOT_OBSERVED，但 `result` 據實記為「Anomalous child termination by signal N」，不再誤標為 EPERM。此前這種情形會被錯誤地標成「Normal behavior (EPERM)」。

不能推論的：
- **不能推論裝置安裝了所有版本的 SUSFS。** 新版 SUSFS 可能修正或調整了防禦行為。
- **不能推論是特定的惡意軟體。** 此特徵為核心模組之防禦機制，非惡意攻擊載荷本身。

## 已知偽陽性來源

- **系統 OOM Killer 或 LMK 殺除子行程**（`native_root_susfs.cpp` 第 72-76 行）：在記憶體極度緊張的極端環境下，fork 出的子行程若在執行 `setresuid` 前後恰好被 Linux 核心的 Out-Of-Memory (OOM) Killer 或 Android Low Memory Killer Daemon (lmkd) 發送 `SIGKILL` 終止，父行程會將此 `SIGKILL` 誤判為 SUSFS 觸發。
- **嚴格沙盒或 Seccomp 規則以 SIGKILL 懲罰未授權系統呼叫**（`native_root_susfs.cpp` 第 54-55、72 行）：某些企業級 MDM、安全容器或特定定製 ROM 的 Seccomp filter 若對 `setresuid` 設置了 `SECCOMP_RET_KILL_PROCESS`（直接殺除進程而非回傳 EPERM），亦會導致子行程被 SIGKILL 終止從而產生偽陽性。

## 看不到什麼

- **修正此側信道的新版 SUSFS**：若 SUSFS 更新或客製編譯版本移除了殺除行程的行為，改為遵循標準 Linux 規範返回 `-EPERM`，此側信道 probe 將完全沉默。
- **未開啟 setresuid 攔截的配置**：若 SUSFS 在該裝置上僅啟用路徑隱藏（hide path / kstat spoofing）而未攔截 UID 切換，檢測器無法察覺。
- **阻擋 fork 的環境**：在無法執行 fork 的沙盒環境下，檢測將回傳 INCONCLUSIVE。

## 建議處置

| 強度 | 建議 |
|---|---|
| STRONG | 觀察到子行程在嘗試 `setresuid` 時被非正常的 `SIGKILL` 殺除，或是成功變更 UID，強烈指示核心層存在 SUSFS 補丁或提權通道。建議納入高風險決策。 |
| NOT_OBSERVED | 子行程的 `setresuid` 被正常拒絕（沙箱預期行為），未觸發 SUSFS 特徵信號；或子行程被非 SIGKILL 信號異常終止（據實記錄，非 SUSFS）。 |
| INCONCLUSIVE | 當前已為 root 身分、無法計算目標 UID、`fork()` 或 `waitpid()` 失敗，視為收集失敗。 |

## 成本

- 執行 1 次 `fork()` 建立子行程。
- 子行程執行 1 次 `setresuid` 系統呼叫並立即 `_exit`。
- 父行程執行 1 次 `waitpid` 同步等待（通常在微秒級完成）。
- 整合者不需要在 `AndroidManifest.xml` 中配置任何權限或設定。

## Evidence units

### native-root-susfs.child-signal

記錄子行程在執行 `setresuid` 探測時的終止行為與信號特徵。包含當前行程 UID、探測目標 UID、子行程的 waitpid 狀態（正常拒絕、`SIGKILL`、異常成功退出碼 100，或其他信號）、以及對應的 SUSFS 判讀結果（`result` 字串據實反映實際終止方式）。
