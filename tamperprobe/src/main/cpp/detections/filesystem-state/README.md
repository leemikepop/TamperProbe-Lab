# Filesystem State Evidence Domain

This directory is the primary source owner for `RW_PATHS`, `MOUNT_INTEGRITY`, and
`NATIVE_ROOT_PATHS`. Each co-located sidecar owns its unit `domainId`; detector-level source
ownership remains `filesystem-state`.

## 檢測項目

### 可讀寫路徑檢查 (`rw_paths.cpp`)
- **原理**: 嘗試檢查一系列系統關鍵目錄與檔案（例如 `/system`, `/vendor`, `/data/local/tmp` 等），判定其是否具有不應該出現的讀取或寫入權限。
- **目的**:
  - 正常的 Android 系統中，許多底層分區（如 `/system`）應該是唯讀的 (Read-Only)。
  - 如果檢測發現這些分區變成了可讀寫 (`rw`) 狀態，通常意味著設備已經被 Root 並且解鎖了系統分區的寫入權限，以便寫入修改檔案。

### Mount consistency (`mount_integrity.cpp`)

The detector parses `/proc/self/mountinfo`, compares visible mount IDs with `statx`, compares
filesystem types with `statfs`, and scans mount source/target/type/options. Framework-specific
markers and cross-channel contradictions support findings; visible OverlayFS, namespace data, and
mount-ID sequence gaps remain Research data. If `statx` is unavailable, the detector records a
unit issue and continues the other channels. An app-local mount view can be filtered, so a
clean result is not proof that no hidden mount exists.

### Root-framework paths (`native_root_paths.cpp`)

Fixed Magisk, KernelSU, APatch, and shared `/data/adb` candidates are probed with `stat`, `lstat`,
and `O_PATH`. Provider-specific paths can support stronger evidence; shared roots remain weak and
do not prove that privilege escalation succeeds. Sandbox visibility and coordinated VFS filtering
bound both positive attribution and clean inference.
