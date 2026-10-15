#include <cerrno>
#include <csignal>
#include <sstream>
#include <string>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "../../nlohmann/json.hpp"

namespace tamperprobe {

/**
 * Detects SUSFS (KernelSU's filesystem hiding module) via a side-channel:
 * fork a child process that attempts setresuid to a different UID.
 * SUSFS intercepts this syscall and kills the child with SIGKILL
 * instead of the normal EPERM failure.
 *
 * References: Duck-Detector nativeroot/probes/susfs_probe.cpp
 */
class NativeRootSusfsDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& scanContext) override {
        nlohmann::json payload;

        uid_t currentUid = getuid();
        if (currentUid == 0) {
            payload["collectionError"] = "Running as root, skipped";
            return {DetectionAssessment::inconclusive(), payload.dump()};
        }

        uid_t targetUid = 0;
        if (currentUid >= 10000) {
            targetUid = currentUid > 10000 ? 10000 : static_cast<uid_t>(currentUid - 1);
        } else if (currentUid > 0) {
            targetUid = static_cast<uid_t>(currentUid - 1);
        }
        if (targetUid >= currentUid) {
            payload["collectionError"] = "Cannot compute target UID";
            return {DetectionAssessment::inconclusive(), payload.dump()};
        }

        pid_t pid = fork();
        if (pid < 0) {
            payload["collectionError"] = "fork() failed";
            return {DetectionAssessment::inconclusive(), payload.dump()};
        }

        if (pid == 0) {
            // Child: attempt UID change
            long result = syscall(__NR_setresuid, targetUid, targetUid, targetUid);
            _exit(result == 0 ? 100 : 0);
        }

        // Parent: wait for child
        int status = 0;
        if (waitpid(pid, &status, 0) < 0) {
            payload["collectionError"] = "waitpid() failed";
            return {DetectionAssessment::inconclusive(), payload.dump()};
        }

        std::ostringstream detail;
        detail << "Current UID " << currentUid << ", attempted setresuid(" << targetUid << ").";
        payload["currentUid"] = static_cast<int>(currentUid);
        payload["targetUid"] = static_cast<int>(targetUid);

        DetectionAssessment assessment = DetectionAssessment::notObserved();

        if (WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL) {
            assessment = DetectionAssessment::strongObserved();
            detail << " Child was killed by SIGKILL instead of returning EPERM.";
            payload["result"] = "SIGKILL — SUSFS side-channel detected";
            payload["susfsDetected"] = true;
        } else if (WIFEXITED(status) && WEXITSTATUS(status) == 100) {
            assessment = DetectionAssessment::strongObserved();
            detail << " Child unexpectedly changed UID successfully.";
            payload["result"] = "Unexpected UID change — privilege escalation detected";
            payload["susfsDetected"] = false;
        } else if (WIFEXITED(status)) {
            // Child exited 0: setresuid returned non-zero, the normal sandboxed refusal.
            detail << " Child's setresuid was refused, as expected in the sandbox.";
            payload["result"] = "Normal behavior (setresuid refused)";
            payload["susfsDetected"] = false;
        } else if (WIFSIGNALED(status)) {
            // Terminated by a signal other than SIGKILL (for example SIGSEGV). Not the
            // SUSFS side channel, but not the EPERM path either, so do not mislabel it.
            detail << " Child terminated by signal " << WTERMSIG(status)
                   << ", which is neither SIGKILL nor a normal exit.";
            payload["result"] =
                "Anomalous child termination by signal " + std::to_string(WTERMSIG(status));
            payload["susfsDetected"] = false;
        } else {
            payload["result"] = "Unknown child termination";
            payload["susfsDetected"] = false;
        }

        payload["detail"] = detail.str();

        return {assessment, payload.dump()};
    }

    const char* getId() const override { return "NATIVE_ROOT_SUSFS"; }
};

REGISTER_DETECTION(NativeRootSusfsDetection);

}  // namespace tamperprobe
