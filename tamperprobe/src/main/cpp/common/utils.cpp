#include "utils.h"

#include <android/log.h>
#include <dlfcn.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>

#include "log.h"

// Global variable to store app's files directory path
std::pair<bool, std::string> readFileFromOrphanProcess(const char* file_path) {
    std::string details;

    // 建立 pipe 用於通訊
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        details = "❌ 無法建立 pipe: " + std::string(strerror(errno));
        return {false, details};
    }

    pid_t pid = fork();
    if (pid < 0) {
        details = "❌ Fork 失敗: " + std::string(strerror(errno));
        close(pipefd[0]);
        close(pipefd[1]);
        return {false, details};
    }

    if (pid == 0) {
        // === 子 process ===
        close(pipefd[0]);  // 關閉讀取端

        // 再次 fork 產生孤兒 process
        pid_t grandchild = fork();
        if (grandchild > 0) {
            // 第一個子 process 立即退出
            _exit(0);
        } else if (grandchild < 0) {
            close(pipefd[1]);
            _exit(1);
        }

        // === 孫 process (孤兒，PPID=1) ===
        char buffer[8192];
        int offset = 0;

        // 確保成為孤兒 (PPID = 1)
        pid_t original_ppid = getppid();
        kill(original_ppid, SIGKILL);

        // 等待 kernel reparent
        for (int i = 0; i < 100; ++i) {
            if (getppid() == 1) break;
            usleep(1000);
        }

        // 讀取指定的檔案
        FILE* file = fopen(file_path, "r");
        if (file) {
            char line[256];
            while (fgets(line, sizeof(line), file) && offset < sizeof(buffer) - 256) {
                offset += snprintf(buffer + offset, sizeof(buffer) - offset, "%s", line);
            }
            fclose(file);
        } else {
            offset += snprintf(buffer + offset, sizeof(buffer) - offset, "❌ 無法開啟檔案: %s (errno: %d - %s)\n",
                               file_path, errno, strerror(errno));
        }

        // 確保不會超過 buffer
        if (offset >= sizeof(buffer) - 1) {
            offset = sizeof(buffer) - 1;
        }

        // 寫入 pipe 並立即退出
        ssize_t written = write(pipefd[1], buffer, offset);
        close(pipefd[1]);
        _exit(written > 0 ? 0 : 1);
    }

    // === 父 process ===
    close(pipefd[1]);  // 關閉寫入端

    // 設置讀取超時 (1 秒)
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(pipefd[0], &readfds);

    // 等待第一個子 process (會立即退出)
    int status;
    pid_t wait_result = waitpid(pid, &status, WNOHANG);
    if (wait_result == 0) {
        usleep(10000);  // 10ms
        waitpid(pid, &status, 0);
    }

    // 使用 select 實現超時讀取
    int select_result = select(pipefd[0] + 1, &readfds, NULL, NULL, &timeout);

    char result[8192];
    ssize_t n = 0;

    if (select_result > 0) {
        n = read(pipefd[0], result, sizeof(result) - 1);
    } else if (select_result == 0) {
        details = "⚠️ 讀取超時 (1秒)";
        close(pipefd[0]);
        return {false, details};
    } else {
        details = "❌ Select 錯誤: " + std::string(strerror(errno));
        close(pipefd[0]);
        return {false, details};
    }

    close(pipefd[0]);

    if (n > 0) {
        result[n] = '\0';
        details = std::string(result);
        return {true, details};
    } else if (n == 0) {
        details = "⚠️ Pipe 已關閉但無資料";
        return {false, details};
    } else {
        details = "❌ 讀取失敗: " + std::string(strerror(errno));
        return {false, details};
    }
}

std::pair<bool, std::string> readFile(const char* file_path) {
    std::ifstream file(file_path);
    if (!file.is_open()) {
        return {false, "❌ 無法開啟檔案: " + std::string(file_path) + " (" + strerror(errno) + ")"};
    }

    std::stringstream buffer;
    buffer << file.rdbuf();

    if (file.bad()) {
        return {false, "❌ 讀取檔案時發生錯誤: " + std::string(file_path)};
    }

    return {true, buffer.str()};
}

std::pair<bool, std::string> writeFile(const char* file_path, const std::string& content, bool append) {
    // 選擇開啟模式: 覆蓋 或 附加
    std::ios_base::openmode mode = append ? (std::ios::out | std::ios::app) : std::ios::out;

    std::ofstream file(file_path, mode);
    if (!file.is_open()) {
        std::string error = "❌ 無法開啟檔案: " + std::string(file_path) + " (" + strerror(errno) + ")";
        return {false, error};
    }

    file << content;

    if (file.bad()) {
        std::string error = "❌ 寫入檔案時發生錯誤: " + std::string(file_path);
        file.close();
        return {false, error};
    }

    file.close();
    return {true, ""};
}



void logLargeText(const char* tag, int priority, const char* title, const std::string& content, size_t maxChunkSize) {
    // 分段輸出到 Logcat (避免 4KB 限制，且保持完整行)
    std::vector<std::string> chunks;

    size_t pos = 0;
    while (pos < content.length()) {
        size_t chunkEnd = pos + maxChunkSize;

        // 如果還沒到結尾，尋找下一個換行符
        if (chunkEnd < content.length()) {
            size_t newlinePos = content.find('\n', chunkEnd);
            if (newlinePos != std::string::npos) {
                chunkEnd = newlinePos + 1;  // 包含換行符
            } else {
                // 如果找不到換行符，就用剩餘的全部內容
                chunkEnd = content.length();
            }
        } else {
            chunkEnd = content.length();
        }

        chunks.push_back(content.substr(pos, chunkEnd - pos));
        pos = chunkEnd;
    }

    // 輸出標題和統計資訊
    __android_log_print(priority, tag, "=== %s (共 %zu 字元，分 %zu 段) ===", title, content.length(), chunks.size());

    // 逐段輸出
    for (size_t i = 0; i < chunks.size(); ++i) {
        __android_log_print(priority, tag, "[第 %zu/%zu 段]\n%s", i + 1, chunks.size(), chunks[i].c_str());
    }

    // 輸出結束標記
    __android_log_print(priority, tag, "=== %s 輸出完成 ===", title);
}

// 便捷函式實作 - 使用專案預設的 LOG_TAG
void logLargeTextV(const char* title, const std::string& content, size_t maxChunkSize) {
    logLargeText(LOG_TAG, ANDROID_LOG_VERBOSE, title, content, maxChunkSize);
}

void logLargeTextD(const char* title, const std::string& content, size_t maxChunkSize) {
    logLargeText(LOG_TAG, ANDROID_LOG_DEBUG, title, content, maxChunkSize);
}

void logLargeTextI(const char* title, const std::string& content, size_t maxChunkSize) {
    logLargeText(LOG_TAG, ANDROID_LOG_INFO, title, content, maxChunkSize);
}

void logLargeTextW(const char* title, const std::string& content, size_t maxChunkSize) {
    logLargeText(LOG_TAG, ANDROID_LOG_WARN, title, content, maxChunkSize);
}
