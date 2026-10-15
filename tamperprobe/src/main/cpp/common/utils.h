#ifndef TAMPERPROBE_UTILS_H
#define TAMPERPROBE_UTILS_H

#include <string>
#include <utility>

std::pair<bool, std::string> readFileFromOrphanProcess(const char* file_path);

std::pair<bool, std::string> readFile(const char* file_path);

std::pair<bool, std::string> writeFile(const char* file_path, const std::string& content, bool append = false);

std::pair<bool, std::string> checkFunctionPrologue(const char* lib_name, const char* func_name, size_t num_bytes = 16);

void logLargeText(const char* tag, int priority, const char* title,
                  const std::string& content, size_t maxChunkSize = 3000);

void logLargeTextV(const char* title, const std::string& content, size_t maxChunkSize = 3000);

void logLargeTextD(const char* title, const std::string& content, size_t maxChunkSize = 3000);

void logLargeTextI(const char* title, const std::string& content, size_t maxChunkSize = 3000);

void logLargeTextW(const char* title, const std::string& content, size_t maxChunkSize = 3000);

#endif // TAMPERPROBE_UTILS_H
