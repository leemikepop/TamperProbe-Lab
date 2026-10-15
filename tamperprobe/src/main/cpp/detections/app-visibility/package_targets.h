#ifndef TAMPERPROBE_PACKAGE_TARGETS_H
#define TAMPERPROBE_PACKAGE_TARGETS_H

#include <string>
#include <vector>

#include "../../core/detection.h"

namespace tamperprobe {

struct PackageIntentRule {
    std::string packageName;
    std::string action;
};

bool collectTargetPackageNames(const DetectionContext& context, std::vector<std::string>& targetPackageNames);
bool collectPackageIntentRules(const DetectionContext& context, std::vector<PackageIntentRule>& intentRules);

}  // namespace tamperprobe

#endif  // TAMPERPROBE_PACKAGE_TARGETS_H
