#ifndef TAMPERPROBE_MEMORY_LINKER_VISIBILITY_H
#define TAMPERPROBE_MEMORY_LINKER_VISIBILITY_H

#include <cstdint>
#include <vector>

#include "../../common/proc_maps.h"

namespace tamperprobe {

// Pure range-coverage seam shared by the live linker detector and native fixtures.
bool linkerRangeCoveredByMaps(std::uintptr_t start, std::uintptr_t end,
                              const std::vector<ProcMapEntry>& maps);

}  // namespace tamperprobe

#endif  // TAMPERPROBE_MEMORY_LINKER_VISIBILITY_H
