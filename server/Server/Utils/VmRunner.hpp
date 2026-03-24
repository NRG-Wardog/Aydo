#pragma once

#include <filesystem>
#include <string>

namespace Utils::VmRunner {

[[nodiscard]] bool startVm(const std::string &sandboxId,
                           const std::filesystem::path &payloadHostPath,
                           int runtimeSeconds);

void warmUpPoolAsync();

} // namespace Utils::VmRunner
