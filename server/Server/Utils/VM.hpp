#pragma once

#include <string>

namespace Utils::VM {
bool startVM(const std::string &sandboxId, const std::string &payloadPath, unsigned int runtimeSeconds);
}
