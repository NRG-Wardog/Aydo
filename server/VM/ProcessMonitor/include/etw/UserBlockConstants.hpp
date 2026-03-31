#pragma once

#include <cstddef>

namespace UserBlockConstants {
inline constexpr long long MIN_WAIT_MS = 0;
inline constexpr long long MAX_WAIT_MS = 0x7fffffff;
inline constexpr const char *TIMEOUT_DETACH_MSG = "UserBlock: trace thread did not stop before deadline; detaching\n";
inline constexpr const char *SYSMON_UNAVAILABLE_MSG = "UserBlock: provider 'Microsoft-Windows-Sysmon' not found; skipping\n";
inline constexpr std::size_t PROVIDER_ENABLE_LOG_LIMIT = 32;
} // namespace UserBlockConstants
