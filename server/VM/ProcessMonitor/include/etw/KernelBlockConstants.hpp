#pragma once

namespace KernelBlockConstants {
inline constexpr long long MIN_WAIT_MS = 0;
inline constexpr long long MAX_WAIT_MS = 0x7fffffff;
inline constexpr const char *TIMEOUT_DETACH_MSG = "KernelBlock: trace thread did not stop before deadline; detaching\n";
} // namespace KernelBlockConstants
