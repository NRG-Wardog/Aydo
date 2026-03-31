#include "ProviderProfiles.hpp"

namespace ProviderProfiles {

const std::array<const wchar_t *, ANALYST_USER_PROVIDER_COUNT> &getAnalystUserProviders() {
  return ANALYST_USER_PROVIDERS;
}

bool isForbiddenProvider(std::wstring_view providerName) {
  return providerName.find(L"Sysmon") != std::wstring_view::npos ||
         providerName.find(L"sysmon") != std::wstring_view::npos;
}

} // namespace ProviderProfiles

