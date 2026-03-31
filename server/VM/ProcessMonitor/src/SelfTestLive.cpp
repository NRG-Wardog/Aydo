#include "pch.h"
#include "SelfTest.hpp"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>

#include "Deadline.hpp"
#include "SelfTestLiveConstants.hpp"
#include "UserBlock.hpp"

int RunProcessMonitorLiveSelfTest() {
  std::atomic_uint64_t eventCount{0};
  UserBlock userBlock{std::wstring(SelfTestLiveConstants::SESSION_NAME)};
  userBlock.addAnalystProviders(SelfTestLiveConstants::TRACE_LEVEL,
                                SelfTestLiveConstants::ANY_MASK,
                                SelfTestLiveConstants::ALL_MASK);

  const UserProviderEnableStats statsBeforeStart = userBlock.getProviderEnableStats();
  userBlock.start([&eventCount](const EVENT_RECORD &, const krabs::trace_context &) {
    eventCount.fetch_add(1, std::memory_order_relaxed);
  });

  std::this_thread::sleep_for(SelfTestLiveConstants::CAPTURE_DURATION);
  const auto stopDeadline = Deadline(std::chrono::steady_clock::now() + SelfTestLiveConstants::STOP_GRACE);
  const bool stoppedGracefully = userBlock.stopWithDeadline(stopDeadline);
  const UserProviderEnableStats statsAfterStart = userBlock.getProviderEnableStats();

  std::wcout << L"[self-test-live] providers requested=" << statsBeforeStart.requested
             << L" resolved=" << statsBeforeStart.resolved
             << L" unresolved=" << statsBeforeStart.unresolved
             << L" enabled=" << statsAfterStart.enabled
             << L" failed_enable=" << statsAfterStart.failed_enable
             << L" events=" << eventCount.load(std::memory_order_relaxed)
             << std::endl;

  if (!stoppedGracefully) {
    std::wcerr << L"[self-test-live] stopWithDeadline failed" << std::endl;
    return EXIT_FAILURE;
  }

  if (statsBeforeStart.requested == 0 || statsBeforeStart.resolved == 0 || statsAfterStart.enabled == 0) {
    std::wcerr << L"[self-test-live] insufficient provider enablement" << std::endl;
    return EXIT_FAILURE;
  }

  std::wcout << L"[self-test-live] PASS" << std::endl;
  return EXIT_SUCCESS;
}
