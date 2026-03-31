#include "Hooks.hpp"

#include "Constants.hpp"
#include "Logger.hpp"
#include "ServiceProtection.hpp"
#include "Types.hpp"
#include "Utils.hpp"

namespace Hooks {

VOID onProcessStart(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
  UNREFERENCED_PARAMETER(Process);

  auto notification = (PPROCESS_NOTIFICATION)ExAllocatePoolZero(
      NonPagedPoolNx,
      sizeof(PROCESS_NOTIFICATION),
      'nPrP');

  if (notification == nullptr) {
    LOG_ERROR("Failed to allocate memory for process notification");

    return;
  }

  RtlZeroMemory(notification, sizeof(PROCESS_NOTIFICATION));

  // Fill in the notification data
  notification->ProcessId = HandleToULong(ProcessId);
  notification->IsCreated = (CreateInfo != nullptr);

  // Process is being created
  if (CreateInfo != nullptr) {
    // Suspend the process (ONLY IF OUR SERVICE IS RUNNING!!!!!!!!!!!!!!!!!!!!!!!!!!!!!)
    if(ServiceProtection::g_servicePID != nullptr) {
       Utils::suspendProcess(ProcessId);
    }

    notification->ParentProcessId = HandleToULong(CreateInfo->ParentProcessId);

    // Copy the image file name if available
    if (CreateInfo->ImageFileName != nullptr) {
      SIZE_T lengthToCopy = min(CreateInfo->ImageFileName->Length / sizeof(WCHAR), MAX_PATH - 1);
      RtlCopyMemory(
          notification->ImageFileName,
          CreateInfo->ImageFileName->Buffer,
          lengthToCopy * sizeof(WCHAR));
      notification->ImageFileName[lengthToCopy] = L'\0';
    } else {
      notification->ImageFileName[0] = L'\0';
    }

    // Copy the command line if available
    if (CreateInfo->CommandLine != nullptr && CreateInfo->CommandLine->Length > 0) {
      SIZE_T lengthToCopy = min(CreateInfo->CommandLine->Length / sizeof(WCHAR), MAX_COMMANDLINE - 1);
      RtlCopyMemory(
          notification->CommandLine,
          CreateInfo->CommandLine->Buffer,
          lengthToCopy * sizeof(WCHAR));
      notification->CommandLine[lengthToCopy] = L'\0';
    } else {
      notification->CommandLine[0] = L'\0';
    }

    // Deny execution if image path is under quarantine directory (best-effort)
    if (CreateInfo->ImageFileName != nullptr && CreateInfo->ImageFileName->Buffer != nullptr) {
      UNICODE_STRING quarantinePath;
      RtlInitUnicodeString(&quarantinePath, Constants::QUARANTINE_DIR_PATH);
      const UNICODE_STRING *imagePath = CreateInfo->ImageFileName;

      bool blocked = false;

      // First, check for absolute quarantine path prefix
      if (RtlPrefixUnicodeString(&quarantinePath, imagePath, TRUE)) {
        blocked = true;
      } else {
        // Fallback: search for "\\quarantine\\" fragment anywhere in the path
        UNICODE_STRING fragment;
        RtlInitUnicodeString(&fragment, Constants::QUARANTINE_DIR_FRAGMENT);

        for (USHORT offset = 0; offset + fragment.Length <= imagePath->Length; offset += sizeof(WCHAR)) {
          UNICODE_STRING window{};
          window.Buffer = imagePath->Buffer + (offset / sizeof(WCHAR));
          window.Length = fragment.Length;
          window.MaximumLength = fragment.Length;

          if (RtlEqualUnicodeString(&window, &fragment, TRUE)) {
            blocked = true;
            break;
          }
        }
      }

      if (blocked) {
        LOG_WARNING("Blocked execution from quarantine path: %wZ", imagePath);
        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
      }
    }

    LOG_INFO("Process created - PID: %lu, Parent: %lu, Image: %wZ, CommandLine: %wZ",
             notification->ProcessId,
             notification->ParentProcessId,
             CreateInfo->ImageFileName,
             CreateInfo->CommandLine);
  } else {
    // Process is being terminated
    notification->ParentProcessId = 0;
    notification->ImageFileName[0] = L'\0';
    notification->CommandLine[0] = L'\0';

    LOG_INFO("Process terminated - PID: %lu", notification->ProcessId);

    // Check if this is our protected service process
    ServiceProtection::ProtectedServiceInfo info{};
    if (ServiceProtection::tryGetProtectedService(info) &&
        info.process != nullptr && Process == info.process) {
      LOG_WARNING("Protected service process (PID: %lu) terminated unexpectedly!",
                  HandleToULong(ProcessId));
      ServiceProtection::clearServiceProcess();
    }
  }

  // Add to queue
  Utils::enqueueProcessNotification(notification);
}

} // namespace Hooks