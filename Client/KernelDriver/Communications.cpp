#include "Communications.hpp"
#include <ntdef.h>
#include <ntstatus.h>

#include <ntifs.h>
#include <wdm.h>
#include "../IOCTLs.hpp"
#include "Constants.hpp"
#include "Logger.hpp"
#include "ServiceProtection.hpp"
#include "Types.hpp"
#include "Utils.hpp"
#include "Validation.hpp"

extern "C" PUCHAR PsGetProcessImageFileName(PEPROCESS Process);

namespace Communications {

NTSTATUS handleKillProcessRequest(PIRP Irp) {
  IOCTL_KILL_PROCESS_INPUT *input = nullptr;
  NTSTATUS status = Validation::validateInputBuffer(Irp, &input);
  CHECK_NT_RETURN(status, "Invalid input buffer for IOCTL_KILL_PROCESS (0x%X)", status);

  LOG_INFO("Received IOCTL_KILL_PROCESS for PID: %lu", input->ProcessId);

  if (!Utils::isProcessKillable(input->ProcessId)) {
    LOG_ERROR("Process by PID: %lu is not killable (protected or critical)", input->ProcessId);
    return STATUS_ACCESS_DENIED;
  }

  status = Utils::killProcessByPID(input->ProcessId);
  CHECK_NT_RETURN(status, "Failed to kill process PID: %lu (0x%X)", input->ProcessId, status);

  LOG_INFO("Successfully killed process PID: %lu", input->ProcessId);
  return status;
}

NTSTATUS handleGetProcessNotificationRequest(PIRP Irp, ULONG *BytesReturned) {
  IOCTL_GET_PROCESS_NOTIFICATION_OUTPUT *output = nullptr;
  PPROCESS_NOTIFICATION notification = nullptr;
  NTSTATUS status = Validation::validateOutputBuffer(Irp, &output);
  CHECK_NT_RETURN(status, "Invalid output buffer for IOCTL_GET_PROCESS_NOTIFICATION (0x%X)", status);

  notification = (PPROCESS_NOTIFICATION)Utils::dequeueProcessNotification();

  if (notification == nullptr) {
    *BytesReturned = 0;

    return STATUS_NO_MORE_ENTRIES;
  }

  // Copy the notification to the output buffer
  output->ProcessId = notification->ProcessId;
  output->ParentProcessId = notification->ParentProcessId;
  output->IsCreated = notification->IsCreated;
  RtlCopyMemory(output->ImageFileName, notification->ImageFileName, sizeof(notification->ImageFileName));
  RtlCopyMemory(output->CommandLine, notification->CommandLine, sizeof(notification->CommandLine));

  // Free the notification
  ExFreePoolWithTag(notification, 'nPrP');

  *BytesReturned = sizeof(IOCTL_GET_PROCESS_NOTIFICATION_OUTPUT);

  LOG_INFO("Sent process notification to client - PID: %lu, Created: %d",
           output->ProcessId, output->IsCreated);

  return STATUS_SUCCESS;
}

NTSTATUS handleRegisterService(PIRP Irp) {
  // Get the process and PID
  PEPROCESS process = IoGetRequestorProcess(Irp);
  if (!process) {
    return STATUS_INVALID_PARAMETER;
  }

  HANDLE pid = PsGetProcessId(process);

  const char *imageName = (const char *)PsGetProcessImageFileName(process);

  LOG_INFO("Request to register service from PID %lu", pid);

  if (_stricmp(imageName, Constants::EXPECTED_SERVICE_IMAGE) != 0) {
    return STATUS_ACCESS_DENIED;
  }

  LOG_INFO("Service is being registered from PID %lu (expected image: %s)", pid,
           Constants::EXPECTED_SERVICE_IMAGE);

  ServiceProtection::setServiceProcess(process);

  return STATUS_SUCCESS;
}

NTSTATUS handleGetProtectedPIDRequest(PIRP Irp, ULONG *BytesReturned) {
  HANDLE *output = nullptr;
  NTSTATUS status = Validation::validateOutputBuffer(Irp, &output);
  CHECK_NT_RETURN(status, "Invalid output buffer for IOCTL_GET_PROTECTED_PID (0x%X)", status);

  ServiceProtection::ProtectedServiceInfo info{};
  if (ServiceProtection::tryGetProtectedService(info)) {
    *output = info.pid;
  } else {
    *output = nullptr;
  }

  *BytesReturned = sizeof(HANDLE);

  LOG_DEBUG("Handled IOCTL_GET_PROTECTED_PID, returning PID: %lu",
            (ULONG)(ULONG_PTR)*output);

  return STATUS_SUCCESS;
}

NTSTATUS handleResumeProcessRequest(PIRP Irp) {
  IOCTL_RESUME_PROCESS_INPUT *input = nullptr;
  NTSTATUS status = Validation::validateInputBuffer(Irp, &input);
  CHECK_NT_RETURN(status, "Invalid input buffer for IOCTL_RESUME_PROCESS (0x%X)", status);

  status = Utils::resumeProcess(input->ProcessId);
  CHECK_NT_RETURN(status, "Failed to resume process %lu (0x%X)", input->ProcessId, status);

  LOG_INFO("Successfully resumed process %lu", input->ProcessId);
  return STATUS_SUCCESS;
}

NTSTATUS handleDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
  UNREFERENCED_PARAMETER(DeviceObject);

  PIO_STACK_LOCATION irpStack;
  NTSTATUS status = STATUS_SUCCESS;
  ULONG bytesReturned = 0;

  irpStack = IoGetCurrentIrpStackLocation(Irp);

  ULONG ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;

  switch (ioControlCode) {
  case IOCTL_KILL_PROCESS:
    status = handleKillProcessRequest(Irp);
    break;

  case IOCTL_GET_PROCESS_NOTIFICATION:
    status = handleGetProcessNotificationRequest(Irp, &bytesReturned);
    break;
  case IOCTL_REGISTER_SERVICE:
    status = handleRegisterService(Irp);
    break;
  case IOCTL_GET_PROTECTED_PID:
    status = handleGetProtectedPIDRequest(Irp, &bytesReturned);
    break;
  case IOCTL_RESUME_PROCESS:
    status = handleResumeProcessRequest(Irp);
    break;
  default:
    status = STATUS_INVALID_DEVICE_REQUEST;
    LOG_ERROR("Unknown IOCTL code: 0x%X", ioControlCode);
    break;
  }

  Irp->IoStatus.Status = status;
  Irp->IoStatus.Information = bytesReturned;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  return status;
}

} // namespace Communications
