#include "Communication.hpp"
#include "Utils.hpp"

NTSTATUS Communication::DriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
  UNREFERENCED_PARAMETER(DeviceObject);

  Irp->IoStatus.Status = STATUS_SUCCESS;
  Irp->IoStatus.Information = 0;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  return STATUS_SUCCESS;
}

// This is called when a message is sent to our driver
NTSTATUS Communication::DriverDeviceControl(PDEVICE_OBJECT, PIRP Irp) {
  // Stack (memory) for our arguments
  auto stack = IoGetCurrentIrpStackLocation(Irp);
  auto status = STATUS_SUCCESS;

  KdPrint(("DriverDeviceControl called with IoControlCode %x\n", stack->Parameters.DeviceIoControl.IoControlCode));

  auto stackLen = stack->Parameters.DeviceIoControl.InputBufferLength;

  switch (stack->Parameters.DeviceIoControl.IoControlCode) {
  case IOCTL_KILL_PROCESS: {
    KdPrint(("IOCTL_KILL_PROCESS called with stackLen %d\n", stackLen));
    // Is this a valid kill request?
    if (stackLen < sizeof(KillProcessRequest)) {
      KdPrint(("Invalid parameter length\n"));
      status = STATUS_INVALID_PARAMETER;
      break;
    }
    KdPrint(("Valid kill request received (size %d)\n", stackLen));

    // Check again to make sure the buffer is valid
    auto killProcessRequest = (KillProcessRequest *)stack->Parameters.DeviceIoControl.Type3InputBuffer;
    if (killProcessRequest == nullptr) {
      KdPrint(("Invalid parameter\n"));
      status = STATUS_INVALID_PARAMETER;
      break;
    }
    KdPrint(("Valid kill request received\n"));

    ULONG _targetPID = killProcessRequest->TargetPID;
    if (!Utils::KillProcess(_targetPID)) {
      KdPrint(("Failed to kill process %d\n", _targetPID));
      status = STATUS_UNSUCCESSFUL;
      break;
    }
    KdPrint(("Process %d killed successfully\n", _targetPID));

    break;
  }
  default:
    status = STATUS_INVALID_DEVICE_REQUEST;
    break;
  }

  Irp->IoStatus.Status = status;
  Irp->IoStatus.Information = 0;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  return status;
}
