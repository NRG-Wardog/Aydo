#include <ntdef.h>

#include "Communications.hpp"
#include "Constants.hpp"
#include "Logger.hpp"
#include "ServiceProtection.hpp"
#include "Utils.hpp"
#include "ntifs.h"

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
VOID DriverUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(RegistryPath);

  LOG_INFO("Loading driver...");

  NTSTATUS status;
  PDEVICE_OBJECT DeviceObject = nullptr;
  UNICODE_STRING deviceName, symlinkName;

  RtlInitUnicodeString(&deviceName, Constants::DEVICE_NAME);
  RtlInitUnicodeString(&symlinkName, Constants::SYMLINK_NAME);

  status = IoCreateDevice(
      DriverObject,
      0,
      &deviceName,
      FILE_DEVICE_UNKNOWN,
      FILE_DEVICE_SECURE_OPEN,
      FALSE,
      &DeviceObject);
  CHECK_NT_RETURN(status, "Failed to create device object (0x%X)", status);

  status = IoCreateSymbolicLink(&symlinkName, &deviceName);
  CHECK_NT_RETURN_CLEANUP(status, IoDeleteDevice(DeviceObject), "Failed to create symbolic link (0x%X)", status);

  DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
  DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Communications::handleDeviceControl;

  status = ServiceProtection::registerProcessProtection();
  CHECK_NT_RETURN_CLEANUP(status,
      (IoDeleteSymbolicLink(&symlinkName), IoDeleteDevice(DeviceObject)),
      "Failed to register process protection (0x%X)", status);

  LOG_INFO("Setup process protection (not ready yet)");

  status = ServiceProtection::registerRegistryProtection(DriverObject);
  CHECK_NT_RETURN_CLEANUP(status,
      (ServiceProtection::unregisterProcessProtection(), IoDeleteSymbolicLink(&symlinkName), IoDeleteDevice(DeviceObject)),
      "Failed to register registry protection (0x%X)", status);

  LOG_INFO("Setup registry protection");

  status = Utils::initializeProcessNotifications();
  CHECK_NT_RETURN_CLEANUP(status,
      (ServiceProtection::unregisterRegistryProtection(), ServiceProtection::unregisterProcessProtection(),
       IoDeleteSymbolicLink(&symlinkName), IoDeleteDevice(DeviceObject)),
      "Failed to initialize process notifications (0x%X)", status);

  // Only allow unloading in debug mode
#if defined(DBG) // TODO: remove this
  DriverObject->DriverUnload = DriverUnload;
  LOG_INFO("Driver loaded successfully (debug mode - unloading allowed)");
#else
  DriverObject->DriverUnload = nullptr;
  LOG_INFO("Driver loaded successfully (release mode - unloading disabled)");
#endif

  return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
  UNICODE_STRING symlinkName;

  LOG_INFO("Unloading driver...");

  // Cleanup service protection callbacks first
  ServiceProtection::unregisterProcessProtection();
  ServiceProtection::unregisterRegistryProtection();

  // Cleanup process notifications
  Utils::cleanupProcessNotifications();

  RtlInitUnicodeString(&symlinkName, Constants::SYMLINK_NAME);

  IoDeleteSymbolicLink(&symlinkName);

  if (DriverObject->DeviceObject) {
    IoDeleteDevice(DriverObject->DeviceObject);
  }

  LOG_INFO("Driver unloaded successfully");
}
NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
  UNREFERENCED_PARAMETER(DeviceObject);

  Irp->IoStatus.Status = STATUS_SUCCESS;
  Irp->IoStatus.Information = 0;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  return STATUS_SUCCESS;
}
