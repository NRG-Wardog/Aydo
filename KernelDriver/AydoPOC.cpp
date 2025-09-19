#include "Communication.hpp"
#include "wdm.h"
#include <bcrypt.h>
#include <ntdef.h>

void TestUnload(_In_ PDRIVER_OBJECT DriverObject) {
  UNREFERENCED_PARAMETER(DriverObject);
  KdPrint(("Sample driver Unload called\n"));

  UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\AydoPOC");
  IoDeleteSymbolicLink(&symLink);
  IoDeleteDevice(DriverObject->DeviceObject);
}

extern "C" NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(RegistryPath);

	KdPrint(("Sample driver Load called\n"));

  // When we unload, use this function
  DriverObject->DriverUnload = TestUnload;

  DriverObject->MajorFunction[IRP_MJ_CREATE] = Communication::DriverCreateClose;
  DriverObject->MajorFunction[IRP_MJ_CLOSE] = Communication::DriverCreateClose;
  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Communication::DriverDeviceControl;

  UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\AydoPOC");
  PDEVICE_OBJECT DeviceObject;

  NTSTATUS status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
  if (!NT_SUCCESS(status)) {
		KdPrint(("IoCreateDevice failed with status 0x%08x\n", status));
    return status;
  }
	KdPrint(("IoCreateDevice success\n"));

  UNICODE_STRING SymbolicLinkName = RTL_CONSTANT_STRING(L"\\??\\AydoPOC");
  status = IoCreateSymbolicLink(&SymbolicLinkName, &DeviceName);
  if (!NT_SUCCESS(status)) {
		KdPrint(("IoCreateSymbolicLink failed with status 0x%08x\n", status));
    IoDeleteDevice(DeviceObject);
    return status;
  }
	KdPrint(("IoCreateSymbolicLink success\n"));

	KdPrint(("Sample driver Loaded\n"));

  return STATUS_SUCCESS;
}
