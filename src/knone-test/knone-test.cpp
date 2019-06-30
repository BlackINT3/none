#include <ntifs.h>
#include "../knone/knone.h"

#define KNONETEST_NTDEVICE_NAME L"\\Device\\KNONETEST"
#define KNONETEST_DOSDEVICE_NAME L"\\DosDevices\\KNONETEST"

extern "C" {
NTSTATUS DriverEntry(PDRIVER_OBJECT drvobj, PUNICODE_STRING registry);
NTSTATUS MainDispatcher(PDEVICE_OBJECT devobj, PIRP irp);
NTSTATUS DefaultDispatcher(PDEVICE_OBJECT devobj, PIRP irp);
VOID DriverUnload(PDRIVER_OBJECT drvobj);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drvobj, PUNICODE_STRING registry)
{
	NTSTATUS status;
	UNICODE_STRING devname, symlnk;
	PDEVICE_OBJECT devobj;

	UNREFERENCED_PARAMETER(registry);
	KdPrint(("OpenArkDrv loading..."));

	RtlInitUnicodeString(&devname, KNONETEST_NTDEVICE_NAME);
	RtlInitUnicodeString(&symlnk, KNONETEST_DOSDEVICE_NAME);

	status = IoCreateDevice(drvobj,
													0,
													&devname,
													FILE_DEVICE_UNKNOWN,
													FILE_DEVICE_SECURE_OPEN,
													FALSE,
													&devobj);
	if (!NT_SUCCESS(status)) {
		KdPrint(("IoCreateDevice err:%x", status));
		return status;
	}

	drvobj->DriverUnload = DriverUnload;
	drvobj->MajorFunction[IRP_MJ_CREATE] = DefaultDispatcher;
	drvobj->MajorFunction[IRP_MJ_CLOSE] = DefaultDispatcher;
	drvobj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MainDispatcher;

	status = IoCreateSymbolicLink(&symlnk, &devname);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(devobj);
		KdPrint(("IoCreateSymbolicLink err:%x", status));
		return status;
	}

	status = STATUS_SUCCESS;
	return status;
}

NTSTATUS MainDispatcher(PDEVICE_OBJECT devobj, PIRP irp)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PIO_STACK_LOCATION	irpstack;
	PVOID inbuf = NULL;
	PVOID outbuf = NULL;
	ULONG inlen = 0;
	ULONG outlen = 0;
	ULONG ctlcode = 0;
	ULONG ops = 0;

	irpstack = IoGetCurrentIrpStackLocation(irp);
	ctlcode = irpstack->Parameters.DeviceIoControl.IoControlCode;

	switch (ctlcode) {
	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}
	irp->IoStatus.Status = status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS DefaultDispatcher(PDEVICE_OBJECT devobj, PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT drvobj)
{
	UNICODE_STRING symlnk;
	PDEVICE_OBJECT dev = drvobj->DeviceObject;
	if (dev) {
		RtlInitUnicodeString(&symlnk, KNONETEST_DOSDEVICE_NAME);
		IoDeleteSymbolicLink(&symlnk);
		IoDeleteDevice(dev);
	}
}