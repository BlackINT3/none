#include <ntifs.h>
#include "../knone/knone.h"

#define NT_DEVICE_NAME              L"\\Device\\KNONE_TEST"
#define DOS_DEVICE_NAME             L"\\DosDevices\\KNONE_TEST"

NTSTATUS DriverEntry(PDRIVER_OBJECT drvobj, PUNICODE_STRING registry)
{
	NTSTATUS status;
	UNICODE_STRING devname, symlnk;
	RtlInitUnicodeString(&devname, NT_DEVICE_NAME);
	RtlInitUnicodeString(&symlnk, DOS_DEVICE_NAME);

	DbgPrint("Hello");
	KNONE::TmSleepV1(1000 * 5);
	DbgPrint("World");
	KNONE::TmSleepV1(1000 * 5);
	DbgPrint("AAA");
	status = STATUS_SUCCESS;
	return status;
}