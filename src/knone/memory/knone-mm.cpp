/****************************************************************************
**
** Copyright (C) 2019 BlackINT3
** Contact: https://github.com/BlackINT3/none
**
** GNU Lesser General Public License Usage (LGPL)
** Alternatively, this file may be used under the terms of the GNU Lesser
** General Public License version 2.1 or version 3 as published by the Free
** Software Foundation and appearing in the file LICENSE.LGPLv21 and
** LICENSE.LGPLv3 included in the packaging of this file. Please review the
** following information to ensure the GNU Lesser General Public License
** requirements will be met: https://www.gnu.org/licenses/lgpl.html and
** http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html.
**
****************************************************************************/
#include "knone-mm.h"
#include <os/knone-os.h>
#include <internal/knone-assist.h>

namespace KNONE {
	
VOID MmEnableWP()
{
	return __MmEnableWP();
}

VOID MmDisableWP()
{
	return __MmDisableWP();
}

VOID MmWriteProtectOn(IN KIRQL Irql)
{
	return __MmWriteProtectOn(Irql);
}

KIRQL MmWriteProtectOff()
{
	return __MmWriteProtectOff();
}

#ifndef MM_COPY_MEMORY_VIRTUAL
#define MM_COPY_MEMORY_VIRTUAL 0x2
#endif
#ifndef _MM_COPY_ADDRESS
typedef struct _MM_COPY_ADDRESS {
	union {
		PVOID VirtualAddress;
		PHYSICAL_ADDRESS PhysicalAddress;
	};
} MM_COPY_ADDRESS, *PMMCOPY_ADDRESS;
#endif
typedef NTSTATUS(NTAPI *__MmCopyMemory)(
	PVOID TargetAddress,
	MM_COPY_ADDRESS SourceAddress,
	SIZE_T NumberOfBytes,
	ULONG Flags,
	PSIZE_T NumberOfBytesTransferred
);

BOOLEAN MmReadKernelMemory(PVOID addr, PVOID buf, ULONG len)
{
	BOOLEAN ret = FALSE;
	if (OsNtVersion() >= NTOS_WIN81) {
		PVOID data = ExAllocatePool(NonPagedPool, len);
		if (data) {
			auto pMmCopyMemory = (__MmCopyMemory)MmGetRoutineAddress(L"MmCopyMemory");
			if (pMmCopyMemory) {
				SIZE_T cplen;
				MM_COPY_ADDRESS cpaddr;
				cpaddr.VirtualAddress = addr;
				NTSTATUS status = pMmCopyMemory(data, cpaddr, len, MM_COPY_MEMORY_VIRTUAL, &cplen);
				if (NT_SUCCESS(status)) {
					if (!buf) {
						if (cplen == len) ret = TRUE;
					} else {
						RtlCopyMemory(buf, data, cplen);
						ret = TRUE;
					}
				}
			}
			ExFreePool(data);
		}
		return ret;
	}

	// [TDOO] BYTE_OFFSET PAGE_ALIGN
	PHYSICAL_ADDRESS pa;
	pa = MmGetPhysicalAddress(addr);
	if (pa.QuadPart) {
		PVOID va = MmMapIoSpace(pa, len, MmNonCached);
		if (va) {
			if (buf) RtlCopyMemory(buf, va, len);
			MmUnmapIoSpace(va, len);
			ret = TRUE;
		}
	}
	return ret;
}

BOOLEAN MmWriteKernelMemory(PVOID addr, PVOID buf, ULONG len)
{
	if (addr > MM_HIGHEST_USER_ADDRESS) {
		if (!MmIsAddressValid(addr)) return FALSE;
		KIRQL irql = KNONE::MmWriteProtectOff();
		RtlCopyMemory(addr, buf, len);
		KNONE::MmWriteProtectOn(irql);
		return TRUE;
	}

	BOOLEAN ret = FALSE;
	KNONE::MmDisableWP();
	__try {
		RtlCopyMemory(addr, buf, len);
		ret = TRUE;
	} __except (1) {}
	KNONE::MmEnableWP();
	return ret;
}

PVOID MmGetRoutineAddress(IN PCWSTR name)
{
	UNICODE_STRING ustr;
	RtlInitUnicodeString(&ustr, name);
	return MmGetSystemRoutineAddress(&ustr);
}

BOOLEAN MmIsAddressValidSafe(PVOID addr, ULONG size)
{
	return MmReadKernelMemory(addr, NULL, size);
}

} // namespace KNONE
