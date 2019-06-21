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
#include <Windows.h>
#include <common/unone-common.h>
#include <internal/unone-internal.h>
#include <string/unone-str.h>
#include "unone-native.h"

namespace UNONE {

/*++
Description:
	query system information by NtQuerySystemInformation
Arguments:
	type - SYSTEM_INFORMATION_CLASS
	info - return data
Return:
	NTSTATUS
--*/
NTSTATUS NtQuerySystemInfo(__in int type, __out std::string &info)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	auto pNtQuerySystemInformation = (__NtQuerySystemInformation)GetProcAddress(
		GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
	if (!pNtQuerySystemInformation) return status;

	ULONG bufsize = 0;
	PSYSTEM_PROCESSES buf = NULL;

	status = pNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)type, buf, bufsize, &bufsize);
	if (status != STATUS_INFO_LENGTH_MISMATCH) {
		UNONE_ERROR("NtQuerySystemInformation err:%#x", status);
		return STATUS_UNSUCCESSFUL;
	}
	ULONG retlen = 0;
	std::string temp;
	do {
		bufsize += MAX(retlen, PAGE_SIZE);
		temp.resize(bufsize);
		buf = (PSYSTEM_PROCESSES)temp.data();
		status = pNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)type, buf, bufsize, &retlen);
		if (NT_SUCCESS(status) && retlen <= bufsize) {
			info.assign(temp.data(), retlen);
			break;
		}
		if (status != STATUS_INFO_LENGTH_MISMATCH) {
			UNONE_ERROR("NtQuerySystemInformation err:%#x", status);
			break;
		}
	} while (1);
	return status;
}

} // namespace UNONE