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
#include <native/unone-native.h>
#include <internal/unone-internal.h>
#include <string/unone-str.h>
#include "unone-mm.h"

namespace UNONE {

/*++
Description:
	map file to section, if succeeded, caller should close handles(MmUnmapFile).
Arguments:
	path - file path
	size - file size
	fd - file handle
	hmap - mapped handle
Return:
	mapped buffer
--*/
CHAR* MmMapFileA(__in const std::string& path, __out DWORD& size, __out HANDLE& fd, __out HANDLE& hmap)
{
	return MmMapFileW(StrToW(path), size, fd, hmap);
}

/*++
Description:
	map file to section, if succeeded, caller should close handles(MmUnmapFile).
Arguments:
	path - file path
	size - file size
	fd - file handle
	hmap - mapped handle
Return:
	mapped buffer
--*/
CHAR* MmMapFileW(__in const std::wstring& path, __out DWORD& size, __out HANDLE& fd, __out HANDLE& hmap)
{
	fd = INVALID_HANDLE_VALUE;
	hmap = NULL;
	do {
		fd = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if (fd == INVALID_HANDLE_VALUE) {
			UNONE_ERROR(L"CreateFileW %s err:%d", path.c_str(), GetLastError());
			break;
		}
		size = GetFileSize(fd, NULL);
		if (size == INVALID_FILE_SIZE) {
			UNONE_ERROR(L"GetFileSize %s err:%d", path.c_str(), GetLastError());
			break;
		}
		if (size == 0) {
			UNONE_ERROR(L"%s is empty file", path.c_str());
			break;
		}
		hmap = CreateFileMapping(fd, NULL, PAGE_READONLY, NULL, NULL, NULL);
		if (hmap == NULL) {
			UNONE_ERROR(L"CreateFileMapping %s err:%d", path.c_str(), GetLastError());
			break;
		}
		PVOID map_buff = MapViewOfFile(hmap, FILE_MAP_READ, 0, 0, 0);
		if (map_buff == NULL) {
			UNONE_ERROR(L"MapViewOfFile %s err:%d", path.c_str(), GetLastError());
			break;
		}
		return (CHAR*)map_buff;
	} while (0);
	if (hmap != NULL)
		CloseHandle(hmap);
	if (fd != INVALID_HANDLE_VALUE)
		CloseHandle(fd);
	return NULL;
}

/*++
Description:
	map file to section, if succeeded, caller should closehandle.
Arguments:
	map_buff - file path
	fd - file size
	hmap - file handle
	hmap - mapped handle
Return:
	bool
--*/
bool MmUnmapFile(__in CHAR* map_buff, __in HANDLE fd, __in HANDLE hmap)
{
	if (!map_buff || fd == INVALID_HANDLE_VALUE || !hmap)
		return false;
	if (!UnmapViewOfFile(map_buff)) {
		UNONE_ERROR("UnmapViewOfFile %#x err:%d", map_buff, GetLastError());
		return false;
	}
	CloseHandle(hmap);
	CloseHandle(fd);
	return true;
}

/*++
Description:
	read process (32-bit) memory, whichever arch(32/64) the caller is
Arguments:
	map_buff - file path
	fd - file size
	hmap - file handle
	hmap - mapped handle
Return:
	bool
--*/
bool MmReadProcessMemory32(__in DWORD pid, __in ULONG addr, __inout PVOID buff, __in ULONG size, __out PULONG readlen)
{
	NTSTATUS result;
	HANDLE phd = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (!phd) {
		UNONE_ERROR("OpenProcess pid:%d err:%d", pid, GetLastError());
		return false;
	}
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	__NtReadVirtualMemory pNtReadVirtualMemory = (__NtReadVirtualMemory)GetProcAddress(ntdll, "NtReadVirtualMemory");
	result = pNtReadVirtualMemory(phd, (PVOID)addr, buff, (SIZE_T)size, (SIZE_T*)readlen);
	CloseHandle(phd);
	return NT_SUCCESS(result);
}

/*++
Description:
	read process (64-bit) memory, whichever arch(32/64) the caller is
Arguments:
	map_buff - file path
	fd - file size
	hmap - file handle
	hmap - mapped handle
Return:
	bool
--*/
bool MmReadProcessMemory64(__in DWORD pid, __in ULONG64 addr, __inout PVOID buff, __in ULONG size, __out PULONG64 readlen)
{
	NTSTATUS result;
	HANDLE phd = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (!phd) {
		UNONE_ERROR("OpenProcess pid:%d err:%d", pid, GetLastError());
		return false;
	}
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
#ifdef _AMD64_
	__NtReadVirtualMemory pNtReadVirtualMemory = (__NtReadVirtualMemory)
		GetProcAddress(ntdll, "NtReadVirtualMemory");
#else
	__NtWow64ReadVirtualMemory64 pNtReadVirtualMemory = (__NtWow64ReadVirtualMemory64)
		GetProcAddress(ntdll, "NtWow64ReadVirtualMemory64");
#endif
	if (!pNtReadVirtualMemory) {
		CloseHandle(phd);
		return false;
	}
	result = pNtReadVirtualMemory(phd, (PVOID64)addr, buff, (SIZE_T)size, readlen);
	CloseHandle(phd);
	return NT_SUCCESS(result);
}

/*++
Description:
	read process (64-bit) memory, whichever arch(32/64) the caller is
Arguments:
	map_buff - file path
	fd - file size
	hmap - file handle
	hmap - mapped handle
Return:
	bool
--*/
bool MmGetProcessMemoryInfo(__in DWORD pid, __inout PROCESS_MEMORY_COUNTERS_EX& mm_info)
{
	bool result = false;
	HANDLE phd = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, pid);
	if (!phd) {
		UNONE_ERROR("OpenProcess pid:%d err:%d", pid, GetLastError());
		return FALSE;
	}
	if (GetProcessMemoryInfo(phd, (PPROCESS_MEMORY_COUNTERS)&mm_info, sizeof(mm_info))) {
		result = true;
	} else {
		UNONE_ERROR("GetProcessMemoryInfo err:%d", GetLastError());
	}
	CloseHandle(phd);
	return result;
}

} //namespace UNONE