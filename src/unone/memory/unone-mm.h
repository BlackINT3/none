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
#pragma once
#include <Windows.h>
#include <string>
#include <Psapi.h>
#pragma comment(lib, "Psapi.lib")

namespace UNONE {

#ifdef _UNICODE
#define MmMapFile MmMapFileW
#else
#define MmMapFile MmMapFileA
#endif // _UNICODE

UNONE_API CHAR* MmMapFileA(__in const std::string& path, __out DWORD& size, __out HANDLE& fd, __out HANDLE& hmap);
UNONE_API CHAR* MmMapFileW(__in const std::wstring& path, __out DWORD& size, __out HANDLE& fd, __out HANDLE& hmap);
UNONE_API bool MmUnmapFile(__in CHAR* map_buff, __in HANDLE fd, __in HANDLE hmap);
UNONE_API bool MmReadProcessMemory32(__in DWORD pid, __in ULONG addr, __inout PVOID buff, __in ULONG size, __out PULONG readlen);
UNONE_API bool MmReadProcessMemory64(__in DWORD pid, __in ULONG64 addr, __inout PVOID buff, __in ULONG size, __out PULONG64 readlen);
UNONE_API bool MmGetProcessMemoryInfo(__in DWORD pid, __inout PROCESS_MEMORY_COUNTERS_EX& mm_info);

} // namespace UNONE

