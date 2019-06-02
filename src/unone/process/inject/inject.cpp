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
#include <algorithm>
#include <memory>
#include "../../common/unone-common.h"
#include "../../native/unone-native.h"
#include "../../internal/unone-internal.h"
#include "../../os/unone-os.h"
#include "../../pe/unone-pe.h"
#include "../../memory//unone-mm.h"
#include "../../string/unone-str.h"
#include "../unone-ps.h"
#include "../wow64/wow64ext.h"

namespace {
ULONG64 GetLoadLibraryAddress32(DWORD pid)
{
	ULONG64 addr = 0;
#ifdef _AMD64_
	std::vector<UNONE::MODULE_BASE_INFOW> mods;
	UNONE::PsGetModulesInfoW(pid, mods);
	auto it = std::find_if(std::begin(mods), std::end(mods), [](UNONE::MODULE_BASE_INFOW &info) {
		return UNONE::StrCompareIW(info.BaseDllName, L"kernel32.dll");
	});
	if (it == std::end(mods)) {
		UNONE_ERROR("not found kernel32.dll");
		return NULL;
	}
	ULONG64 base = it->DllBase;
	std::wstring& path = it->FullDllName;
	auto image = UNONE::PeMapImageByPathW(path);
	if (!image) {
		UNONE_ERROR("MapImage %s failed, err:%d", path.c_str(), GetLastError());
		return NULL;
	}
	auto pLoadLibraryW = UNONE::PeGetProcAddress(image, "LoadLibraryW");
	UNONE::PeUnmapImage(image);
	if (pLoadLibraryW == NULL) {
		UNONE_ERROR("PsGetProcAddress err:%d", GetLastError());
		return NULL;
	}
	addr = (ULONG64)pLoadLibraryW - (ULONG64)image + base;
#else
	addr = (ULONG64)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
#endif
	return addr;
}
}

namespace UNONE {

/*++
Description:
	create remote thread for 32-bits process
Arguments:
	phd - process handle
	routine - thread procedure
	param - thread parameter
	flags - create flags
Return:
	thread handle
--*/
HANDLE PsCreateRemoteThread32(__in HANDLE phd, __in ULONG32 routine, __in ULONG32 param, __in DWORD flags)
{
	HANDLE thd = NULL;
	BOOLEAN suspended = flags & CREATE_SUSPENDED;
	if (OsIsVistaUpper()) {
		auto pRtlCreateUserThread = (__RtlCreateUserThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCreateUserThread");
		if (pRtlCreateUserThread == NULL) return NULL;
		NTSTATUS status = pRtlCreateUserThread(phd, NULL, suspended, 0, 0, 0, (PVOID)routine, (PVOID)param, &thd, NULL);
		if (!NT_SUCCESS(status)) {
			UNONE_ERROR("CreateThread err:%x", status);
			return NULL;
		}
	} else {
		thd = CreateRemoteThread(phd, NULL, 0, (LPTHREAD_START_ROUTINE)routine, (PVOID)param, flags, NULL);
		if (thd == NULL) {
			UNONE_ERROR("CreateThread err:%d", GetLastError());
			return NULL;
		}
	}
	UNONE_INFO("CreateThread thd:%x ok", thd);
	return thd;
}

/*++
Description:
	create remote thread for 64-bits process
Arguments:
	phd - process handle
	routine - thread procedure
	param - thread parameter
	flags - create flags
Return:
	thread handle
--*/
HANDLE PsCreateRemoteThread64(__in HANDLE phd, __in ULONG64 routine, __in ULONG64 param, __in DWORD flags)
{
	NTSTATUS status;
	DWORD64 thd = NULL;
	BOOLEAN suspended = flags & CREATE_SUSPENDED;
#ifdef _AMD64_
	auto pRtlCreateUserThread = (__RtlCreateUserThread)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateUserThread");
	if (!pRtlCreateUserThread) return NULL;
	status = pRtlCreateUserThread(phd, NULL, suspended, (ULONG)0, (SIZE_T)0, (SIZE_T)0, (PVOID)routine, (PVOID)param, (PHANDLE)&thd, NULL);
#else
	auto pRtlCreateUserThread = GetProcAddress64(GetModuleHandle64(L"ntdll.dll"), "RtlCreateUserThread");
	if (!pRtlCreateUserThread) return NULL;
	status = (NTSTATUS)X64Call(pRtlCreateUserThread, 10,
		(DWORD64)phd,
		(DWORD64)NULL,
		(DWORD64)suspended,
		(DWORD64)0,
		(DWORD64)0,
		(DWORD64)0,
		(DWORD64)routine,
		(DWORD64)param,
		(DWORD64)&thd,
		(DWORD64)NULL);
#endif
	if (!NT_SUCCESS(status)) {
		UNONE_ERROR("CreateThread err:%x", status);
		return NULL;
	}
	UNONE_INFO("CreateThread thd:%x ok", thd);
	return (HANDLE)thd;
}

/*++
Description:
	create remote thread for 32/64-bits process
Arguments:
	phd - process handle
	routine - thread procedure
	param - thread parameter
	flags - create flags
Return:
	thread handle
--*/
HANDLE PsCreateRemoteThread(__in DWORD pid, __in ULONG64 routine, __in ULONG64 param, __in DWORD flags)
{
	HANDLE thd = NULL;
	HANDLE phd = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
	if (!phd) {
		UNONE_ERROR("OpenProcess pid:%d, err:%d", pid, GetLastError());
		return NULL;
	}
	if (PsIsX64(pid))
		thd = PsCreateRemoteThread64(phd, (ULONG64)routine, (ULONG64)param, flags);
	else
		thd = PsCreateRemoteThread32(phd, (ULONG32)routine, (ULONG32)param, flags);
	CloseHandle(phd);
	return thd;
}

/*++
Description:
	inject dll to 32-bits process by create remote thread
Arguments:
	pid - process id
	path - dll path
Return:
	thread handle
--*/
HANDLE PsInjectByRemoteThread32A(__in DWORD pid, __in const std::string &path)
{
	return PsInjectByRemoteThread32W(pid, StrToW(path));
}

/*++
Description:
	inject dll to 32-bits process by create remote thread
Arguments:
	pid - process id
	path - dll path
Return:
	thread handle
--*/
HANDLE PsInjectByRemoteThread32W(__in DWORD pid, __in const std::wstring &path)
{
	HANDLE thd = NULL;
	HANDLE phd = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
	if (!phd) {
		UNONE_ERROR(L"OpenProcess %d, err:%d", pid, GetLastError());
		return NULL;
	}

	LPVOID param = NULL;
	do {
		auto routine = GetLoadLibraryAddress32(pid);
		if (!routine) break;

		SIZE_T writelen = 0;
		SIZE_T bufsize = (path.size() + 1) * 2;
		param = VirtualAllocEx(phd, NULL, bufsize, MEM_COMMIT, PAGE_READWRITE);
		if (!param) {
			UNONE_ERROR(L"VirtualAllocEx err:%d", GetLastError());
			break;
		}
		if (!WriteProcessMemory(phd, param, path.c_str(), bufsize, &writelen) || writelen != bufsize) {
			UNONE_ERROR(L"WriteProcessMemory err:%d", GetLastError());
			break;
		}
		thd = PsCreateRemoteThread32(phd, (ULONG64)routine, (ULONG64)param, 0);
		if (!thd) break;
	} while (0);

	if (!thd && param) VirtualFreeEx(phd, param, 0, MEM_RELEASE);
	CloseHandle(phd);
	return thd;
}

/*++
Description:
	inject dll to 64-bits process by create remote thread
Arguments:
	pid - process id
	path - dll path
Return:
	thread handle
--*/
HANDLE PsInjectByRemoteThread64A(__in DWORD pid, __in const std::string &path)
{
	return PsInjectByRemoteThread64W(pid, StrToW(path));
}

/*++
Description:
	inject dll to 64-bits process by create remote thread
Arguments:
	pid - process id
	path - dll path
Return:
	thread handle
--*/
HANDLE PsInjectByRemoteThread64W(__in DWORD pid, __in const std::wstring &path)
{
	HANDLE thd = NULL;
	HANDLE phd = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
	if (!phd) {
		UNONE_ERROR(L"OpenProcess %d, err:%d", pid, GetLastError());
		return NULL;
	}

#ifdef _AMD64_
	LPVOID param = NULL;
	do {
		auto routine = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
		if (!routine) break;
		SIZE_T writelen = 0;
		SIZE_T bufsize = (path.size() + 1) * 2;
		param = VirtualAllocEx(phd, NULL, bufsize, MEM_COMMIT, PAGE_READWRITE);
		if (!param) {
			UNONE_ERROR(L"VirtualAllocEx err:%d", GetLastError());
			break;
		}
		if (!WriteProcessMemory(phd, param, path.c_str(), bufsize, &writelen) || writelen != bufsize) {
			UNONE_ERROR(L"WriteProcessMemory err:%d", GetLastError());
			break;
		}
		thd = PsCreateRemoteThread64(phd, (ULONG64)routine, (ULONG64)param, 0);
		if (!thd) break;
	} while (0);
#else
	// shellcode from:https://github.com/ChengChengCC/Ark-tools/tree/master/Wow64Injectx64
	unsigned char shellcode[] = {
		0x48, 0x89, 0x4c, 0x24, 0x08,                               // mov       qword ptr [rsp+8],rcx 
		0x57,                                                       // push      rdi
		0x48, 0x83, 0xec, 0x20,                                     // sub       rsp,20h
		0x48, 0x8b, 0xfc,                                           // mov       rdi,rsp
		0xb9, 0x08, 0x00, 0x00, 0x00,                               // mov       ecx,8
		0xb8, 0xcc, 0xcc, 0xcc, 0xcc,                               // mov       eac,0CCCCCCCCh
		0xf3, 0xab,                                                 // rep stos  dword ptr [rdi]
		0x48, 0x8b, 0x4c, 0x24, 0x30,                               // mov       rcx,qword ptr [__formal]
		0x49, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       r9,0  //PVOID*  BaseAddr opt
		0x49, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       r8,0  //PUNICODE_STRING Name
		0x48, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       rdx,0
		0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       rcx,0
		0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       rax,0 
		0xff, 0xd0,                                                 // call      rax   LdrLoadDll
		0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       rcx,0
		0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       rax,0
		0xff, 0xd0                                                  // call      rax
	};
#pragma pack(push, 1)
	struct ShellCodeParam {
		DWORD64 modbase;
		_UNICODE_STRING_T<DWORD64> modpath;
		WCHAR modbuf[1];
	};
#pragma pack(pop)
	char *param = NULL;
	DWORD path_size = (path.size() + 1) * sizeof(WCHAR);
	DWORD param_size = sizeof(ShellCodeParam) - sizeof(WCHAR) + path_size;
	DWORD64 routine = 0, s_param = 0;

	do {
		DWORD64 ntdll = GetModuleHandle64(L"ntdll.dll");
		DWORD64 ldrloaddll = GetProcAddress64(ntdll, "LdrLoadDll");
		DWORD64 rtlexituserthread = GetProcAddress64(ntdll, "RtlExitUserThread");
		if (ntdll == NULL || ldrloaddll == NULL || rtlexituserthread == NULL) break;
			
		routine = VirtualAllocEx64(phd, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (routine == NULL) {
			UNONE_ERROR(L"VirtualAllocEx err:%d", GetLastError());
			break;
		}
		s_param = VirtualAllocEx64(phd, NULL, param_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (s_param == NULL) {
			UNONE_ERROR(L"VirtualAllocEx err:%d", GetLastError());
			break;
		}
		auto s_modbase = s_param + FIELD_OFFSET(ShellCodeParam, modbase);
		auto s_modpath = s_param + FIELD_OFFSET(ShellCodeParam, modpath);
		auto s_modbuf = s_param + FIELD_OFFSET(ShellCodeParam, modbuf);
		param = (char*)malloc(param_size);
		if (!param) {
			UNONE_ERROR(L"malloc err");
			break;
		}

		((ShellCodeParam*)param)->modbase = 0;
		auto modpath = &((ShellCodeParam*)param)->modpath;
		auto modbuf = &((ShellCodeParam*)param)->modbuf;
		modpath->Length = (WORD)path.size() * 2;
		modpath->MaximumLength = (WORD)(path.size() + 1) * 2;
		modpath->Buffer = s_modbuf;
		memcpy(modbuf, path.c_str(), path_size);

		//r9
		memcpy(shellcode + 32, &s_modbase, sizeof(DWORD64));
		//r8
		memcpy(shellcode + 42, &s_modpath, sizeof(DWORD64));
		//LdrLoaddll
		memcpy(shellcode + 72, &ldrloaddll, sizeof(DWORD64));
		//RtlExitUserThread
		memcpy(shellcode + 94, &rtlexituserthread, sizeof(DWORD64));

		if (!WriteProcessMemory64(phd, routine, shellcode, sizeof(shellcode), NULL) ||
			!WriteProcessMemory64(phd, s_param, param, param_size, NULL)) {
			UNONE_ERROR(L"WriteProcessMemory err:%d", GetLastError());
			break;
		}
		thd = PsCreateRemoteThread64(phd, routine, s_param, 0);
		if (!thd) break;
	} while (0);

	if (!thd && routine) VirtualFreeEx64(phd, routine, sizeof(shellcode), MEM_RELEASE);
	if (!thd && s_param) VirtualFreeEx64(phd, s_param, param_size, MEM_RELEASE);
	if (param) free(param);
#endif

	CloseHandle(phd);
	return thd;
}

/*++
Description:
	inject dll to process by create remote thread
Arguments:
	pid - process id
	path - dll path
Return:
	thread handle
--*/
HANDLE PsInjectByRemoteThreadA(__in DWORD pid, __in const std::string &path)
{
	return PsInjectByRemoteThreadW(pid, StrToW(path));
}

/*++
Description:
	inject dll to process by create remote thread
Arguments:
	pid - process id
	path - dll path
Return:
	thread handle
--*/
HANDLE PsInjectByRemoteThreadW(__in DWORD pid, __in const std::wstring &path)
{
	if (PsIsX64(pid))
		return PsInjectByRemoteThread64W(pid, path);
	else
		return PsInjectByRemoteThread32W(pid, path);
}

} // namespace UNONE
