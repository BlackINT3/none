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
#include <Tlhelp32.h>
#include <Psapi.h>
#include <tchar.h>
#include <algorithm>
#pragma comment(lib, "Psapi.lib")
#include <common/unone-common.h>
#include <internal/unone-internal.h>
#include <native/unone-native.h>
#include <string/unone-str.h>
#include <os/unone-os.h>
#include <file/unone-fs.h>
#include <object/unone-ob.h>
#include "wow64/wow64ext.h"
#include "unone-ps.h"

namespace {

//internal: suspend normal
DWORD PsSuspendNormalThread(DWORD tid)
{
	DWORD result = -1;
	HANDLE thd = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
	if (thd) {
		result = SuspendThread(thd);
		CloseHandle(thd);
	}
	return result;
}

//internal: suspend wow64
DWORD PsSuspendWow64Thread(DWORD tid)
{
	DWORD result = -1;
	__Wow64SuspendThread pWow64SuspendThread = (__Wow64SuspendThread)GetProcAddress(
		GetModuleHandleW(L"kernel32.dll"), "Wow64SuspendThread");
	if (pWow64SuspendThread) {
		HANDLE thd = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
		if (thd) {
			result = pWow64SuspendThread(thd);
			CloseHandle(thd);
		}
	}
	return result;
}

BOOL CALLBACK RetrieveWndCallback(HWND wnd, LPARAM param)
{
	DWORD pid;
	if (GetWindowThreadProcessId(wnd, &pid)) {
		PVOID *arr = (PVOID*)param;
		if (*(DWORD*)arr[0] == pid) {
			std::vector<HWND>& wnds = *(std::vector<HWND>*)arr[1];
			wnds.push_back(wnd);
		}
	}
	return TRUE;
}

bool ReadUnicodeString32(HANDLE phd, std::wstring& wstr, PUNICODE_STRING32 ustr, __NtReadVirtualMemory read_routine)
{
	SIZE_T readlen;
	wstr.assign(ustr->Length / 2, 0);
	NTSTATUS status = read_routine(phd, (PVOID)ustr->Buffer, (PVOID)wstr.c_str(), ustr->Length, &readlen);
	if (!NT_SUCCESS(status)) {
		UNONE_ERROR("read memory err:%x", status);
		wstr.clear();
		return false;
	}
	return true;
}

#ifdef _M_IX86
bool ReadUnicodeString64(HANDLE phd, std::wstring& wstr, PUNICODE_STRING64 ustr, __NtWow64ReadVirtualMemory64 read_routine)
#else
bool ReadUnicodeString64(HANDLE phd, std::wstring& wstr, PUNICODE_STRING64 ustr, __NtReadVirtualMemory read_routine)
#endif
{
	ULONG64 readlen;
	wstr.assign(ustr->Length / 2, 0);
	NTSTATUS status = read_routine(phd, (PVOID64)ustr->Buffer, (PVOID)wstr.c_str(), ustr->Length, &readlen);
	if (!NT_SUCCESS(status)) {
		UNONE_ERROR("read memory err:%x", status);
		return false;
	}
	return true;
}

FORCEINLINE PVOID GetReadRoutine32()	
{
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	return GetProcAddress(ntdll, "NtReadVirtualMemory");
}

FORCEINLINE PVOID GetReadRoutine64()
{
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
#ifdef _M_IX86
	return GetProcAddress(ntdll, "NtWow64ReadVirtualMemory64");
#else
	return GetProcAddress(ntdll, "NtReadVirtualMemory");
#endif
}
}

namespace UNONE {

/*++
Description:
	check process is running under wow64 by process handle.
	default process is current.
Arguments:
	phd - process handle
Return:
	bool
--*/
bool PsIsWow64(__in HANDLE phd)
{
	typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS pIsWow64Process = NULL;
	BOOL is_wow64 = FALSE;
	pIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(TEXT("kernel32")),"IsWow64Process");
	if (NULL != pIsWow64Process) {
		if (!pIsWow64Process(phd,&is_wow64)) {
			// handle error
		}
	}
	return is_wow64 == TRUE;
}

/*++
Description:
	check process is running under wow64 by process id.
	default process is current.
Arguments:
	pid - process id
Return:
	bool
--*/
bool PsIsWow64(__in DWORD pid)
{
	bool result = false;
	HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (process) {
		result = PsIsWow64(process);
		CloseHandle(process);
	}
	return result;
}

/*++
Description:
	check process is x64 by process id.
Arguments:
	pid - process id
Return:
	bool
--*/
bool PsIsX64(__in DWORD pid)
{
	return OsIs64() && !PsIsWow64(pid);
}

/*++
Description:
	check thread is x64 by thread id
Arguments:
	tid - thread id
Return:
	bool
--*/
bool PsThreadIsX64(__in DWORD tid)
{
	//return PsIsX64(PsFastGetPidByTid(tid));
	return false;
}

/*++
Description:
	check process is existed by pid
Arguments:
	pid - process id
Return:
	bool
--*/
bool PsIsPidExisted(__in DWORD pid)
{
	bool exsited = false;
	PsEnumProcess([&](PROCESSENTRY32W& entry)->bool{
		if (entry.th32ProcessID == pid) {
			exsited = true;
			return false;	//stop
		}
		return true;
	});
	if (!exsited) {
		if (!PsIsDeleted(pid)) exsited = true;
	}
	return exsited;
}

/*++
Description:
	check process is existed by name
Arguments:
	wild - process name wildcard
Return:
	bool
--*/
bool PsIsNameExistedA(__in const std::string &wild)
{
	return PsIsNameExistedW(StrToW(wild));
}

/*++
Description:
	check process is existed by name
Arguments:
	wild - process name wildcard
Return:
	bool
--*/
bool PsIsNameExistedW(__in const std::wstring &wild)
{
	if (wild.empty()) return false;
	bool exsited = false;
	PsEnumProcess([&](PROCESSENTRY32W& entry)->bool{
		if (StrWildCompareIW(entry.szExeFile, wild)) {
			exsited = true;
			return false;
		}
		return true;
	});
	return exsited;
}

/*++
Description:
	check process is existed by path
Arguments:
	wild - process path wildcard
Return:
	bool
--*/
bool PsIsPathExistedA(__in const std::string &wild)
{
	return PsIsPathExistedW(StrToW(wild));
}

/*++
Description:
	check process is existed by path
Arguments:
	wild - process path wildcard
Return:
	bool
--*/
bool PsIsPathExistedW(__in const std::wstring &wild)
{
	if (wild.empty()) return false;
	bool exsited = false;
	PsEnumProcess([&](PROCESSENTRY32W& entry)->bool{
		std::wstring p1 = PsGetProcessPathW(entry.th32ProcessID);
		std::wstring p2 = wild;
		StrReplaceIW(p1, L"/", L"\\");
		StrReplaceIW(p2, L"/", L"\\");
		if (StrWildCompareIW(p1, p2)) {
			exsited = true;
			return false;
		}
		return true;
	});
	return exsited;
}

/*++
Description:
	check process is deleted
Arguments:
	pid - process id
Return:
	bool
--*/
bool PsIsDeleted(__in DWORD pid)
{
	bool result = false;
	HANDLE phd = OpenProcess(SYNCHRONIZE, FALSE, pid);
	if (phd) {
		if (WaitForSingleObject(phd, 0) == WAIT_OBJECT_0)	//signal
			result = true;
		CloseHandle(phd);
	} else {
		if (GetLastError() == ERROR_INVALID_PARAMETER)	//87
			result = true;
	}
	return result;
}

/*++
Description:
	get process basic information
Arguments:
	phd - process handle
	pbi32 - PROCESS_BASIC_INFORMATION
Return:
	bool
--*/
bool PsGetPbi32(__in HANDLE phd, __out PROCESS_BASIC_INFORMATION32 &pbi32)
{
	NTSTATUS status;
	ULONG retlen;
	PROCESS_BASIC_INFORMATION pbi;
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	auto pNtQueryInformationProcess = (__NtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
	if (!pNtQueryInformationProcess)
		return false;
	status = pNtQueryInformationProcess(phd, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &retlen);
	if (!NT_SUCCESS(status))
		return false;
	pbi32.ExitStatus = pbi.ExitStatus;
	pbi32.PebBaseAddress = (ULONG)pbi.PebBaseAddress;
	pbi32.AffinityMask = (ULONG)pbi.AffinityMask;
	pbi32.BasePriority = pbi.BasePriority;
	pbi32.UniqueProcessId = (ULONG)pbi.UniqueProcessId;
	pbi32.InheritedFromUniqueProcessId = (ULONG)pbi.InheritedFromUniqueProcessId;
	return true;
}

/*++
Description:
	get process basic information
Arguments:
	phd - process handle
	pbi64 - PROCESS_BASIC_INFORMATION64
Return:
	bool
--*/
bool PsGetPbi64(__in HANDLE phd, __out PROCESS_BASIC_INFORMATION64 &pbi64)
{
	NTSTATUS status;
	ULONG retlen;
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
#ifdef _M_IX86
	auto pNtQueryInformationProcess = (__NtWow64QueryInformationProcess64)GetProcAddress(ntdll, "NtWow64QueryInformationProcess64");
#else
	auto pNtQueryInformationProcess = (__NtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
#endif
	if (!pNtQueryInformationProcess)
		return false;
	status = pNtQueryInformationProcess(phd, ProcessBasicInformation, &pbi64, sizeof(PROCESS_BASIC_INFORMATION64), &retlen);
	if (!NT_SUCCESS(status)) {
		UNONE_ERROR("query process information err:%x", status);
		return false;
	}
	return true;
}

/*++
Description:
	get process PEB
Arguments:
	phd - process handle
Return:
	PEB
--*/
PVOID PsGetPebAddress32(__in HANDLE phd)
{
	NTSTATUS status;
	ULONG retlen;
	PVOID peb = NULL;
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	auto pNtQueryInformationProcess = (__NtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
#ifdef _M_IX86
	PROCESS_BASIC_INFORMATION32 pbi32 = { 0 };
	status = pNtQueryInformationProcess(phd, ProcessBasicInformation, &pbi32, sizeof(PROCESS_BASIC_INFORMATION32), &retlen);
	if (!NT_SUCCESS(status)) {
		UNONE_ERROR("query process information err:%x", status);
		return NULL;
	}
	peb = (PVOID)pbi32.PebBaseAddress;
#else
	status = pNtQueryInformationProcess(phd, ProcessWow64Information, &peb, sizeof(PVOID), &retlen);
	if (!NT_SUCCESS(status)) {
		UNONE_ERROR("query process information err:%x", status);
		return NULL;
	}
#endif
	return peb;
}

/*++
Description:
	get process PEB
Arguments:
	phd - process handle
Return:
	PEB
--*/
PVOID64 PsGetPebAddress64(__in HANDLE phd)
{
	PROCESS_BASIC_INFORMATION64 pbi64 = { 0 };
	if (PsGetPbi64(phd, pbi64))
		return (PVOID64)pbi64.PebBaseAddress;
	return NULL;
}

/*++
Description:
	get process parent pid
Arguments:
	pid - process id
Return:
	process pid
--*/
DWORD PsGetParentPid(__in DWORD pid)
{
	DWORD ppid = INVALID_PID;
	HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (!process) return INVALID_PID;
	if (PsIsX64(pid)) {
		PROCESS_BASIC_INFORMATION64 pbi64;
		if (PsGetPbi64(process, pbi64))
			ppid = (DWORD)pbi64.InheritedFromUniqueProcessId;
	} else {
		PROCESS_BASIC_INFORMATION32 pbi32;
		if (PsGetPbi32(process, pbi32))
			ppid = (DWORD)pbi32.InheritedFromUniqueProcessId;
	}
	CloseHandle(process);
	return ppid;
}

/*++
Description:
	get process id by thread id
Arguments:
	tid - thread id
Return:
	process pid
--*/
DWORD PsGetPidByThread(__in DWORD tid)
{
	DWORD retlen = 0;
	DWORD pid = 0;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	HANDLE thd = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
	if (!thd) {
		UNONE_ERROR("OpenThread tid:%d err:%d", tid, GetLastError());
		return INVALID_TID;
	}
#ifdef _M_IX86
	if (PsIsWow64()) {
		THREAD_BASIC_INFORMATION64 tbi64;
		auto pNtQueryInformationThread64 = GetProcAddress64(GetModuleHandle64(L"ntdll.dll"), "NtQueryInformationThread");
		if (!pNtQueryInformationThread64)
			return 0;
		status = (NTSTATUS)X64Call((DWORD64)pNtQueryInformationThread64, 5,
			(DWORD64)thd,
			(DWORD64)ThreadBasicInformation,
			(DWORD64)&tbi64,
			(DWORD64)sizeof(tbi64),
			(DWORD64)&retlen);
		if (!NT_SUCCESS(status)) {
			UNONE_ERROR("NtQueryInformationThread tid:%d err:%x", tid, status);
		} else {
			pid = (DWORD)tbi64.ClientId.UniqueProcess;
		}
		CloseHandle(thd);
		return pid;
	}
#endif

#ifdef _M_IX86
	THREAD_BASIC_INFORMATION32 tbi;
#else
	THREAD_BASIC_INFORMATION64 tbi;
#endif
	auto pNtQueryInformationThread = (__NtQueryInformationThread)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread");
	if (!pNtQueryInformationThread) return INVALID_TID;
	status = pNtQueryInformationThread(
		thd,
		ThreadBasicInformation,
		&tbi,
		sizeof(tbi),
		&retlen);
	if (!NT_SUCCESS(status)) {
		UNONE_ERROR("NtQueryInformationThread tid:%d err:%x", tid, status);
	} else {
		pid = (DWORD)tbi.ClientId.UniqueProcess;
	}
	CloseHandle(thd);
	return pid;
}


/*++
Description:
	get process child pid list
Arguments:
	pid - process id
Return:
	child processes
--*/
std::vector<DWORD> PsGetChildPids(__in DWORD pid)
{
	std::vector<DWORD> childs;
	UNONE::PsEnumProcess([&](PROCESSENTRY32W &entry)->bool {
		if (pid != 0 && pid == entry.th32ParentProcessID) {
			childs.push_back(entry.th32ProcessID);
		}
		return true;
	});
	return childs;
}

/*++
Description:
	get process descendant pid list
Arguments:
	pid - process id
Return:
	descendant processes
--*/
std::vector<DWORD> PsGetDescendantPids(__in DWORD pid)
{
	std::vector<DWORD> descendants;
	std::vector<DWORD> childs = PsGetChildPids(pid);
	if (childs.empty()) return childs;
	std::for_each(std::begin(childs), std::end(childs), [&](DWORD id) {
		//child can't includes parent
		if (id == pid) return;
		std::vector<DWORD> trees = PsGetDescendantPids(id);
		if (!trees.empty())
			descendants.insert(descendants.end(), trees.begin(), trees.end());
		descendants.push_back(id);
	});
	return descendants;
}

/*++
Description:
	get 32bit process base information
Arguments:
	pid - process id
	info - base information
Return:
	bool
--*/
bool PsGetProcessInfo32A(__in DWORD pid, __out PROCESS_BASE_INFOA &info)
{
	PROCESS_BASE_INFOW info_w;
	if (PsGetProcessInfo32W(pid, info_w)) {
		info.ImagePathName = StrToA(info_w.ImagePathName);
		info.CommandLine = StrToA(info_w.CommandLine);
		info.WindowTitle = StrToA(info_w.WindowTitle);
		info.CurrentDirectory = StrToA(info_w.CurrentDirectory);
		return true;
	}
	return false;
}

/*++
Description:
	get 32bit process base information
Arguments:
	pid - process id
	info - base information
Return:
	bool
--*/
bool PsGetProcessInfo32W(__in DWORD pid, __out PROCESS_BASE_INFOW &info)
{
	auto read_routine = (__NtReadVirtualMemory)GetReadRoutine32();
	if (!read_routine) return false;

	NTSTATUS status = STATUS_SUCCESS;
	HANDLE phd = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (!phd) {
		UNONE_ERROR("OpenProcess pid:%d err:%d", pid, GetLastError());
		return false;
	}
	do {
		PVOID peb_addr = PsGetPebAddress32(phd);
		if (!peb_addr) break;
		
		PEB32 peb;
		SIZE_T readlen;
		status = read_routine(phd, peb_addr, &peb, sizeof(peb), &readlen);
		if (!NT_SUCCESS(status)) break;
		
		RTL_USER_PROCESS_PARAMETERS32 params;
		status = read_routine(phd, (PVOID)peb.ProcessParameters, &params, sizeof(params), &readlen);
		if (!NT_SUCCESS(status)) break;

		if (!ReadUnicodeString32(phd, info.ImagePathName, &params.ImagePathName, read_routine)) break;
		if (!ReadUnicodeString32(phd, info.CommandLine, &params.CommandLine, read_routine)) break;
		if (!ReadUnicodeString32(phd, info.WindowTitle, &params.WindowTitle, read_routine)) break;
		if (!ReadUnicodeString32(phd, info.CurrentDirectory, &params.CurrentDirectory.DosPath, read_routine)) break;
	} while (0);

	CloseHandle(phd);
	if (!NT_SUCCESS(status)) {
		UNONE_ERROR(L"ReadVirtualMemory err:%x", status);
		return false;
	}
	return true;
}

/*++
Description:
	get 64bit process base information
Arguments:
	pid - process id
	info - base information
Return:
	bool
--*/
bool PsGetProcessInfo64A(__in DWORD pid, __out PROCESS_BASE_INFOA &info)
{
	PROCESS_BASE_INFOW info_w;
	if (PsGetProcessInfo64W(pid, info_w)) {
		info.ImagePathName = StrToA(info_w.ImagePathName);
		info.CommandLine = StrToA(info_w.CommandLine);
		info.WindowTitle = StrToA(info_w.WindowTitle);
		info.CurrentDirectory = StrToA(info_w.CurrentDirectory);
		return true;
	}
	return false;
}

/*++
Description:
	get 64bit process base information
Arguments:
	pid - process id
	info - base information
Return:
	bool
--*/
bool PsGetProcessInfo64W(__in DWORD pid, __out PROCESS_BASE_INFOW &info)
{
#ifdef _M_IX86
	auto read_routine = (__NtWow64ReadVirtualMemory64)GetReadRoutine64();
#else
	auto read_routine = (__NtReadVirtualMemory)GetReadRoutine64();
#endif
	if (!read_routine) return false;

	NTSTATUS status = STATUS_SUCCESS;
	HANDLE phd = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (!phd) {
		UNONE_ERROR(L"OpenProcess pid:%d err:%d", pid, GetLastError());
		return false;
	}
	do {
		PVOID64 peb_addr = PsGetPebAddress64(phd);
		if (!peb_addr) break;
		
		PEB64 peb;
		ULONG64 readlen;
		status = read_routine(phd, peb_addr, &peb, sizeof(peb), &readlen);
		if (!NT_SUCCESS(status)) break;
		
		RTL_USER_PROCESS_PARAMETERS64 params;
		status = read_routine(phd, (PVOID64)peb.ProcessParameters, &params, sizeof(params), &readlen);
		if (!NT_SUCCESS(status)) break;

		if (!ReadUnicodeString64(phd, info.ImagePathName, &params.ImagePathName, read_routine)) break;
		if (!ReadUnicodeString64(phd, info.CommandLine, &params.CommandLine, read_routine)) break;
		if (!ReadUnicodeString64(phd, info.WindowTitle, &params.WindowTitle, read_routine)) break;
		if (!ReadUnicodeString64(phd, info.CurrentDirectory, &params.CurrentDirectory.DosPath, read_routine)) break;
	} while (0);

	CloseHandle(phd);
	if (!NT_SUCCESS(status)) {
		UNONE_ERROR(L"ReadVirtualMemory err:%x", status);
		return false;
	}
	return true;
}

/*++
Description:
	get process base information
Arguments:
	pid - process id
	info - base information
Return:
	bool
--*/
bool PsGetProcessInfoA(__in DWORD pid, __out PROCESS_BASE_INFOA &info)
{
	PROCESS_BASE_INFOW info_w;
	if (PsGetProcessInfoW(pid, info_w)) {
		info.ImagePathName = StrToA(info_w.ImagePathName);
		info.CommandLine = StrToA(info_w.CommandLine);
		info.WindowTitle = StrToA(info_w.WindowTitle);
		info.CurrentDirectory = StrToA(info_w.CurrentDirectory);
		return true;
	}
	return false;
}

/*++
Description:
	get process base information
Arguments:
	pid - process id
	info - base information
Return:
	bool
--*/
bool PsGetProcessInfoW(__in DWORD pid, __out PROCESS_BASE_INFOW &info)
{
	if (PsIsX64(pid))
		return PsGetProcessInfo64W(pid, info);
	else
		return PsGetProcessInfo32W(pid, info);
}

/*++
Description:
	get 32bit module list information
Arguments:
	pid - process id
	infos - module list information
Return:
	bool
--*/
bool PsGetModulesInfo32A(__in DWORD pid, __out std::vector<MODULE_BASE_INFOA> &infos)
{
	infos.clear();
	std::vector<MODULE_BASE_INFOW> infos_w;
	if (PsGetModulesInfo32W(pid, infos_w)) {
		for (size_t i = 0; i < infos_w.size(); i++) {
			MODULE_BASE_INFOA info;
			info.DllBase = infos_w[i].DllBase;
			info.EntryPoint = infos_w[i].EntryPoint;
			info.SizeOfImage = infos_w[i].SizeOfImage;
			info.FullDllName = UNONE::StrToA(infos_w[i].FullDllName);
			info.BaseDllName = UNONE::StrToA(infos_w[i].BaseDllName);
			info.Flags = infos_w[i].Flags;
			info.LoadCount = infos_w[i].LoadCount;
			info.TimeDateStamp = infos_w[i].TimeDateStamp;
			infos.push_back(info);
		}
		return true;
	}
	return false;
}

/*++
Description:
	get 32bit module list information
Arguments:
	pid - process id
	infos - module list information
Return:
	bool
--*/
bool PsGetModulesInfo32W(__in DWORD pid, __out std::vector<MODULE_BASE_INFOW> &infos)
{
	auto read_routine = (__NtReadVirtualMemory)GetReadRoutine32();
	if (!read_routine) return false;

	NTSTATUS status = STATUS_SUCCESS;
	HANDLE phd = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (!phd) {
		UNONE_ERROR(L"OpenProcess pid:%d err:%d", pid, GetLastError());
		return false;
	}
	do {
		PVOID peb_addr = PsGetPebAddress32(phd);
		if (!peb_addr) break;

		PEB32 peb;
		SIZE_T readlen;
		status = read_routine(phd, peb_addr, &peb, sizeof(peb), &readlen);
		if (!NT_SUCCESS(status)) break;

		PEB_LDR_DATA32 ldr;
		LIST_ENTRY32 node, *last = NULL;
		status = read_routine(phd, (PVOID)peb.Ldr, &ldr, sizeof(ldr), &readlen);
		if (!NT_SUCCESS(status)) break;

		node = ldr.InLoadOrderModuleList;
		last = (LIST_ENTRY32*)((ULONG32)peb.Ldr + FIELD_OFFSET(PEB_LDR_DATA32, InLoadOrderModuleList));

		while ((LIST_ENTRY32*)node.Flink != last)	{
			LDR_DATA_TABLE_ENTRY32 entry;
			status = read_routine(phd, (PVOID)(ULONG32)node.Flink, &entry, sizeof(entry), &readlen);
			if (!NT_SUCCESS(status)) break;

			if (entry.EntryPoint != NULL && !IN_RANGE(entry.EntryPoint, entry.DllBase, entry.SizeOfImage)) {
				UNONE_ERROR(L"LdrEntry illegal, EntryPoint:%x DllBase:%x SizeOfImage:%x", entry.EntryPoint, entry.DllBase, entry.SizeOfImage);
				break;
			}
			MODULE_BASE_INFOW info;
			info.DllBase = (ULONG64)entry.DllBase;
			info.EntryPoint = (ULONG64)entry.EntryPoint;
			info.SizeOfImage = entry.SizeOfImage;
			info.Flags = entry.Flags;
			info.LoadCount = entry.LoadCount;
			info.TimeDateStamp = entry.TimeDateStamp;
			ReadUnicodeString32(phd, info.FullDllName, &entry.FullDllName, read_routine);
			ReadUnicodeString32(phd, info.BaseDllName, &entry.BaseDllName, read_routine);
			node = entry.InLoadOrderLinks;
			infos.push_back(info);
		}
	} while (0);

	CloseHandle(phd);
	if (!NT_SUCCESS(status)) {
		UNONE_ERROR(L"ReadVirtualMemory err:%x", status);
		return false;
	}
	return true;
}

/*++
Description:
	get 64bit module list information
Arguments:
	pid - process id
	infos - module list information
Return:
	bool
--*/
bool PsGetModulesInfo64A(__in DWORD pid, __out std::vector<MODULE_BASE_INFOA> &infos)
{
	infos.clear();
	std::vector<MODULE_BASE_INFOW> infos_w;
	if (PsGetModulesInfo64W(pid, infos_w)) {
		for (size_t i = 0; i < infos_w.size(); i++) {
			MODULE_BASE_INFOA info;
			info.DllBase = infos_w[i].DllBase;
			info.EntryPoint = infos_w[i].EntryPoint;
			info.SizeOfImage = infos_w[i].SizeOfImage;
			info.FullDllName = UNONE::StrToA(infos_w[i].FullDllName);
			info.BaseDllName = UNONE::StrToA(infos_w[i].BaseDllName);
			info.Flags = infos_w[i].Flags;
			info.LoadCount = infos_w[i].LoadCount;
			info.TimeDateStamp = infos_w[i].TimeDateStamp;
			infos.push_back(info);
		}
		return true;
	}
	return false;
}

/*++
Description:
	get 64bit module list information
Arguments:
	pid - process id
	infos - module list information
Return:
	bool
--*/
bool PsGetModulesInfo64W(__in DWORD pid, __out std::vector<MODULE_BASE_INFOW> &infos)
{
#ifdef _M_IX86
	auto read_routine = (__NtWow64ReadVirtualMemory64)GetReadRoutine64();
#else
	auto read_routine = (__NtReadVirtualMemory)GetReadRoutine64();
#endif
	if (!read_routine) return false;

	NTSTATUS status = STATUS_SUCCESS;
	HANDLE phd = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (!phd) {
		UNONE_ERROR(L"OpenProcess pid:%d err:%d", pid, GetLastError());
		return false;
	}
	do {
		PVOID64 peb_addr = PsGetPebAddress64(phd);
		if (!peb_addr) break;

		PEB64 peb;
		ULONG64 readlen;
		status = read_routine(phd, peb_addr, &peb, sizeof(peb), &readlen);
		if (!NT_SUCCESS(status)) break;

		PEB_LDR_DATA64 ldr;
		LIST_ENTRY64 node, *last = NULL;
		status = read_routine(phd, (PVOID)peb.Ldr, &ldr, sizeof(ldr), &readlen);
		if (!NT_SUCCESS(status)) break;

		node = ldr.InLoadOrderModuleList;
		last = (LIST_ENTRY64*)((ULONG64)peb.Ldr + FIELD_OFFSET(PEB_LDR_DATA64, InLoadOrderModuleList));

		while ((LIST_ENTRY64*)node.Flink != last) {
			LDR_DATA_TABLE_ENTRY64 entry;
			status = read_routine(phd, (PVOID64)(ULONG64)node.Flink, &entry, sizeof(entry), &readlen);
			if (!NT_SUCCESS(status)) break;

			if (entry.EntryPoint != NULL && !IN_RANGE(entry.EntryPoint, entry.DllBase, entry.SizeOfImage)) {
				UNONE_ERROR(L"LdrEntry illegal, EntryPoint:%x DllBase:%x SizeOfImage:%x", entry.EntryPoint, entry.DllBase, entry.SizeOfImage);
				break;
			}
			MODULE_BASE_INFOW info;
			info.DllBase = (ULONG64)entry.DllBase;
			info.EntryPoint = (ULONG64)entry.EntryPoint;
			info.SizeOfImage = entry.SizeOfImage;
			info.Flags = entry.Flags;
			info.LoadCount = entry.LoadCount;
			info.TimeDateStamp = entry.TimeDateStamp;
			ReadUnicodeString64(phd, info.FullDllName, &entry.FullDllName, read_routine);
			ReadUnicodeString64(phd, info.BaseDllName, &entry.BaseDllName, read_routine);
			node = entry.InLoadOrderLinks;
			infos.push_back(info);
		}
	} while (0);

	CloseHandle(phd);
	if (!NT_SUCCESS(status)) {
		UNONE_ERROR(L"ReadVirtualMemory err:%x", status);
		return false;
	}
	return true;
}

/*++
Description:
	get module list information
Arguments:
	pid - process id
	infos - module list information
Return:
	bool
--*/
bool PsGetModulesInfoA(__in DWORD pid, __out std::vector<MODULE_BASE_INFOA> &infos)
{
	infos.clear();
	std::vector<MODULE_BASE_INFOW> infos_w;
	if (PsGetModulesInfoW(pid, infos_w)) {
		for (size_t i = 0; i < infos_w.size(); i++) {
			MODULE_BASE_INFOA info;
			info.DllBase = infos_w[i].DllBase;
			info.EntryPoint = infos_w[i].EntryPoint;
			info.SizeOfImage = infos_w[i].SizeOfImage;
			info.FullDllName = UNONE::StrToA(infos_w[i].FullDllName);
			info.BaseDllName = UNONE::StrToA(infos_w[i].BaseDllName);
			info.Flags = infos_w[i].Flags;
			info.LoadCount = infos_w[i].LoadCount;
			info.TimeDateStamp = infos_w[i].TimeDateStamp;
			infos.push_back(info);
		}
		return true;
	}
	return false;
}

/*++
Description:
	get module list information
Arguments:
	pid - process id
	infos - module list information
Return:
	bool
--*/
bool PsGetModulesInfoW(__in DWORD pid, __out std::vector<MODULE_BASE_INFOW> &infos)
{
	if (PsIsX64(pid))
		return PsGetModulesInfo64W(pid, infos);
	else
		return PsGetModulesInfo32W(pid, infos);
}

/*++
Description:
	get process name
Arguments:
	pid - process id
Return:
	process name
--*/
std::string PsGetProcessNameA(__in DWORD pid)
{
	return StrToA(PsGetProcessNameW(pid));
}

/*++
Description:
	get process name
Arguments:
	pid - process id
Return:
	process name
--*/
std::wstring PsGetProcessNameW(__in DWORD pid)
{
	return FsPathToNameW(PsGetProcessPathW(pid));
}

/*++
Description:
	get process full path
Arguments:
	pid - process id
Return:
	process path
--*/
std::string PsGetProcessPathA(__in DWORD pid)
{
	return StrToA(PsGetProcessPathW(pid));
}

/*++
Description:
	get process full path
Arguments:
	pid - process id
Return:
	process path
--*/
std::wstring PsGetProcessPathW(__in DWORD pid)
{
	WCHAR path[MAX_PATH*2] = {0};
	DWORD path_size = (MAX_PATH*2-1) * sizeof(WCHAR);

	if (pid == 0) return L"System Idle Process";
	if (pid == 4) return L"System";

	HANDLE phd = NULL;
	phd = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, pid);
	if (phd != NULL) {
		if (GetModuleFileNameExW(phd, NULL, path, path_size) != 0) {
			CloseHandle(phd);
			return path;
		}
	}

	if (phd == NULL)
		phd = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (phd == NULL) {
		UNONE_ERROR(L"OpenProcess pid:%d err:%d", pid, GetLastError());
		return L"";
	}
	if (GetProcessImageFileNameW(phd, path, path_size) == 0) {
		UNONE_ERROR(L"GetProcessImageFileNameW pid:%d err:%d", pid, GetLastError());
		CloseHandle(phd);
		return L"";
	}
	CloseHandle(phd);
	std::wstring dos_path;
	ObParseToDosPathW(path, dos_path);
	return dos_path;
}

/*++
Description:
	get process dir
Arguments:
	pid - process id
Return:
	process dir
--*/
std::string PsGetProcessDirA(__in DWORD pid)
{
	return StrToA(PsGetProcessDirW(pid));
}

/*++
Description:
	get process dir
Arguments:
	pid - process id
Return:
	process dir
--*/
std::wstring PsGetProcessDirW(__in DWORD pid)
{
	return FsPathToDirW(PsGetProcessPathW(pid));
}

/*++
Description:
	get module base address(HMODULE)
	if module name is empty, get current
Arguments:
	mod - module name
	addr - caller address
Return:
	module base address
--*/
HMODULE PsGetModuleBaseA(const std::string &name, PVOID addr)
{
	return PsGetModuleBaseW(StrToW(name), addr);
}

/*++
Description:
	get module base address(HMODULE)
	if module name is empty, get current
Arguments:
	mod - module name
	addr - caller address
Return:
	module base address
--*/
HMODULE PsGetModuleBaseW(const std::wstring &name, PVOID addr)
{
	if (!name.empty()) return GetModuleHandleW(name.c_str());

	MEMORY_BASIC_INFORMATION mbi;
	if (!VirtualQueryEx(GetCurrentProcess(), addr, &mbi, sizeof(MEMORY_BASIC_INFORMATION))) {
		UNONE_ERROR(L"VirtualQueryEx err:%d", GetLastError());
		return NULL;
	}
	return (HMODULE)mbi.AllocationBase;
}

/*++
Description:
	get module name
Arguments:
	base - module base address
Return:
	module name
--*/
std::string PsGetModuleNameA(__in HMODULE base)
{
	return StrToA(PsGetModuleNameW(base));
}

/*++
Description:
	get module name
Arguments:
	base - module base address
Return:
	module name
--*/
std::wstring PsGetModuleNameW(__in HMODULE base)
{
	if (base == NULL) base = PsGetModuleBaseW(L"");
	return FsPathToNameW(PsGetModulePathW(L"", base));
}

/*++
Description:
	get module path
Arguments:
	name - module name
	base - module base address
Return:
	module path
--*/
std::string PsGetModulePathA(__in const std::string &name, __in HMODULE base)
{
	return StrToA(PsGetModulePathW(StrToW(name), base));
}

/*++
Description:
	get module path
Arguments:
	name - module name
	base - module base address
Return:
	module path
--*/
std::wstring PsGetModulePathW(__in const std::wstring &name, __in HMODULE base)
{
	HMODULE mod;
	if (base != NULL) mod = base;
	else mod = GetModuleHandleW(name.c_str());
	if (mod != NULL) {
		WCHAR path[MAX_PATH] = { 0 };
		if (GetModuleFileNameW(mod, path, MAX_PATH - 1) &&
			GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			return path;
		}
	}
	return L"";
}

/*++
Description:
	get module directory
Arguments:
	name - module name
	base - module base address
Return:
	module directory
--*/
std::string PsGetModuleDirA(__in const std::string &name, __in HMODULE base)
{
	return FsPathToDirA(PsGetModulePathA(name, base));
}

/*++
Description:
	get module directory
Arguments:
	name - module name
	base - module base address
Return:
	module directory
--*/
std::wstring PsGetModuleDirW(__in const std::wstring &name, __in HMODULE base)
{
	return FsPathToDirW(PsGetModulePathW(name, base));
}

/*++
Description:
get window text
Arguments:
wnd - hwnd
Return:
window text
--*/
std::string PsGetWndTextA(__in HWND wnd)
{
	return StrToA(PsGetWndTextW(wnd));
}

/*++
Description:
get window text
Arguments:
wnd - hwnd
Return:
window text
--*/
std::wstring PsGetWndTextW(__in HWND wnd)
{
	int size = GetWindowTextLengthW(wnd);
	if (size == 0) return L"";
	std::wstring text;
	text.resize(size + 1);
	GetWindowTextW(wnd, (LPWSTR)text.data(), size + 1);
	return text.c_str();
}

/*++
Description:
	get window class name
Arguments:
	wnd - hwnd
Return:
	window class name
--*/
std::string PsGetWndClassNameA(__in HWND wnd)
{
	return StrToA(PsGetWndClassNameW(wnd));
}

/*++
Description:
	get window class name
Arguments:
	wnd - hwnd
Return:
	window class name
--*/
std::wstring PsGetWndClassNameW(__in HWND wnd)
{
	std::wstring name;
	name.resize(MAX_PATH);
	int retlen = GetClassNameW(wnd, (LPWSTR)name.data(), MAX_PATH-1);
	if (retlen == 0) return L"";
	if (retlen < MAX_PATH - 1) return name.c_str();
	name.resize(retlen+1);
	retlen = GetClassNameW(wnd, (LPWSTR)name.data(), retlen+1);
	if (retlen == 0) return L"";
	return name.c_str();
}

/*++
Description:
	get process window hwnd list
Arguments:
	pid - process id
Return:
	window hwnd list
--*/
std::vector<HWND> PsGetWnds(__in DWORD pid)
{
	std::vector<HWND> wnds;
	PVOID param[] = { &pid, &wnds };
	EnumChildWindows(GetDesktopWindow(), (WNDENUMPROC)RetrieveWndCallback, (LPARAM)param);
	return wnds;
}


/*++
Description:
	get all process id
Arguments:
	pids - process id list
Return:
	bool
--*/
bool PsGetAllProcess(__out std::vector<DWORD> &pids)
{
	pids.clear();
	PsEnumProcess([&pids](PROCESSENTRY32W &entry)->bool{
		pids.push_back(entry.th32ProcessID);
		return true;
	});
	return !pids.empty();
}

/*++
Description:
	get all process id by search exhaustively
Arguments:
	pids - process id list
Return:
	bool
--*/
bool PsGetAllProcessV2(__out std::vector<DWORD> &pids)
{
	pids.clear();
	bool result = true;
	for (DWORD i = 8; i < 65536; i += 4) {
		if (!PsIsDeleted(i))
			pids.push_back(i);
	}
	return !pids.empty();
}

/*++
Description:
	get all thread id, if pid == -1, it will get all threads in os.
Arguments:
	tids - thread id list
	pid - process id
Return:
	bool
--*/
bool PsGetAllThread(__in DWORD pid, __out std::vector<DWORD> &tids)
{
	tids.clear();
	PsEnumThread(pid, [&tids](THREADENTRY32 &entry)->bool{
		tids.push_back(entry.th32ThreadID);
		return true;
	});
	return !tids.empty();
}

/*++
Description:
	enum process, if callback return false then enum aborted
Arguments:
	proc_cb - process callback
Return:
	bool
--*/
bool PsEnumProcess(__in ProcessCallback process_cb)
{
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE) {
		UNONE_ERROR("CreateToolhelp32Snapshot err:%d", GetLastError());
		return false;
	}
	PROCESSENTRY32W entry;
	entry.dwSize = sizeof(entry);
	if (!Process32FirstW(snap, &entry)) {
		UNONE_ERROR("Process32FirstW err:%d", GetLastError());
		CloseHandle(snap);
		return false;
	}
	do {
		if (!process_cb(entry))
			break;
	} while (Process32NextW(snap, &entry));
	CloseHandle(snap);
	return true;
}

/*++
Description:
	enum thread, if callback return false then enum aborted
Arguments:
	thread_cb - thread callback
	pid - process id, default -1, implies all threads in os
Return:
	bool
--*/
bool PsEnumThread(__in DWORD pid, __in ThreadCallback thread_cb)
{
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snap == INVALID_HANDLE_VALUE) {
		UNONE_ERROR("CreateToolhelp32Snapshot err:%d", GetLastError());
		return false;
	}
	THREADENTRY32 entry;
	entry.dwSize = sizeof(entry);
	if (!Thread32First(snap, &entry)) {
		UNONE_ERROR("Thread32First err:%d", GetLastError());
		CloseHandle(snap);
		return false;
	}
	do {
		if (pid == -1 || entry.th32OwnerProcessID == pid) {
			if (!thread_cb(entry))
				break;
		}
	} while (Thread32Next(snap, &entry));
	CloseHandle(snap);
	return true;
}

/*++
Description:
	enum module, if callback return false then enum aborted
Arguments:
	pid - process id
	module_cb - module callback
Return:
	bool
--*/
bool PsEnumModule(__in DWORD pid, __in ModuleCallback module_cb)
{
	DWORD flags = TH32CS_SNAPMODULE;
#ifdef _AMD64_
	if (!PsIsX64(pid)) flags |= TH32CS_SNAPMODULE32;
#endif
	HANDLE snap = CreateToolhelp32Snapshot(flags, pid);
	if (snap == INVALID_HANDLE_VALUE) {
		UNONE_ERROR("CreateToolhelp32Snapshot pid:%d err:%d", pid, GetLastError());
		return false;
	}
	MODULEENTRY32W entry;
	entry.dwSize = sizeof(entry);
	if (!Module32FirstW(snap, &entry)) {
		CloseHandle(snap);
		UNONE_ERROR("Module32FirstW err:%d", GetLastError());
		return false;
	}
	do {
		if (!module_cb(entry))
			break;
	} while (Module32NextW(snap, &entry));
	CloseHandle(snap);
	return true;
}

/*++
Description:
	enum handle, if callback return false then enum aborted
Arguments:
	pid - process id, if equal -1, implies all handles in os
	handle_cb - handle callback
Return:
	bool
--*/
bool PsEnumHandle(__in DWORD pid, __in HandleCallback handle_cb)
{
	std::string info;
	NTSTATUS status = NtQuerySystemInfo(SystemHandleInformation, info);
	if (!NT_SUCCESS(status)) return false;

	auto hds = (PSYSTEM_HANDLE_INFORMATION)info.data();
	for (ULONG i = 0; i < hds->NumberOfHandles; i++) {
		auto hd = hds->Handles[i];
		if (pid == INVALID_PID || pid == hd.UniqueProcessId) {
			if (!handle_cb(hd)) break;
		}
	}
	return true;
}

/*++
Description:
	enum memory, if callback return false then enum aborted
Arguments:
	pid - process id, if equal -1, implies all handles in os
	memory_cb - memory callback
Return:
	bool
--*/
bool PsEnumMemory(__in DWORD pid, __in MemoryCallback memory_cb)
{
	HANDLE phd = OpenProcess(PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (!phd) {
		UNONE_ERROR("OpenProcess pid:%d err:%d", pid, GetLastError());
		return false;
	}
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	char *start = (char*)sysinfo.lpMinimumApplicationAddress;
	char *end = (char*)sysinfo.lpMaximumApplicationAddress;
	if (PsIsWow64(phd)) {
		end = (char*)0x7FFE0000;
	}
	DWORD pagesize = sysinfo.dwPageSize;
	do {
		MEMORY_BASIC_INFORMATION mbi;
		if (VirtualQueryEx(phd, start, &mbi, sizeof(MEMORY_BASIC_INFORMATION))) {
			if (!memory_cb(mbi)) break;
			start += mbi.RegionSize;
		}	else {
			start += pagesize;
		}
	} while (start < end);
	CloseHandle(phd);
	return true;
}

/*++
Description:
	kill process
Arguments:
	pid - process id
Return:
	bool
--*/
bool PsKillProcess(__in DWORD pid)
{
	bool result = false;
	HANDLE phd = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
	if (phd) {
		if (TerminateProcess(phd, 1))
			result = true;
		CloseHandle(phd);
	}
	return result;
}

/*++
Description:
	kill process by process wild name(be carefully)
Arguments:
	wild - process wild name
Return:
	bool
--*/
bool PsKillProcessNameA(__in const std::string &wild)
{
	return PsKillProcessNameW(StrToW(wild));
}

/*++
Description:
	kill process by process wild name(be carefully)
Arguments:
	wild - process wild name
Return:
	bool
--*/
bool PsKillProcessNameW(__in const std::wstring &wild)
{
	bool ret = true;
	PsEnumProcess([&](PROCESSENTRY32W &entry)->bool {
		if (StrWildCompareIW(entry.szExeFile, wild)) {
			if (!PsKillProcess(entry.th32ProcessID)) ret = false;
		}
		return true;
	});
	return ret;
}

/*++
Description:
	kill process by process wild path(be carefully)
Arguments:
	wild - process wild path
Return:
	bool
--*/
bool PsKillProcessPathA(__in const std::string &wild)
{
	return PsKillProcessPathW(StrToW(wild));
}

/*++
Description:
	kill process by process wild path(be carefully)
Arguments:
	wild - process wild path
Return:
	bool
--*/
bool PsKillProcessPathW(__in const std::wstring &wild)
{
	bool ret = true;
	PsEnumProcess([&](PROCESSENTRY32W &entry)->bool {
		std::wstring &&path = PsGetProcessPathW(entry.th32ProcessID);
		if (StrWildCompareIW(path, wild)) {
			if (!PsKillProcess(entry.th32ProcessID)) ret = false;
		}
		return true;
	});
	return ret;
}

/*++
Description:
	kill process tree, include itself
Arguments:
	pid - process id
Return:
	bool
--*/
bool PsKillProcessTree(__in DWORD pid)
{
	if (!PsKillProcess(pid)) return false;
	std::vector<DWORD> tree = PsGetDescendantPids(pid);
	for (size_t i = 0; i < tree.size(); i++) {
		if (!PsKillProcess(tree[i])) return false;
	}
	return true;
}

/*++
Description:
	create process, WinExec analogous
Arguments:
	cmdline - process path or command line
	cmdshow - show type
	proc_info - process information
Return:
	bool
--*/
bool PsCreateProcessA(__in const std::string &cmdline, __in UINT cmdshow /*= SW_SHOW*/, __out PROCESS_INFORMATION *proc_info /*= NULL*/)
{
	return PsCreateProcessW(StrToW(cmdline), cmdshow, proc_info);
}

/*++
Description:
	create process, WinExec analogous
Arguments:
	cmdline - process path or command line
	cmdshow - show type
	proc_info - process information
Return:
	bool
--*/
bool PsCreateProcessW(__in const std::wstring &cmdline, __in UINT cmdshow /*= SW_SHOW*/, __out PROCESS_INFORMATION *proc_info /*= NULL*/)
{
	PROCESS_INFORMATION pi = {0};
	STARTUPINFOW si = {0};
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = (WORD)cmdshow;
	si.cb = sizeof(STARTUPINFOA);
	if (!proc_info)
		proc_info = &pi;
	if (!CreateProcessW(NULL, (LPWSTR)cmdline.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, proc_info))
		return false;
	if (pi.hProcess)
		CloseHandle(pi.hProcess);
	if (pi.hThread)
		CloseHandle(pi.hThread);
	return true;
}

/*++
Description:
	restart process, support command line
Arguments:
	pid - process id
Return:
	bool
--*/
bool PsRestartProcess(__in DWORD pid)
{
	if (pid == GetCurrentProcessId()) {
		UNONE::PsCreateProcessW(UNONE::PsGetProcessPathW());
		ExitProcess(0);
		return true;
	}
	PROCESS_BASE_INFOW info;
	bool ret = UNONE::PsGetProcessInfoW(pid, info);
	if (!ret) return false;
	auto &&cmdline = info.CommandLine.empty() ? info.ImagePathName : info.CommandLine;
	if (cmdline.empty()) return false;
	UNONE::PsKillProcess(pid);
	return UNONE::PsCreateProcessW(cmdline);
}

/*++
Description:
	suspend process
Arguments:
	pid - process id
Return:
	bool
--*/
bool PsSuspendProcess(__in DWORD pid)
{
	bool result = false;
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	__NtSuspendProcess pNtSuspendProcess = (__NtSuspendProcess)GetProcAddress(ntdll,"NtSuspendProcess");
	if (pNtSuspendProcess) {
		HANDLE phd = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
		if (phd) {
			if (NT_SUCCESS(pNtSuspendProcess(phd)))
				result = true;
			CloseHandle(phd);
		}
	}
	return result;
}

/*++
Description:
	resume process
Arguments:
	pid - process id
Return:
	bool
--*/
bool PsResumeProcess(__in DWORD pid)
{
	bool result = false;
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	__NtResumeProcess pNtResumeProcess = (__NtResumeProcess)GetProcAddress(ntdll,"NtResumeProcess");
	if (pNtResumeProcess) {
		HANDLE phd = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
		if (phd) {
			if (NT_SUCCESS(pNtResumeProcess(phd)))
				result = true;
			CloseHandle(phd);
		}
	}
	return result;
}

/*++
Description:
	suspend thread
Arguments:
	tid - thread id
Return:
	previous suspend count
--*/
DWORD PsSuspendThread(__in DWORD tid)
{
#ifdef _AMD64_
	if (!PsThreadIsX64(tid))
		return PsSuspendWow64Thread(tid);		
#endif
	return PsSuspendNormalThread(tid);
}

/*++
Description:
	resume thread
Arguments:
	tid - thread id
Return:
	previous suspend count
--*/
DWORD PsResumeThread(__in DWORD tid)
{
	DWORD result = -1;
	HANDLE thd = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
	if (thd) {
		result = ResumeThread(thd);
		CloseHandle(thd);
	}
	return result;
}

} // namespace UNONE