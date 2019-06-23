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
#include <Tlhelp32.h>
#include <Psapi.h>
#include <string>
#include <vector>
#include <functional>

namespace UNONE {
	
#define INVALID_PID -1
#define INVALID_TID -1

#ifdef _UNICODE
#define PsGetProcessInfo32 PsGetProcessInfo32W
#define PsGetProcessInfo64 PsGetProcessInfo64W
#define PsGetProcessInfo PsGetProcessInfoW
#define PsGetModulesInfo32 PsGetModulesInfo32W
#define PsGetModulesInfo64 PsGetModulesInfo64W
#define PsGetModulesInfo PsGetModulesInfoW
#define PsGetProcessName PsGetProcessNameW
#define PsGetProcessPath PsGetProcessPathW
#define PsGetProcessDir PsGetProcessDirW
#define PsGetModuleBase PsGetModuleBaseW
#define PsGetModuleName PsGetModuleNameW
#define PsGetModulePath PsGetModulePathW
#define PsGetModuleDir PsGetModuleDirW
#define PsGetWndText PsGetWndTextW
#define PsGetWndClassName PsGetWndClassNameW
#define PsKillProcessName PsKillProcessNameW
#define PsKillProcessPath PsKillProcessPathW
#define PsCreateProcess PsCreateProcessW
#define PsInjectByRemoteThread32 PsInjectByRemoteThread32W
#define PsInjectByRemoteThread64 PsInjectByRemoteThread64W
#define PsInjectByRemoteThread PsInjectByRemoteThreadW
#else
#define PsGetProcessInfo32 PsGetProcessInfo32A
#define PsGetProcessInfo64 PsGetProcessInfo64A
#define PsGetProcessInfo PsGetProcessInfoA
#define PsGetModulesInfo32 PsGetModulesInfo32A
#define PsGetModulesInfo64 PsGetModulesInfo64A
#define PsGetModulesInfo PsGetModulesInfoA
#define PsGetProcessName PsGetProcessNameA
#define PsGetProcessPath PsGetProcessPathA
#define PsGetProcessDir PsGetProcessDirA
#define PsGetModuleBase PsGetModuleBaseA
#define PsGetModuleName PsGetModuleNameA
#define PsGetModulePath PsGetModulePathA
#define PsGetModuleDir PsGetModuleDirA
#define PsGetWndText PsGetWndTextA
#define PsGetWndClassName PsGetWndClassNameA
#define PsKillProcessName PsKillProcessNameA
#define PsKillProcessPath PsKillProcessPathA
#define PsCreateProcess PsCreateProcessA
#define PsInjectByRemoteThread32 PsInjectByRemoteThread32A
#define PsInjectByRemoteThread64 PsInjectByRemoteThread64A
#define PsInjectByRemoteThread PsInjectByRemoteThreadA
#endif // _UNICODE

typedef struct _OBJECT_TABLE_ENTRY {
	HANDLE	HandleValue;
	USHORT	ObjectTypeIndex;
	ULONG	GrantedAccess;
} OBJECT_TABLE_ENTRY, *POBJECT_TABLE_ENTRY;
typedef std::function<bool(PROCESSENTRY32W &entry)> ProcessCallback;
typedef std::function<bool(THREADENTRY32 &entry)> ThreadCallback;
typedef std::function<bool(MODULEENTRY32W &entry)> ModuleCallback;
typedef std::function<bool(HEAPENTRY32 &entry)> HeapCallback;
typedef std::function<bool(SYSTEM_HANDLE_TABLE_ENTRY_INFO &entry)> HandleCallback;
typedef std::function<bool(MEMORY_BASIC_INFORMATION &mbi)> MemoryCallback;

typedef struct _PROCESS_BASE_INFOA {
	std::string ImagePathName;
	std::string CommandLine;
	std::string WindowTitle;
	std::string CurrentDirectory;
} PROCESS_BASE_INFOA, *PPROCESS_BASE_INFOA;

typedef struct _PROCESS_BASE_INFOW {
	std::wstring ImagePathName;
	std::wstring CommandLine;
	std::wstring WindowTitle;
	std::wstring CurrentDirectory;
} PROCESS_BASE_INFOW, *PPROCESS_BASE_INFOW;

typedef struct _MODULE_BASE_INFOA {
	ULONG64	DllBase;
	ULONG64 EntryPoint;
	ULONG SizeOfImage;
	std::string FullDllName;
	std::string BaseDllName;
	DWORD Flags;
	WORD LoadCount;
	DWORD TimeDateStamp;
} MODULE_BASE_INFOA, *PMODULE_BASE_INFOA;

typedef struct _MODULE_BASE_INFOW {
	ULONG64	DllBase;
	ULONG64 EntryPoint;
	ULONG SizeOfImage;
	std::wstring FullDllName;
	std::wstring BaseDllName;
	DWORD Flags;
	WORD LoadCount;
	DWORD TimeDateStamp;
} MODULE_BASE_INFOW, *PMODULE_BASE_INFOW;

enum PsInjectType {
	InjectRemoteThread,
	InjectMessageHook,
};

UNONE_API bool PsIsWow64(__in HANDLE phd = GetCurrentProcess());
UNONE_API bool PsIsWow64(__in DWORD pid);
UNONE_API bool PsIsX64(__in DWORD pid);
UNONE_API bool PsThreadIsX64(__in DWORD tid);
UNONE_API bool PsIsPidExisted(__in DWORD pid);
UNONE_API bool PsIsNameExistedA(__in const std::string &wild);
UNONE_API bool PsIsNameExistedW(__in const std::wstring &wild);
UNONE_API bool PsIsPathExistedA(__in const std::string &wild);
UNONE_API bool PsIsPathExistedW(__in const std::wstring &wild);
UNONE_API bool PsIsDeleted(__in DWORD pid);

UNONE_API bool PsGetPbi32(__in HANDLE phd, __out PROCESS_BASIC_INFORMATION32 &pbi32);
UNONE_API bool PsGetPbi64(__in HANDLE phd, __out PROCESS_BASIC_INFORMATION64 &pbi64);
UNONE_API PVOID PsGetPebAddress32(__in HANDLE phd);
UNONE_API PVOID64 PsGetPebAddress64(__in HANDLE phd);
UNONE_API DWORD PsGetParentPid(__in DWORD pid);
UNONE_API DWORD PsGetPidByThread(__in DWORD tid);
UNONE_API std::vector<DWORD> PsGetChildPids(__in DWORD pid);
UNONE_API std::vector<DWORD> PsGetDescendantPids(__in DWORD pid);
UNONE_API bool PsGetProcessInfo32A(__in DWORD pid, __out PROCESS_BASE_INFOA &info);
UNONE_API bool PsGetProcessInfo32W(__in DWORD pid, __out PROCESS_BASE_INFOW &info);
UNONE_API bool PsGetProcessInfo64A(__in DWORD pid, __out PROCESS_BASE_INFOA &info);
UNONE_API bool PsGetProcessInfo64W(__in DWORD pid, __out PROCESS_BASE_INFOW &info);
UNONE_API bool PsGetProcessInfoA(__in DWORD pid, __out PROCESS_BASE_INFOA &info);
UNONE_API bool PsGetProcessInfoW(__in DWORD pid, __out PROCESS_BASE_INFOW &info);
UNONE_API bool PsGetModulesInfo32A(__in DWORD pid, __out std::vector<MODULE_BASE_INFOA> &infos);
UNONE_API bool PsGetModulesInfo32W(__in DWORD pid, __out std::vector<MODULE_BASE_INFOW> &infos);
UNONE_API bool PsGetModulesInfo64A(__in DWORD pid, __out std::vector<MODULE_BASE_INFOA> &infos);
UNONE_API bool PsGetModulesInfo64W(__in DWORD pid, __out std::vector<MODULE_BASE_INFOW> &infos);
UNONE_API bool PsGetModulesInfoA(__in DWORD pid, __out std::vector<MODULE_BASE_INFOA> &infos);
UNONE_API bool PsGetModulesInfoW(__in DWORD pid, __out std::vector<MODULE_BASE_INFOW> &infos);

UNONE_API std::string PsGetProcessNameA(__in DWORD pid = GetCurrentProcessId());
UNONE_API std::wstring PsGetProcessNameW(__in DWORD pid = GetCurrentProcessId());
UNONE_API std::string PsGetProcessPathA(__in DWORD pid = GetCurrentProcessId());
UNONE_API std::wstring PsGetProcessPathW(__in DWORD pid = GetCurrentProcessId());
UNONE_API std::string PsGetProcessDirA(__in DWORD pid = GetCurrentProcessId());
UNONE_API std::wstring PsGetProcessDirW(__in DWORD pid = GetCurrentProcessId());
UNONE_API HMODULE PsGetModuleBaseA(__in const std::string &name, __in PVOID addr = PsIsX64);
UNONE_API HMODULE PsGetModuleBaseW(__in const std::wstring &name, __in PVOID addr = PsIsX64);
UNONE_API std::string PsGetModuleNameA(__in HMODULE base = NULL);
UNONE_API std::wstring PsGetModuleNameW(__in HMODULE base = NULL);
UNONE_API std::string PsGetModulePathA(__in const std::string &name, __in HMODULE base = NULL);
UNONE_API std::wstring PsGetModulePathW(__in const std::wstring &name, __in HMODULE base = NULL);
UNONE_API std::string PsGetModuleDirA(__in const std::string &name, __in HMODULE base = NULL);
UNONE_API std::wstring PsGetModuleDirW(__in const std::wstring &name, __in HMODULE base = NULL);
UNONE_API std::string PsGetWndTextA(__in HWND wnd);
UNONE_API std::wstring PsGetWndTextW(__in HWND wnd);
UNONE_API std::string PsGetWndClassNameA(__in HWND wnd);
UNONE_API std::wstring PsGetWndClassNameW(__in HWND wnd);
UNONE_API std::vector<HWND> PsGetWnds(__in DWORD pid);

UNONE_API bool PsGetAllProcess(__out std::vector<DWORD> &pids);
UNONE_API bool PsGetAllProcessV2(__out std::vector<DWORD> &pids);
UNONE_API bool PsGetAllThread(__in DWORD pid, __out std::vector<DWORD> &tids);
UNONE_API bool PsEnumProcess(__in ProcessCallback process_cb);
UNONE_API bool PsEnumThread(__in DWORD pid, __in ThreadCallback thread_cb);
UNONE_API bool PsEnumModule(__in DWORD pid, __in ModuleCallback module_cb);
UNONE_API bool PsEnumHandle(__in DWORD pid, __in HandleCallback handle_cb);
UNONE_API bool PsEnumMemory(__in DWORD pid, __in MemoryCallback memory_cb);

UNONE_API bool PsKillProcess(__in DWORD pid);
UNONE_API bool PsKillProcessNameA(__in const std::string &wild);
UNONE_API bool PsKillProcessNameW(__in const std::wstring &wild);
UNONE_API bool PsKillProcessPathA(__in const std::string &wild);
UNONE_API bool PsKillProcessPathW(__in const std::wstring &wild);
UNONE_API bool PsKillProcessTree(__in DWORD pid);
UNONE_API bool PsCreateProcessA(__in const std::string &cmdline, __in UINT cmdshow = SW_SHOW, __out PROCESS_INFORMATION *proc_info = NULL);
UNONE_API bool PsCreateProcessW(__in const std::wstring &cmdline, __in UINT cmdshow = SW_SHOW, __out PROCESS_INFORMATION *proc_info = NULL);
UNONE_API bool PsRestartProcess(__in DWORD pid);
UNONE_API bool PsSuspendProcess(__in DWORD pid);
UNONE_API bool PsResumeProcess(__in DWORD pid);
UNONE_API DWORD PsSuspendThread(__in DWORD tid);
UNONE_API DWORD PsResumeThread(__in DWORD tid);

UNONE_API HANDLE PsCreateRemoteThread32(__in HANDLE phd, __in ULONG32 routine, __in ULONG32 param, __in DWORD flags);
UNONE_API HANDLE PsCreateRemoteThread64(__in HANDLE phd, __in ULONG64 routine, __in ULONG64 param, __in DWORD flags);
UNONE_API HANDLE PsCreateRemoteThread(__in DWORD pid, __in ULONG64 routine, __in ULONG64 param, __in DWORD flags);
UNONE_API HANDLE PsInjectByRemoteThread32A(__in DWORD pid, __in const std::string &path);
UNONE_API HANDLE PsInjectByRemoteThread32W(__in DWORD pid, __in const std::wstring &path);
UNONE_API HANDLE PsInjectByRemoteThread64A(__in DWORD pid, __in const std::string &path);
UNONE_API HANDLE PsInjectByRemoteThread64W(__in DWORD pid, __in const std::wstring &path);
UNONE_API HANDLE PsInjectByRemoteThreadA(__in DWORD pid, __in const std::string &path);
UNONE_API HANDLE PsInjectByRemoteThreadW(__in DWORD pid, __in const std::wstring &path);


} // namespace UNONE
