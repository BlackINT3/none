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
#include <tchar.h>
#include <common/unone-common.h>
#include <native/unone-native.h>
#include <internal/unone-internal.h>
#include <string/unone-str.h>
#include "unone-se.h"

namespace {
enum PRIVILEGE_OPERATE {
	PRIVILEGE_UNKNOWN,
	PRIVILEGE_ENBALE,
	PRIVILEGE_DISABLE
};
bool OpProcessPrivilegeByApi(const wchar_t* priv_name, PRIVILEGE_OPERATE operate_type)
{
	typedef BOOL (WINAPI* __OpenProcessToken)(
		__in        HANDLE ProcessHandle,
		__in        DWORD DesiredAccess,
		__deref_out PHANDLE TokenHandle
		);
	typedef BOOL (WINAPI* __LookupPrivilegeValueW)(
		__in_opt LPCWSTR lpSystemName,
		__in     LPCWSTR lpName,
		__out    PLUID   lpLuid
		);
	typedef BOOL (WINAPI* __AdjustTokenPrivileges)(
		__in      HANDLE TokenHandle,
		__in      BOOL DisableAllPrivileges,
		__in_opt  PTOKEN_PRIVILEGES NewState,
		__in      DWORD BufferLength,
		__out_bcount_part_opt(BufferLength, *ReturnLength) PTOKEN_PRIVILEGES PreviousState,
		__out_opt PDWORD ReturnLength
		);
	bool result = false;
	HANDLE token;
	LUID name_value;
	TOKEN_PRIVILEGES tp;
	do {
		HMODULE advapi32 = GetModuleHandleW(L"advapi32.dll");
		if (advapi32 == NULL) {
			advapi32 = LoadLibraryW(L"advapi32.dll");
			if (advapi32 == NULL) break;
		}
		__OpenProcessToken pOpenProcessToken = (__OpenProcessToken)GetProcAddress(advapi32, "OpenProcessToken");
		__LookupPrivilegeValueW pLookupPrivilegeValueW = (__LookupPrivilegeValueW)GetProcAddress(advapi32, "LookupPrivilegeValueW");
		__AdjustTokenPrivileges pAdjustTokenPrivileges = (__AdjustTokenPrivileges)GetProcAddress(advapi32, "AdjustTokenPrivileges");
		if (pOpenProcessToken == NULL || pLookupPrivilegeValueW == NULL || pAdjustTokenPrivileges == NULL) {
			break;
		}
		if (!pOpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &token)) {
			UNONE_ERROR("OpenProcessToken err:%d",GetLastError());
			break;
		}
		if (!pLookupPrivilegeValueW(NULL, priv_name, &name_value)) {
			UNONE_ERROR("LookupPrivilegeValueW err:%d",GetLastError());
			CloseHandle(token);
			break;
		}
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = name_value;
		if (operate_type == PRIVILEGE_ENBALE)
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		else
			tp.Privileges[0].Attributes = 0;
		if (!pAdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL) || 
			GetLastError() != ERROR_SUCCESS) {
			UNONE_ERROR("AdjustTokenPrivileges err:%d",GetLastError());
			CloseHandle(token); 
			break;
		}
		CloseHandle(token);
		result = true;
	} while(0);
	return result;
}

bool OpProcessPrivilegeByNative(DWORD priv_number, PRIVILEGE_OPERATE operate_type)
{
	NTSTATUS status;
	BOOLEAN enable;
	BOOLEAN was_enabled = FALSE;
	bool result = false;
	__RtlAdjustPrivilege pRtlAdjustPrivilege = NULL;
	do {
		pRtlAdjustPrivilege = (__RtlAdjustPrivilege)GetProcAddress(
			GetModuleHandleW(L"ntdll.dll"), "RtlAdjustPrivilege");
		if (pRtlAdjustPrivilege == NULL) break;
		enable = (operate_type == PRIVILEGE_ENBALE);
		status = pRtlAdjustPrivilege(priv_number, enable, FALSE, &was_enabled);	//SE_DEBUG_PRIVILEGE=20
		if (!NT_SUCCESS(status)) {
			UNONE_ERROR("RtlAdjustPrivilege err:%x", status);
			break;
		}
		result = true;
	} while (0);
	return result;
}
}

namespace UNONE {

/*++
Description:
	enable privilege
Arguments:
	priv_name - privilege name
	priv_number - privilege number
Return:
	bool
--*/
bool SeEnablePrivilegeA(__in const char* priv_name, __in DWORD priv_number)
{
	return SeEnablePrivilegeW(StrToW(priv_name).c_str(), priv_number);
}

/*++
Description:
	enable privilege
Arguments:
	priv_name - privilege name
	priv_number - privilege number
Return:
	bool
--*/
bool SeEnablePrivilegeW(__in const wchar_t* priv_name, __in DWORD priv_number)
{
	if (priv_name != NULL)
		return OpProcessPrivilegeByApi(priv_name, PRIVILEGE_ENBALE);
	else
		return OpProcessPrivilegeByNative(priv_number, PRIVILEGE_ENBALE);
}

/*++
Description:
	enable privilege
Arguments:
	priv_name - privilege name
	priv_number - privilege number
Return:
	bool
--*/
bool SeDisablePrivilegeA(__in const char* priv_name, __in DWORD priv_number)
{
	return SeDisablePrivilegeW(StrToW(priv_name).c_str(), priv_number);
}

/*++
Description:
	enable privilege
Arguments:
	priv_name - privilege name
	priv_number - privilege number
Return:
	bool
--*/
bool SeDisablePrivilegeW(__in const wchar_t* priv_name, __in DWORD priv_number)
{
	if (priv_name != NULL)
		return OpProcessPrivilegeByApi(priv_name, PRIVILEGE_DISABLE);
	else
		return OpProcessPrivilegeByNative(priv_number, PRIVILEGE_DISABLE);
}


/*++
Description:
	enable debug privilege
Arguments:
	natived - use native
Return:
	bool
--*/
bool SeEnableDebugPrivilege(__in bool natived)
{
	if (natived)
		return SeEnablePrivilege(NULL, SE_DEBUG_PRIVILEGE);
	else
		return SeEnablePrivilege(SE_DEBUG_NAME);
}

/*++
Description:
	disable debug privilege
Arguments:
	natived - use native
Return:
	bool
--*/
bool SeDisableDebugPrivilege(__in bool natived)
{
	if (natived)
		return SeDisablePrivilege(NULL, SE_DEBUG_PRIVILEGE);
	else
		return SeDisablePrivilege(SE_DEBUG_NAME);
}

}