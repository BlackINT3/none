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
#include <memory>
#include <map>
#include <WtsApi32.h>
#pragma comment(lib, "WtsApi32.lib")
#include <common/unone-common.h>
#include <native/unone-native.h>
#include <internal/unone-internal.h>
#include <string/unone-str.h>
#include <security/unone-se.h>
#include <time/unone-tm.h>
#include "unone-os.h"

namespace {
typedef enum _SHUTDOWN_ACTION {
	ShutdownNoReboot,
	ShutdownReboot,
	ShutdownPowerOff
} SHUTDOWN_ACTION;

typedef NTSTATUS(NTAPI *__NtShutdownSystem)(
	__in SHUTDOWN_ACTION Action
	);
}

namespace UNONE {

/*++
Description:
	check os is x64/amd64.
Arguments:
	void
Return:
	true - x64/amd64
	false - non x64/amd64
--*/
bool OsIs64()
{
	bool result = false;
	SYSTEM_INFO si;
	RtlZeroMemory(&si, sizeof(SYSTEM_INFO));
	GetNativeSystemInfo(&si);
	if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
		result = true;
	return result;
}

/*++
Description:
	check os version >= vista
Arguments:
	void
Return:
	bool
--*/
bool OsIsVistaUpper()
{
	return OsMajorVer() >= 6;
}

/*++
Description:
	get major version number of os, works in xp to win10 and compatible mode.
	in compatible mode, return real version.
Arguments:
	void
Return:
	major version, failed return 0
--*/
DWORD OsMajorVer()
{
	DWORD number = 0;
	__RtlGetNtVersionNumbers pRtlGetNtVersionNumbers = (__RtlGetNtVersionNumbers)
		GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"RtlGetNtVersionNumbers");
	if (pRtlGetNtVersionNumbers) {
		pRtlGetNtVersionNumbers(&number, NULL, NULL);
	}
	return number;
}

/*++
Description:
	get minor version number of os, works in xp to win10 and compatible mode.
	in compatible mode, return real version.
Arguments:
	void
Return:
	minor version, failed return 0
--*/
DWORD OsMinorVer()
{
	DWORD number = 0;
	__RtlGetNtVersionNumbers pRtlGetNtVersionNumbers = (__RtlGetNtVersionNumbers)
		GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"RtlGetNtVersionNumbers");
	if (pRtlGetNtVersionNumbers) {
		pRtlGetNtVersionNumbers(NULL, &number, NULL);
	}
	return number;
}

/*++
Description:
	get os version info
Arguments:
	void
Return:
	version info
--*/
std::string OsWinVersionInfo()
{
	std::string winver;
	auto major = UNONE::OsMajorVer();
	auto minor = UNONE::OsMinorVer();
	auto release = UNONE::OsBuildNumber();
	SYSTEM_INFO info;
	GetSystemInfo(&info);
	OSVERSIONINFOEX os;
	os.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	GetVersionEx((OSVERSIONINFO*)&os);
	if (major == 10 && minor == 0) {
		if (os.dwPlatformId == VER_PLATFORM_WIN32_NT) {
			if (release >= 22000) winver = "Windows 11";
			else winver = "Windows 10";
		} else {
			switch (release) {
			case 14393: winver = "Windows Server 2016"; break;
			case 17763:
			case 18363:
			case 19041:
			case 19042: winver = "Windows Server 2019"; break;
			case 20348: winver = "Windows Server 2022"; break;
			}
		}
	} else {
		switch (major) {
		case 4:
			switch (minor) {
			case 0:
				if (os.dwPlatformId == VER_PLATFORM_WIN32_NT) winver = "Windows NT 4.0";
				else if (os.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS) winver = "Windows 95";
				break;
			case 10: winver = "Windows 98"; break;
			case 90: winver = "Windows ME"; break;
			}
			break;
		case 5:
			switch (minor) {
			case 0: winver = "Windows 2000"; break;
			case 1: winver = "Windows XP"; break;
			case 2:
				if (os.wProductType == VER_NT_WORKSTATION && info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
					winver = "Windows XP Professional x64 Edition";
				else if (GetSystemMetrics(SM_SERVERR2) == 0)
					winver = "Windows Server 2003";
				else if (GetSystemMetrics(SM_SERVERR2) != 0)
					winver = "Windows Server 2003 R2";
				break;
			}
			break;
		case 6:
			switch (minor) {
			case 0:
				if (os.wProductType == VER_NT_WORKSTATION) winver = "Windows Vista";
				else winver = "Windows Server 2008";
				break;
			case 1:
				if (os.wProductType == VER_NT_WORKSTATION) winver = "Windows 7";
				else winver = "Windows Server 2008 R2";
				break;
			case 2:
				if (os.wProductType == VER_NT_WORKSTATION) winver = "Windows 8";
				else winver = "Windows Server 2012";
				break;
			case 3:
				if (os.wProductType == VER_NT_WORKSTATION) winver = "Windows 8.1";
				else winver = "Windows Server 2012 R2";
			}
			break;
		}
	}
	return winver;
}

/*++
Description:
	get minor version number of os, works in xp to win10 and compatible mode.
	in compatible mode, return real version.
Arguments:
	void
Return:
	build number, failed return 0
--*/
DWORD OsBuildNumber()
{
	DWORD number = 0;
	__RtlGetNtVersionNumbers pRtlGetNtVersionNumbers = (__RtlGetNtVersionNumbers)
		GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"RtlGetNtVersionNumbers");
	if (pRtlGetNtVersionNumbers) {
		pRtlGetNtVersionNumbers(NULL, NULL, &number);
		return number ^ 0xF0000000;
	}
	return 0;
}

/*++
Description:
	get release version number string
Arguments:
	void
Return:
	build number string
--*/
std::string OsReleaseNumber()
{
	std::pair<DWORD, std::string> pairs[] = {
		std::make_pair(10240, "1507"),
		std::make_pair(10586, "1511"),
		std::make_pair(14393, "1607"),
		std::make_pair(15063, "1703"),
		std::make_pair(16299, "1709"),
		std::make_pair(17134, "1803"),
		std::make_pair(17763, "1809"),
		std::make_pair(18362, "1903"),
		std::make_pair(18363, "1909"),
		std::make_pair(19041, "2004"),
		std::make_pair(19042, "20H2"),
		std::make_pair(19043, "21H1"),
		std::make_pair(19044, "21H2"),
		std::make_pair(19045, "22H2"),
		//Win11
		std::make_pair(22000, "21H2"),
		std::make_pair(22621, "22H2"),
	};
	std::map<DWORD, std::string> tables(pairs, pairs + _countof(pairs));
	DWORD build = UNONE::OsBuildNumber();
	auto it = tables.find(build);
	if (it != tables.end())
		return it->second;
	return "";
}

/*++
Description:
	get netbios name
Arguments:
	void
Return:
	netbios name
--*/
std::string OsNetBiosNameA()
{
	return StrToA(OsNetBiosNameW());
}

/*++
Description:
	get netbios name
Arguments:
	void
Return:
	netbios name
--*/
std::wstring OsNetBiosNameW()
{
	WCHAR name[MAX_COMPUTERNAME_LENGTH+1] = {0};
	DWORD size = MAX_COMPUTERNAME_LENGTH+1;
	if (GetComputerNameW(name, &size))
		return name;
	else
		return L"";
}

/*++
Description:
	get host name
Arguments:
	void
Return:
	host name
--*/
std::string OsHostNameA()
{
	return StrToA(OsHostNameW());
}

/*++
Description:
	get host name
Arguments:
	void
Return:
	host name
--*/
std::wstring OsHostNameW()
{
	DWORD size = 0;
	if (!GetComputerNameExW(ComputerNameDnsHostname, NULL, &size) && GetLastError() == ERROR_MORE_DATA) {
		std::unique_ptr<wchar_t> name(new(std::nothrow) wchar_t[size + 1]);
		if (name) {
			memset(name.get(), 0, size + 1);
			if (GetComputerNameExW(ComputerNameDnsHostname, name.get(), &size))
				return name.get();
		}
	}
	return L"";
}

/*++
Description:
	get current user name
Arguments:
	void
Return:
	user name
--*/
std::string OsUserNameA()
{
	return StrToA(OsUserNameW());
}

/*++
Description:
	get current user name
Arguments:
	void
Return:
	user name
--*/
std::wstring OsUserNameW()
{
	DWORD size = 0;
	if (!GetUserNameW(NULL, &size) && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
		std::unique_ptr<wchar_t> name(new(std::nothrow) wchar_t[size + 1]);
		if (name)	{
			memset(name.get(), 0, size + 1);
			if (GetUserNameW(name.get(), &size))
				return name.get();
		}
	}
	return L"";
}

/*++
Description:
	get session user name, WTS_CURRENT_SESSION is current
Arguments:
	session - session id
Return:
	session user name
--*/
std::string OsSessionUserNameA(__in DWORD id)
{
	return StrToA(OsSessionUserNameW(id));
}

/*++
Description:
	get session user name, WTS_CURRENT_SESSION is current
Arguments:
	session - session id
Return:
	session user name
--*/
std::wstring OsSessionUserNameW(__in DWORD id)
{
	LPWSTR temp_name = NULL;
	DWORD size = 0;
	std::wstring name;
	BOOL ret = WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, id, WTSUserName, &temp_name, &size);
	if (ret && temp_name != NULL) {
		name = temp_name;
		WTSFreeMemory(temp_name);
	}	else {
		UNONE_ERROR("WTSQuerySessionInformationW sessionid:%d err:%d", id, GetLastError());
	}
	return name;
}

/*++
Description:
	get windows directory (WinDir/SystemRoot)
Arguments:
	void
Return:
	directory
--*/
std::string OsWinDirA()
{
	return StrToA(OsWinDirW());
}

/*++
Description:
	get windows directory (WinDir/SystemRoot)
Arguments:
	void
Return:
	directory
--*/
std::wstring OsWinDirW()
{
	wchar_t windir[MAX_PATH] = { 0 };
	GetWindowsDirectoryW(windir, MAX_PATH);
	return windir;
}

/*++
Description:
	get system 32bit directory
Arguments:
	void
Return:
	directory
--*/
std::string OsSysDir32A()
{
	return OsIs64() ? OsSyswow64DirA() : OsSystem32DirA();
}

/*++
Description:
	get system 32bit directory
Arguments:
	void
Return:
	directory
--*/
std::wstring OsSysDir32W()
{
	return OsIs64() ? OsSyswow64DirW() : OsSystem32DirW();
}

/*++
Description:
	get system32 directory
Arguments:
	void
Return:
	directory
--*/
std::string OsSystem32DirA()
{
	return StrToA(OsSystem32DirW());
}

/*++
Description:
	get system32 directory
Arguments:
	void
Return:
	directory
--*/
std::wstring OsSystem32DirW()
{
	std::wstring wstr;
	wchar_t windir[MAX_PATH] = { 0 };
	if (GetWindowsDirectoryW(windir, MAX_PATH)) {
		wstr.append(windir);
		wstr.append(L"\\System32");
	}
	return wstr;
}

/*++
Description:
	get syswow64 directory
Arguments:
	void
Return:
	directory
--*/
std::string OsSyswow64DirA()
{
	return StrToA(OsSyswow64DirW());
}

/*++
Description:
	get syswow64 directory
Arguments:
	void
Return:
	directory
--*/
std::wstring OsSyswow64DirW()
{
	std::wstring wstr;
	wchar_t windir[MAX_PATH] = { 0 };
	if (GetWindowsDirectoryW(windir, MAX_PATH)) {
		wstr.append(windir);
		wstr.append(L"\\SysWOW64");
	}
	return wstr;
}

/*++
Description:
	get tickcount whatever os
Arguments:
	void
Return:
	tickcount
--*/
uint64_t OsTickCount()
{
	uint64_t ticks;
	typedef ULONGLONG(WINAPI* _GetTickCount64)();
	_GetTickCount64 pGetTickCount64 = (_GetTickCount64)GetProcAddress(GetModuleHandleA("kernel32"), "GetTickCount64");
	if (!pGetTickCount64) {
		ticks = (uint64_t)GetTickCount();
	} else {
		ticks = (uint64_t)pGetTickCount64();
	}
	return ticks;
}

/*++
Description:
	get startup time
Arguments:
	void
Return:
	ms
--*/
LONGLONG OsStartupTime()
{
	FILETIME		Filetime;
	SYSTEMTIME		Systime;
	ULARGE_INTEGER  *ui = (ULARGE_INTEGER*)&Filetime;
	GetSystemTime(&Systime);
	Filetime = TmSystemTimeToFile(Systime);
	ui->QuadPart -= OsTickCount() * 10000;
	return TmFileTimeToMs(Filetime);
}

/*++
Description:
	get startup time string
Arguments:
	format
Return:
	str
--*/
std::string OsStartupTimeStrA(const std::string& format)
{
	return StrToA(OsStartupTimeStrW(StrToW(format)));
}
std::wstring OsStartupTimeStrW(const std::wstring& format)
{
	return TmFormatMsW(OsStartupTime(), format, NULL);
}

/*++
Description:
	get environment
Arguments:
	void
Return:
	environment
--*/
std::string OsEnvironmentA(const std::string &env)
{
	return StrToA(OsEnvironmentW(StrToW(env)));
}

/*++
Description:
	get environment
Arguments:
	void
Return:
	environment
--*/
std::wstring OsEnvironmentW(const std::wstring &env)
{
	std::wstring wstr;
	DWORD size = 0;
	WCHAR buf[1] = { 0 };
	size = ExpandEnvironmentStringsW(env.c_str(), buf, size);
	if (size) {
		wstr.resize(size-1);
		if (!ExpandEnvironmentStringsW(env.c_str(), (LPWSTR)wstr.data(), size)) {
			wstr.clear();
		}
	}
	return wstr;
}

/*++
Description:
	ntstatus to dos error
Arguments:
	status - NTSTATUS
Return:
	dos error
--*/
DWORD OsNtToDosError(__in LONG status)
{
	DWORD err = -1;
	__RtlNtStatusToDosError pRtlNtStatusToDosError = (__RtlNtStatusToDosError)
		GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlNtStatusToDosError");
	if (pRtlNtStatusToDosError)
		err = pRtlNtStatusToDosError(status);
	return err;
}

/*++
Description:
	dos error to message
Arguments:
	err - dos error
Return:
	error message
--*/
std::string OsDosErrorMsgA(__in DWORD err)
{
	return StrToA(OsDosErrorMsgW(err));
}

/*++
Description:
	dos error to message
Arguments:
	err - dos error
Return:
	error message
--*/
std::wstring OsDosErrorMsgW(__in DWORD err)
{
	std::wstring wstr;
	LPVOID msg_buff = NULL;
	FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		err,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPWSTR)&msg_buff,
		0,
		NULL);
	if (msg_buff) {
		wstr.assign((LPWSTR)msg_buff, wcslen((LPWSTR)msg_buff)-2);
		LocalFree(msg_buff);
	}
	return wstr;
}

/*++
Description:
	fast reboot
Arguments:
	void
Return:
	bool
--*/
bool OsFastReboot()
{
	NTSTATUS status;
	__NtShutdownSystem shutdown_api = (__NtShutdownSystem)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtShutdownSystem");
	if (shutdown_api == NULL) {
		return false;
	}
	SeEnablePrivilege(SE_SHUTDOWN_NAME);
	status = shutdown_api(ShutdownReboot);
	if (!NT_SUCCESS(status)) {
		return false;
	}
	return true;
}

/*++
Description:
	fast power off
Arguments:
	void
Return:
	bool
--*/
bool OsFastPoweroff()
{
	NTSTATUS status;
	__NtShutdownSystem shutdown_api = (__NtShutdownSystem)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtShutdownSystem");
	if (shutdown_api == NULL) {
		return false;
	}
	UNONE::SeEnablePrivilege(SE_SHUTDOWN_NAME);
	status = shutdown_api(ShutdownPowerOff);
	if (!NT_SUCCESS(status)) {
		return false;
	}
	return true;
}
}