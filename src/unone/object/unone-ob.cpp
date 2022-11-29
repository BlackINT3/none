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
#include <Psapi.h>
#include <shlwapi.h>
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "shlwapi.lib")
#include <common/unone-common.h>
#include <native/unone-native.h>
#include <internal/unone-internal.h>
#include <file/unone-fs.h>
#include <os/unone-os.h>
#include <security/unone-se.h>
#include <string/unone-str.h>
#include "unone-ob.h"

namespace {

}

namespace UNONE {
/*++
Description:
	parse symbolic link name
	eg:
	\??\Volume{2ef08931-cc52-11e4-b7c4-005056c00008} => \Device\HarddiskVolume3
Arguments:
	symlnk - symbolic lnk name
	target - parsed name
Return:
	bool
--*/
bool ObParseSymbolicLinkA(__in const std::string& symlnk, __out std::string& target)
{
	std::wstring target_w;
	if (ObParseSymbolicLinkW(StrToW(symlnk), target_w)) {
		target = StrToA(target_w);
		return true;
	}
	return false;
}

/*++
Description:
	parse symbolic link name
	eg:
	\??\Volume{2ef08931-cc52-11e4-b7c4-005056c00008} => \Device\HarddiskVolume3
Arguments:
	symlnk - symbolic lnk name
	target - parsed name
Return:
	bool
--*/
bool ObParseSymbolicLinkW(__in const std::wstring& symlnk, __out std::wstring& target)
{
	bool result = false;
	do {
		WCHAR* buff;
		ULONG retlen;
		HANDLE symlnk_obj;
		OBJECT_ATTRIBUTES oa;
		UNICODE_STRING ustr, name_str;
		HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
		__RtlInitUnicodeString pRtlInitUnicodeString = (__RtlInitUnicodeString)GetProcAddress(ntdll,"RtlInitUnicodeString");
		if (pRtlInitUnicodeString == NULL)
			break;
		__NtOpenSymbolicLinkObject pNtOpenSymbolicLinkObject = (__NtOpenSymbolicLinkObject)GetProcAddress(ntdll,"NtOpenSymbolicLinkObject");
		if (pNtOpenSymbolicLinkObject == NULL)
			break;
		__NtQuerySymbolicLinkObject pNtQuerySymbolicLinkObject = (__NtQuerySymbolicLinkObject) GetProcAddress(ntdll,"NtQuerySymbolicLinkObject");
		if (pNtQuerySymbolicLinkObject == NULL)
			break;
		__NtClose pNtClose = (__NtClose)GetProcAddress(ntdll,"NtClose");
		if (!pNtClose)
			break;
		pRtlInitUnicodeString(&ustr, symlnk.c_str());
		InitializeObjectAttributes(&oa, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);
		NTSTATUS status = pNtOpenSymbolicLinkObject(&symlnk_obj, SYMBOLIC_LINK_QUERY, &oa);
		if (!NT_SUCCESS(status))
			break;
		buff = new(std::nothrow) WCHAR[512];
		if (!buff)
			break;
		RtlZeroMemory(buff, 512*2);
		name_str.Buffer = buff;
		name_str.Length = 0;
		name_str.MaximumLength = 512*2;
		status = pNtQuerySymbolicLinkObject(symlnk_obj, &name_str, &retlen);
		if (!NT_SUCCESS(status)) {
			delete[] buff;
			if (status != STATUS_BUFFER_TOO_SMALL)
				break;
			buff = new(std::nothrow) WCHAR[retlen/2];
			if (!buff)
				break;
			RtlZeroMemory(buff, retlen);
			name_str.Buffer = buff;
			name_str.Length = 0;
			name_str.MaximumLength = (USHORT)retlen;
			status = pNtQuerySymbolicLinkObject(symlnk_obj, &name_str, &retlen);
			if (!NT_SUCCESS(status))
				break;
		}
		target.assign(name_str.Buffer, name_str.Length/2);
		result = true;
		delete[] buff;
	} while (0);
	return result;
}

/*++
Description:
	parse symbolic link / nt path to dos path
	eg:
	\??\Volume{2ef08931-cc52-11e4-b7c4-005056c00008}\Windows => C:\Windows
	\Device\HarddiskVolume3\Windows => C:\Windows
Arguments:
	ori_path - symbolic link path / nt path
	dos_path - dos path
Return:
	bool
--*/
bool ObParseToDosPathA(__in std::string ori_path, __out std::string& dos_path)
{
	std::wstring wstr;
	if (ObParseToDosPathW(StrToW(ori_path), wstr)) {
		dos_path = StrToA(wstr);
		return true;
	}
	return false;
}

/*++
Description:
	parse symbolic link / NT path to DOS path
	eg:
	\??\Volume{2ef08931-cc52-11e4-b7c4-005056c00008}\Windows => C:\Windows
	\Device\HarddiskVolume3\Windows => C:\Windows
Arguments:
	ori_path - symbolic link path / NT path
	dos_path - dos path
Return:
	bool
--*/
bool ObParseToDosPathW(__in std::wstring ori_path, __out std::wstring& dos_path)
{
	bool result = false;

	//symbolic name
	std::wstring dospath, wstr, symlnk;
	WCHAR* path = (WCHAR*)ori_path.c_str();
	if (wcsncmp(path,L"\\??\\",sizeof(L"\\??\\")/2-1) == 0) {
		symlnk = path;
		symlnk = StrTruncateW(symlnk,L"\\??\\",L"\\");
		symlnk = L"\\??\\" + symlnk;
		if (ObParseSymbolicLinkW(symlnk,wstr)) {
			WCHAR* subpath = path + symlnk.size();
			ori_path = wstr + subpath;
		}
	}

	//parse nt path
	const DWORD driveslen = sizeof(DWORD)*('Z'-'A'+2);
	WCHAR drives[driveslen] = {0};
	DWORD size = GetLogicalDriveStringsW(driveslen, drives);
	if (size < driveslen) {
		DWORD i = 0;
		while (i < size) {
			WCHAR target[MAX_PATH*2] = {0};
			WCHAR volume[3] = L" :";
			volume[0] = drives[i];
			i += sizeof(DWORD);
			if (QueryDosDeviceW(volume, target, MAX_PATH*2-1) == 0)
				continue;
			int targetlen = (int)wcslen(target);
			if (_wcsnicmp(ori_path.c_str(), target, targetlen) == 0) {
				dos_path = volume + ori_path.substr(targetlen);
				result = true;
				break;
			}
		}
	}
	return result;
}

/*++
Description:
	parse symbolic link / DOS path to NT path
	eg:
	\??\Volume{2ef08931-cc52-11e4-b7c4-005056c00008}\Windows => \Device\HarddiskVolume3\Windows
	C:\Windows => \Device\HarddiskVolume3\Windows
Arguments:
	ori_path - symbolic link path / DOS path
	nt_path - NT path
Return:
	bool
--*/
bool ObParseToNtPathA(__in std::string ori_path, __out std::string& nt_path)
{
	std::wstring wstr;
	if (ObParseToNtPathW(StrToW(ori_path), wstr)) {
		nt_path = StrToA(wstr);
		return true;
	}
	return false;
}

/*++
Description:
	parse symbolic link / DOS path to NT path
	eg:
	\??\Volume{2ef08931-cc52-11e4-b7c4-005056c00008}\Windows => \Device\HarddiskVolume3\Windows
	C:\Windows => \Device\HarddiskVolume3\Windows
Arguments:
	ori_path - symbolic link path / DOS path
	nt_path - NT path
Return:
	bool
--*/
bool ObParseToNtPathW(__in std::wstring ori_path, __out std::wstring& nt_path)
{
	//symbolic name
	std::wstring wstr, symlnk;
	WCHAR* path = (WCHAR*)ori_path.c_str();
	if (wcsncmp(path,L"\\??\\",sizeof(L"\\??\\")/2-1) == 0) {
		symlnk = path;
		symlnk = StrTruncateW(symlnk,L"\\??\\",L"\\");
		symlnk = L"\\??\\" + symlnk;
		if (ObParseSymbolicLinkW(symlnk,wstr)) {
			WCHAR* subpath = path + symlnk.size();
			nt_path = wstr + subpath;
			return true;
		}
		return false;
	}

	//dos path
	if (ori_path.size()<2 || ori_path[1]!=L':') {
		UNONE_ERROR(L"DosPath:%s illegal", ori_path.c_str());
		return false;
	}
	std::wstring volume = ori_path.substr(0,2);
	std::wstring rel = ori_path.substr(2);
	WCHAR target[MAX_PATH*2] = {0};
	if (QueryDosDeviceW(volume.c_str(), target, MAX_PATH*2-1) == 0) {
		UNONE_ERROR(L"QueryDosDeviceW %s err:%d", volume.c_str(), GetLastError());
		return false;
	}
	nt_path = target + rel;
	return true;
}



/*++
Description:
	load driver registry
Arguments:
	file_path - driver file path
	srv_name - driver service name
Return:
	bool
--*/
bool ObLoadDriverRegistryW(__in const std::wstring &file_path, __in std::wstring srv_name)
{
	HKEY subkey = NULL;
	do {
		std::wstring driver_path = UNONE::FsPathStandardW(L"\\??\\" + file_path);
		DWORD dispos;
		std::wstring key_name = L"SYSTEM\\CurrentControlSet\\services\\" + srv_name;
		LONG result = RegCreateKeyExW(HKEY_LOCAL_MACHINE, key_name.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &subkey, &dispos);
		if (result != ERROR_SUCCESS) {
			UNONE_ERROR(L"RegCreateKeyExW %s err:%d", key_name.c_str(), result);
			return false;
		}
		DWORD start = SERVICE_DEMAND_START;
		result = RegSetValueExW(subkey, L"Start", 0, REG_DWORD, (BYTE*)&start, sizeof(start));
		if (result != ERROR_SUCCESS) {
			UNONE_ERROR(L"RegSetValueW err:%d", result);
			break;
		}

		DWORD type = SERVICE_KERNEL_DRIVER;
		result = RegSetValueExW(subkey, L"Type", 0, REG_DWORD, (BYTE*)&type, sizeof(type));
		if (result != ERROR_SUCCESS) {
			UNONE_ERROR(L"RegSetValueW err:%d", result);
			break;
		}

		DWORD errctl = SERVICE_ERROR_NORMAL;
		result = RegSetValueExW(subkey, L"ErrorControl", 0, REG_DWORD, (BYTE*)&errctl, sizeof(errctl));
		if (result != ERROR_SUCCESS) {
			UNONE_ERROR(L"RegSetValueW err:%d", result);
			break;
		}

		result = RegSetValueExW(subkey, L"ImagePath", 0, REG_EXPAND_SZ, (BYTE*)driver_path.c_str(), (DWORD)driver_path.size() * 2);
		if (result != ERROR_SUCCESS) {
			UNONE_ERROR(L"RegSetValueW err:%d", result);
			break;
		}
	} while (0);
	if (subkey)	RegCloseKey(subkey);
	return true;
}

/*++
Description:
	load driver
Arguments:
	file_path - driver file path
	srv_name - driver service name
Return:
	bool
--*/
bool ObLoadDriverA(__in const std::string &file_path, __in std::string srv_name)
{
	return ObLoadDriverW(UNONE::StrToW(file_path), UNONE::StrToW(srv_name));
}

/*++
Description:
	load driver
Arguments:
	file_path - driver file path
	srv_name - driver service name
Return:
	bool
--*/
bool ObLoadDriverW(__in const std::wstring &file_path, __in std::wstring srv_name)
{
	if (srv_name.empty()) srv_name = FsPathToPureNameW(file_path);
	if (!SeEnablePrivilegeW(NULL, SE_LOAD_DRIVER_PRIVILEGE)) {
		UNONE_ERROR("enable SE_LOAD_DRIVER_PRIVILEGE err");
		return false;
	}
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	auto pRtlInitUnicodeString = (__RtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
	if (!pRtlInitUnicodeString) return false;
	auto pNtLoadDriver = (__NtLoadDriver)GetProcAddress(ntdll, "NtLoadDriver");
	if (!pNtLoadDriver) return false;



	bool ret = true;
	NTSTATUS status;
	UNICODE_STRING ustr;
	std::wstring wstr = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + srv_name;
	pRtlInitUnicodeString(&ustr, wstr.c_str());
	status = pNtLoadDriver(&ustr);
	if (!NT_SUCCESS(status)) {
		UNONE_ERROR(L"NtLoadDriver service:%s err:%x", wstr.c_str(), status);
		ret = false;
	}
	return ret;
}

/*++
Description:
	unload driver
Arguments:
	srv_name - driver service name
Return:
	bool
--*/
bool ObUnloadDriverA(__in const std::string &srv_name)
{
	return ObUnloadDriverW(UNONE::StrToW(srv_name));
}

/*++
Description:
	unload driver
Arguments:
	srv_name - driver service name
Return:
	bool
--*/
bool ObUnloadDriverW(__in const std::wstring &srv_name)
{
	if (!SeEnablePrivilegeW(NULL, SE_LOAD_DRIVER_PRIVILEGE)) {
		UNONE_ERROR("enable SE_LOAD_DRIVER_PRIVILEGE err");
		return false;
	}
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	auto pRtlInitUnicodeString = (__RtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
	if (!pRtlInitUnicodeString) return false;
	auto pNtUnloadDriver = (__NtUnloadDriver)GetProcAddress(ntdll, "NtUnloadDriver");
	if (!pNtUnloadDriver) return false;

	NTSTATUS status;
	UNICODE_STRING ustr;
	std::wstring wstr = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + srv_name;
	std::wstring key_name = L"SYSTEM\\CurrentControlSet\\services\\" + srv_name;
	pRtlInitUnicodeString(&ustr, wstr.c_str());
	status = pNtUnloadDriver(&ustr);
	if (!NT_SUCCESS(status)) {
		UNONE_ERROR(L"NtUnloadDriver service:%s err:%x", wstr.c_str(), status);
		return false;
	}
	SHDeleteKeyW(HKEY_LOCAL_MACHINE, key_name.c_str());
	return true;
}

/*++
Description:
	get driver list
Arguments:
	drivers - driver list
Return:
	bool
--*/
bool ObGetDriverList(__out std::vector<LPVOID> &drivers)
{
	DWORD needed = 0;
	if (EnumDeviceDrivers(NULL, 0, &needed)) {
		int count = needed / sizeof(LPVOID);
		std::vector<LPVOID> images;
		images.resize(count);
		if (EnumDeviceDrivers(&images[0], needed, &needed)) {
			SYSTEM_INFO sysinfo;
			GetSystemInfo(&sysinfo);
			for (size_t i = 0; i < images.size(); i++) {
				auto addr = images[i];
				if (addr > sysinfo.lpMaximumApplicationAddress)
					drivers.push_back(addr);
			}
			return true;
		}
		drivers.clear();
	}
	return false;
}

/*++
Description:
	get driver name
Arguments:
	driver - driver image base
Return:
	bool
--*/
std::string ObGetDriverNameA(__in LPVOID driver)
{
	return StrToA(ObGetDriverNameW(driver));
}

/*++
Description:
	get driver name
Arguments:
	driver - driver image base
Return:
	bool
--*/
std::wstring ObGetDriverNameW(__in LPVOID driver)
{
	WCHAR data[MAX_PATH] = { 0 };
	if (GetDeviceDriverBaseNameW(driver, data, MAX_PATH - 1)) {
		return data;
	}
	return L"";
}

/*++
Description:
	get driver path
Arguments:
	driver - driver image base
Return:
	bool
--*/
std::string ObGetDriverPathA(__in LPVOID driver)
{
	return StrToA(ObGetDriverPathW(driver));
}

/*++
Description:
	get driver path
Arguments:
	driver - driver image base
Return:
	bool
--*/
std::wstring ObGetDriverPathW(__in LPVOID driver)
{
	WCHAR data[MAX_PATH] = { 0 };
	if (GetDeviceDriverFileNameW(driver, data, MAX_PATH - 1)) {
		std::wstring path = data;
		std::wstring sysroot = L"\\SystemRoot";
		auto pos = path.find(sysroot);
		if (pos == 0) path.replace(0, sysroot.size(), OsWinDirW());
		StrReplaceW(path, L"\\??\\");
		return path;
	}
	return L"";
}

/*++
Description:
	get current ntoskrnl.exe path
Arguments:
	void
Return:
	path
--*/
std::string ObGetNtKernelFilePath()
{
	std::string path;
	DWORD needed = 1;
	PVOID base = NULL;
	if (EnumDeviceDrivers(&base, sizeof(LPVOID), &needed)) {
		path = ObGetDriverPathA(base);
	}
	return path;
}

}