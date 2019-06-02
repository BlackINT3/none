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
#include "../common/unone-common.h"
#include "../internal/unone-internal.h"
#include "../string/unone-str.h"
#include "../time/unone-tm.h"
#include "unone-fs.h"
#include <tchar.h>

namespace {
bool GetFileInfoByBlockW(__in const std::wstring& block, __in const wchar_t* type, __out std::wstring& name, __in const wchar_t* sub_translation = NULL)
{
	bool ret = false;
	struct LANGANDCODEPAGE {
		WORD language;
		WORD codepage;
	};
	UINT size = 0;
	WCHAR sub_block[MAX_PATH] = { 0 };
	if (sub_translation == NULL) {
		LANGANDCODEPAGE* Translation = NULL;
		if (!VerQueryValueW(block.c_str(), L"\\VarFileInfo\\Translation", (LPVOID*)&Translation, &size)) {
			UNONE_ERROR("VerQueryValueW err:%d", GetLastError());
			return false;
		}
		_snwprintf_s(sub_block, MAX_PATH - 1,	L"\\StringFileInfo\\%04X%04X\\%s",
			Translation->language, Translation->codepage, type);
	} else {
		_snwprintf_s(sub_block, MAX_PATH - 1, L"\\StringFileInfo\\%s\\%s",
			sub_translation, type);
	}
	LPVOID buf = NULL;
	if (VerQueryValueW(block.data(), sub_block, (LPVOID*)&buf, &size)) {
		if (buf != NULL) {
			name = (WCHAR*)buf;
			ret = true;
		}
	} else {
		UNONE_ERROR(L"VerQueryValueW %s err:%d", sub_block, GetLastError());
	}
	return ret;
}

bool GetResourceVersionInfoW(__in const std::wstring& path, __out std::wstring& verinfo)
{
	DWORD reserved1;
	DWORD reserved2 = NULL;
	DWORD versize = GetFileVersionInfoSizeW(path.c_str(), &reserved1);
	if (versize == 0) {
		UNONE_ERROR("GetFileVersionInfoSizeW err:%d", GetLastError());
		return false;
	}
	verinfo.resize(versize);
	memset((void*)verinfo.c_str(), 0, versize*2);
	if (!GetFileVersionInfoW(path.c_str(), reserved2, versize, (LPVOID)verinfo.c_str())) {
		UNONE_ERROR("GetFileVersionInfoW err:%d", GetLastError());
		return false;
	}
	return true;
}
}

namespace UNONE {

/*++
Description:
	disable wow64 file redirection, it's thread-related.
Arguments:
	old_value - internal value
Return:
	bool
--*/
bool FsDisableRedirection(__out PVOID& old_value)
{
	typedef BOOL (WINAPI* __Wow64DisableWow64FsRedirection)(PVOID* old_value);
	__Wow64DisableWow64FsRedirection pWow64DisableWow64FsRedirection;
	if( (pWow64DisableWow64FsRedirection = (__Wow64DisableWow64FsRedirection)
		GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "Wow64DisableWow64FsRedirection")) == NULL )
		return false;
	return pWow64DisableWow64FsRedirection(&old_value) == TRUE;
}

/*++
Description:
	disable wow64 file redirection, it's thread-related.
Arguments:
	old_value - internal value
Return:
	bool
--*/
bool FsEnableRedirection(__in PVOID& old_value)
{
	typedef BOOL (WINAPI* __Wow64RevertWow64FsRedirection)(PVOID old_value);
	__Wow64RevertWow64FsRedirection pWow64RevertWow64FsRedirection;
	if( (pWow64RevertWow64FsRedirection = (__Wow64RevertWow64FsRedirection)
		GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "Wow64RevertWow64FsRedirection")) == NULL )
		return false;
	return pWow64RevertWow64FsRedirection(old_value) == TRUE;
}

/*++
Description:
	get file size.
Arguments:
	fpath - file path
	fsize - file size
Return:
	bool
--*/
bool FsGetFileSizeA(__in const std::string& fpath, __out DWORD64& fsize)
{
	return FsGetFileSizeW(StrToW(fpath), fsize);
}

/*++
Description:
	get file size.
Arguments:
	fpath - file path
	fsize - file size
Return:
	bool
--*/
bool FsGetFileSizeW(__in const std::wstring& fpath, __out DWORD64& fsize)
{
	HANDLE fd = CreateFileW(fpath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fd == INVALID_HANDLE_VALUE) {
		UNONE_ERROR(L"CreateFileW %s err:%d", fpath.c_str(), GetLastError());
		return false;
	}
	DWORD hi_size = 0;
	DWORD lo_size = GetFileSize(fd, &hi_size);
	if (lo_size == INVALID_FILE_SIZE) {
		UNONE_ERROR(L"GetFileSize %s err:%d", fpath.c_str(), GetLastError());
		CloseHandle(fd);
		return false;
	}
	fsize = MAKEULONGLONG(hi_size, lo_size);
	CloseHandle(fd);
	return true;
}

/*++
Description:
	read file data.
Arguments:
	fpath - file path
	fdata - file data
Return:
	bool
--*/
bool FsReadFileDataA(__in const std::string& fpath, __out std::string& fdata)
{
	return FsReadFileDataW(StrToW(fpath), fdata);
}

/*++
Description:
	read file data.
Arguments:
	fpath - file path
	fdata - file data
Return:
	bool
--*/
bool FsReadFileDataW(__in const std::wstring& fpath, __out std::string& fdata)
{
	bool result = false;
	DWORD fsize = 0;
	HANDLE fd = CreateFileW(fpath.c_str(), GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (fd == INVALID_HANDLE_VALUE) {
		UNONE_ERROR(L"CreateFileW %s err:%d", fpath.c_str(), GetLastError());
		return false;
	}
	fsize = GetFileSize(fd, NULL);
	if (fsize == INVALID_FILE_SIZE) {
		UNONE_ERROR(L"GetFileSize %s err:%d", fpath.c_str(), GetLastError());
		CloseHandle(fd);
		return false;
	}
	if (fsize == 0) {
		UNONE_WARN(L"%s is empty file", fpath.c_str());
		CloseHandle(fd);
		return true;
	}
	char* buff = new(std::nothrow) char[fsize];
	if (buff == NULL) {
		UNONE_ERROR(L"alloc memory err");
		CloseHandle(fd);
		return false;
	}
	DWORD readlen;
	if (ReadFile(fd, buff, fsize, &readlen, NULL)) {
		if (readlen == fsize) {
			try {
				fdata.assign(buff, fsize);
				result = true;
			} catch (std::exception& e) {
				fdata.clear();
				UNONE_ERROR("c++ exception: %s", e.what());
			} catch (...) {
				fdata.clear();
				UNONE_ERROR("c++ exception: unknown");
			}
		} else {
			UNONE_ERROR(L"ReadFile %s err, expected-size:%d actual-size:%d", fpath.c_str(), fsize, readlen);
		}
	} else {
		UNONE_ERROR(L"ReadFile %s err:%d", fpath.c_str(), GetLastError());
	}
	delete[] buff;
	CloseHandle(fd);
	return result;
}

/*++
Description:
	write file data, it can write read-only file.
Arguments:
	fpath - file path
	fdata - file data
Return:
	bool
--*/
bool FsWriteFileDataA(__in const std::string& fpath, __in const std::string& fdata)
{
	return FsWriteFileDataW(StrToW(fpath), fdata);
}

/*++
Description:
	write file data, it can write read-only file.
Arguments:
	fpath - file path
	fdata - file data
Return:
	bool
--*/
bool FsWriteFileDataW(__in const std::wstring& fpath, __in const std::string& fdata)
{
	bool result = false;
	bool read_only = false;
	DWORD saved_attr = GetFileAttributesW(fpath.c_str());
	if (saved_attr != INVALID_FILE_ATTRIBUTES) {
		if (saved_attr & FILE_ATTRIBUTE_READONLY) {
			read_only = true;
			SetFileAttributesW(fpath.c_str(), saved_attr&(~FILE_ATTRIBUTE_READONLY));
		}
	}
	HANDLE fd = CreateFileW(fpath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fd != INVALID_HANDLE_VALUE) {
		DWORD writelen;
		SetEndOfFile(fd);
		if (WriteFile(fd, fdata.data(), (DWORD)fdata.size(), &writelen, NULL)) {
			if (fdata.size() == writelen) {
				result = true;
			} else {
				UNONE_ERROR(L"WriteFile %s err, expected-size:%d actual-size:%d", fpath.c_str(), fdata.size(), writelen);
			}
		} else {
			UNONE_ERROR(L"WriteFile %s err:%d", fpath.c_str(), GetLastError());
		}
		CloseHandle(fd);
	} else {
		UNONE_ERROR(L"CreateFileW %s err:%d", fpath.c_str(), GetLastError());
	}
	if (read_only)
		SetFileAttributesW(fpath.c_str(), saved_attr);
	return result;
}

/*++
Description:
	insert file data to specific position.
Arguments:
	fpath - file path
	fdata - file data
	pos - position, default -1, implies the end of file
Return:
	bool
--*/
bool FsInsertFileDataA(__in const std::string& fpath, __in std::string fdata, __in size_t pos)
{
	return FsInsertFileDataW(StrToW(fpath), fdata, pos);
}

/*++
Description:
	insert file data to specific position.
Arguments:
	fpath - file path
	fdata - file data
	pos - position, default -1, implies the end of file
Return:
	bool
--*/
bool FsInsertFileDataW(__in const std::wstring& fpath, __in std::string fdata, __in size_t pos)
{
	bool result = false;
	std::string new_data;
	FsReadFileDataW(fpath, new_data);
	if (pos == -1) {
		pos = new_data.size();
	}
	try {
		new_data.insert(pos, fdata);
		if (FsWriteFileDataW(fpath, new_data)) {
			result = true;
		}
	} catch (std::exception& e) {
		UNONE_ERROR("c++ exception: %s", e.what());
	} catch (...) {
		UNONE_ERROR("c++ exception: unknown");
	}
	return result;
}
/*++
Description:
	file path to name
Arguments:
	fpath - file path
Return:
	file name
--*/
std::string FsPathToNameA(__in const std::string& fpath)
{
	return StrToA(FsPathToNameW(StrToW(fpath)));
}

/*++
Description:
	file path to name
Arguments:
	fpath - file path
Return:
	file name
--*/
std::wstring FsPathToNameW(__in const std::wstring& fpath)
{
	try {
		return fpath.substr(fpath.find_last_of(L"\\/")+1);
	} catch (...) {
		return L"";
	}
}

/*++
Description:
	file path to dir
Arguments:
	fpath - file path
	up_level - up level
Return:
	dir
--*/
std::string FsPathToDirA(__in const std::string& fpath, __in int up_level)
{
	return StrToA(FsPathToDirW(StrToW(fpath), up_level));
}

/*++
Description:
	file path to dir
Arguments:
	fpath - file path
	up_level - up level
Return:
	dir
--*/
std::wstring FsPathToDirW(__in const std::wstring& fpath, __in int up_level)
{
	try {
		std::wstring dir(fpath);
		for (int i = 0; i < up_level; i++) {
			if (dir.empty())
				break;
			size_t offset = std::wstring::npos;
			wchar_t end = dir[dir.size()-1];
			if (end == L'\\' || end == L'/')
				offset = dir.size()-2;
			dir = dir.substr(0,dir.find_last_of(L"\\/",offset));
		}
		return dir;
	} catch (...) {
		return L"";
	}
}

/*++
Description:
	compose two path
Arguments:
	fpath - file path
	subpath - sub path
Return:
	full path
--*/
std::string FsPathComposeA(__in const std::string& fpath, __in const std::string& subpath)
{
	return StrToA(FsPathComposeW(StrToW(fpath), StrToW(subpath)));
}

/*++
Description:
	compose two path
Arguments:
	fpath - file path
	subpath - sub path
Return:
	full path
--*/
std::wstring FsPathComposeW(__in const std::wstring& fpath, __in const std::wstring& subpath)
{
	try {
		std::wstring composed;
		size_t pos = fpath.find_last_not_of(L"\\/");
		composed = fpath.substr(0, pos+1);
		if (pos != std::wstring::npos) {
			composed.append(L"\\");
		}
		pos = subpath.find_first_not_of(L"\\/");
		if (pos != std::wstring::npos) {
			composed.append(subpath.substr(pos));
		}
		return composed;
	} catch (...) {
		return L"";
	}
}

/*++
Description:
	standardize path
Arguments:
	fpath - file path
Return:
	standardized path
--*/
std::string FsPathStandardA(__in const std::string& fpath)
{
	return StrToA(FsPathStandardW(StrToW(fpath)));
}

/*++
Description:
	standardize path
Arguments:
	fpath - file path
Return:
	standardized path
--*/
std::wstring FsPathStandardW(__in const std::wstring& fpath)
{
	try {
		if (fpath.empty()) {
			return L"";
		}
		std::wstring tmp(fpath);
		StrReplaceW(tmp, L"/", L"\\");
		if (tmp.back() == L'\\') {
			tmp.erase(tmp.end()-1);
		}
		return tmp;
	} catch (...) {
		return L"";
	}
}

/*++
Description:
	create directory, could be created recursively 
Arguments:
	dir - directory
Return:
	bool
--*/
bool FsCreateDirA(const std::string& dir)
{
	return FsCreateDirW(StrToW(dir));
}

/*++
Description:
	create directory, could be created recursively  
Arguments:
	dir - directory
Return:
	bool
--*/
bool FsCreateDirW(const std::wstring& dir)
{
	if (FsIsExistedW(dir))
		return true;
	if (CreateDirectoryW(dir.c_str(),NULL))
		return true;

	bool result = true;
	std::vector<std::wstring> subdirs;
	std::wstring sub = dir;
	std::wstring str;
	do {
		str = sub;
		subdirs.push_back(sub);
		sub = FsPathToDirW(str);
	} while (str.compare(sub) != 0);

	int k = 0;
	for (int i=(int)subdirs.size()-1; i>=0; i--) {
		if (FsIsExistedW(subdirs[i])) {
			k = i;
			continue;
		}
		if (!CreateDirectoryW(subdirs[i].c_str(),NULL)) {
			//fail rollback
			for (int j=i; j<k; j++)
				RemoveDirectoryW(subdirs[j].c_str());
			result = false;
			break;
		}
	}
	return result;
}

/*++
Description:
	check directory/file is existed
Arguments:
	fpath - directory/file path
Return:
	bool
--*/
bool FsIsExistedA(const std::string& path)
{
	return FsIsExistedW(StrToW(path));
}

/*++
Description:
	check directory/file is existed
Arguments:
	fpath - directory/file path
Return:
	bool
--*/
bool FsIsExistedW(const std::wstring& path)
{
	WIN32_FILE_ATTRIBUTE_DATA attrs = {0};
	return GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &attrs) != 0;
}

/*++
Description:
	check path is a directory
Arguments:
	fpath - path
Return:
	bool
--*/
bool FsIsDirA(const std::string& path)
{
	return FsIsDirW(StrToW(path));
}

/*++
Description:
	check path is a directory
Arguments:
	fpath - path
Return:
	bool
--*/
bool FsIsDirW(const std::wstring& path)
{
	DWORD attrs = GetFileAttributesW(path.c_str());
	if (attrs != INVALID_FILE_ATTRIBUTES)	{
		if (attrs & FILE_ATTRIBUTE_DIRECTORY)
			return true;
	}
	return false;
}

/*++
Description:
	check path is a file
Arguments:
	fpath - path
Return:
	bool
--*/
bool FsIsFileA(const std::string& path)
{
	return FsIsFileW(StrToW(path));
}

/*++
Description:
	check path is a file
Arguments:
	fpath - path
Return:
	bool
--*/
bool FsIsFileW(const std::wstring& path)
{
	DWORD attrs = GetFileAttributesW(path.c_str());
	if (attrs != INVALID_FILE_ATTRIBUTES)	{
		if (!(attrs & FILE_ATTRIBUTE_DIRECTORY))
			return true;
	}
	return false;
}

/*++
Description:
	get file information
Arguments:
	path - file path
	type - FileDescription/CompanyName/InternalName/OriginalFileName/LegalCopyright/ProductName/ProductVersion
	info - retrieved information
	translation - language and codepage
Return:
	bool
--*/
bool FsGetFileInfoA(__in const std::string& path, __in const char* type, __out std::string& info, __in const char* translation)
{
	std::wstring info_w;
	std::wstring translation_w;
	if (translation != NULL)
		translation_w = StrToW(translation).c_str();

	if (FsGetFileInfoW(StrToW(path), StrToW(type).c_str(), info_w,
		translation_w.empty() ? NULL : translation_w.c_str())) {
		info = StrToA(info_w);
		return true;
	}
	return false;
}

/*++
Description:
	get file information
Arguments:
	path - file path
	type - FileDescription/CompanyName/InternalName/OriginalFileName/LegalCopyright/ProductName/ProductVersion
	info - retrieved information
	translation - language and codepage
Return:
	bool
--*/
bool FsGetFileInfoW(__in const std::wstring& path, __in const wchar_t* type, __out std::wstring& info, __in const wchar_t* translation)
{
	bool ret = false;
	std::wstring verinfo;
	if (GetResourceVersionInfoW(path, verinfo)) {
		ret = GetFileInfoByBlockW(verinfo, type, info, translation);
	}
	return ret;
}

/*++
Description:
	get file version
Arguments:
	path - file path
	version - file version string
Return:
	file version number
--*/
LONGLONG FsGetFileVersionA(__in const std::string& path, __out std::string& version)
{
	std::wstring version_w;
	LONGLONG vernumber = FsGetFileVersionW(StrToW(path), version_w);
	if (vernumber != 0) {
		version = StrToA(version_w);
	}
	return vernumber;
}

/*++
Description:
	get file version
Arguments:
	path - file path
	version - file version string
Return:
	file version number, failed return -1
--*/
LONGLONG FsGetFileVersionW(__in const std::wstring& path, __out std::wstring& version)
{
	LONGLONG vernumber = 0;
	std::wstring verinfo;

	if (!GetResourceVersionInfoW(path, verinfo)) {
		return -1;
	}

	UINT fixed_size = 0;
	VS_FIXEDFILEINFO* fixed_info = NULL;
	if (!VerQueryValueW(verinfo.data(), L"\\", (VOID **)&fixed_info, &fixed_size)) {
		UNONE_ERROR(L"VerQueryValueW err:%d", GetLastError());
		return -1;
	}

	if (fixed_info == NULL || fixed_size != sizeof(VS_FIXEDFILEINFO)) {
		UNONE_ERROR(L"fixed_info:%#x fixed_size:%#x", fixed_info, fixed_size);
		return -1;
	}

	WORD ver1 = HIWORD(fixed_info->dwFileVersionMS);
	WORD ver2 = LOWORD(fixed_info->dwFileVersionMS);
	WORD ver3 = HIWORD(fixed_info->dwFileVersionLS);
	WORD ver4 = LOWORD(fixed_info->dwFileVersionLS);
	StrFormatW(version, L"%d.%d.%d.%d", ver1, ver2, ver3, ver4);
	vernumber = MAKELONGLONG(MAKELONG(ver2, ver1), MAKELONG(ver4, ver3));

	return vernumber;
}

/*++
Description:
	get file create time
Arguments:
	path - file path
Return:
	create time
--*/
LONGLONG FsGetFileCreateTimeA(__in const std::string& path)
{
	return FsGetFileCreateTimeW(StrToW(path));
}

/*++
Description:
	get file create time
Arguments:
	path - file path
Return:
	create time
--*/
LONGLONG FsGetFileCreateTimeW(__in const std::wstring& path)
{
	LONGLONG tm = 0;
	if (!FsGetFileTimeW(path, &tm, NULL, NULL)) {
		return 0;
	}
	return tm;
}

/*++
Description:
	get file access time
Arguments:
	path - file path
Return:
	access time
--*/
LONGLONG FsGetFileAccessTimeA(__in const std::string& path)
{
	return FsGetFileAccessTimeW(StrToW(path));
}

/*++
Description:
	get file access time
Arguments:
	path - file path
Return:
	access time
--*/
LONGLONG FsGetFileAccessTimeW(__in const std::wstring& path)
{
	LONGLONG tm = 0;
	if (!FsGetFileTimeW(path, NULL, &tm, NULL)) {
		return 0;
	}
	return tm;
}

/*++
Description:
	get file modify time
Arguments:
	path - file path
Return:
	modify time
--*/
LONGLONG FsGetFileModifyTimeA(__in const std::string& path)
{
	return FsGetFileModifyTimeW(StrToW(path));
}

/*++
Description:
	get file modify time
Arguments:
	path - file path
Return:
	modify time
--*/
LONGLONG FsGetFileModifyTimeW(__in const std::wstring& path)
{
	LONGLONG tm = 0;
	if (!FsGetFileTimeW(path, NULL, NULL, &tm)) {
		return 0;
	}
	return tm;
}

/*++
Description:
	get file time
Arguments:
	path - file path
	create_tm - create time
	access_tm - access time
	modify_tm - modify time
Return:
	bool
--*/
bool FsGetFileTimeA(__in const std::string& path, __inout LONGLONG* create_tm, __inout LONGLONG* access_tm, __inout LONGLONG* modify_tm)
{
	return FsGetFileTimeW(StrToW(path), create_tm, access_tm, modify_tm);
}

/*++
Description:
	get file time
Arguments:
	path - file path
	create_tm - create time
	access_tm - access time
	modify_tm - modify time
Return:
	bool
--*/
bool FsGetFileTimeW(__in const std::wstring& path, __inout LONGLONG* create_tm, __inout LONGLONG* access_tm, __inout LONGLONG* modify_tm)
{
	bool ret = false;
	HANDLE fd = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (fd == INVALID_HANDLE_VALUE) {
		UNONE_ERROR(L"CreateFileW %s err:%d",path.c_str(), GetLastError());
		return false;
	}
	FILETIME ft1, ft2, ft3;
	if (!GetFileTime(fd, &ft1, &ft2, &ft3)) {
		UNONE_ERROR(L"GetFileTime %s err:%d", path.c_str(), GetLastError());
		CloseHandle(fd);
	}
	LARGE_INTEGER Li;
	if (create_tm != NULL) {
		Li.LowPart = ft1.dwLowDateTime;
		Li.HighPart = ft1.dwHighDateTime;
		*create_tm = Li.QuadPart / 10000;
	}
	if (access_tm != NULL) {
		Li.LowPart = ft2.dwLowDateTime;
		Li.HighPart = ft2.dwHighDateTime;
		*access_tm = Li.QuadPart / 10000;
	}
	if (modify_tm != NULL) {
		Li.LowPart = ft3.dwLowDateTime;
		Li.HighPart = ft3.dwHighDateTime;
		*modify_tm = Li.QuadPart / 10000;
	}
	ret = true;
	CloseHandle(fd);
	return ret;
}

/*++
Description:
	enum directory
Arguments:
	dir - directory
	callback - enum callback
	param - callback param
Return:
	bool
--*/
bool FsEnumDirectoryA(__in const std::string& dir, __inout FileCallbackA callback, __in void* param)
{
	return FsEnumDirectoryW(StrToW(dir), [&](wchar_t* path, wchar_t* name, void* param)->bool {
		return callback(
			(char*)StrToA(path).c_str(),
			(char*)StrToA(name).c_str(),
			param);
	}, param);
}

/*++
Description:
	enum directory
Arguments:
	dir - directory
	callback - enum callback
	param - callback param
Return:
	bool
--*/
bool FsEnumDirectoryW(__in const std::wstring& dir, __inout FileCallbackW callback, __in void* param)
{
	if (!FsIsExistedW(dir) || !FsIsDirW(dir)) return false;

	wchar_t path[MAX_PATH] = { 0 };
	_snwprintf_s(path, MAX_PATH - 1, L"%s\\*.*", dir.c_str());
	WIN32_FIND_DATAW find_data;
	HANDLE hfind = FindFirstFileW(path, &find_data);
	if (hfind == INVALID_HANDLE_VALUE) return false;

	do {
		if (!wcscmp(find_data.cFileName, L".") || !wcscmp(find_data.cFileName, L".."))
			continue;
		wchar_t fullpath[MAX_PATH] = { 0 };
		_snwprintf_s(fullpath, MAX_PATH - 1, L"%s\\%s", dir.c_str(), find_data.cFileName);
		if (!callback(fullpath, find_data.cFileName, param))
			break;
	} while (FindNextFileW(hfind, &find_data));
	FindClose(hfind);
	return true;
}

/*++
Description:
	delete directory include sub files
Arguments:
	dir - directory
Return:
	bool
--*/
bool FsDeleteDirectoryA(__in const std::string& dir)
{
	return FsDeleteDirectoryW(StrToW(dir));
}

/*++
Description:
	delete directory include sub files
Arguments:
	dir - directory
Return:
	bool
--*/
bool FsDeleteDirectoryW(__in const std::wstring& dir)
{
	if (!FsIsExistedW(dir)) return true;
	bool ret = true;
	FsEnumDirectoryW(dir, [&ret](wchar_t* path, wchar_t* name, void* param)->bool {
		if (FsIsDirW(path)) {
			ret = FsDeleteDirectoryW(path);
		} else {
			ret = (DeleteFileW(path) == TRUE);
		}
		return ret;
	});
	if (ret) {
		ret = (RemoveDirectoryW(dir.c_str()) == TRUE);
	}
	return ret;
}

} // namespace UNONE