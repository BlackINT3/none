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
#include "file-ops.h"
namespace FileOps {

bool FsCopyDirectoryW(const std::wstring &src, const std::wstring &dst)
{
	if (!UNONE::FsIsExistedW(src)) return false;
	if (!UNONE::FsCreateDirW(dst)) return false;

	bool ret = true;
	UNONE::FsEnumDirectoryW(src, [&](wchar_t* path, wchar_t* name, void* param)->bool {
		std::wstring to_path(path);
		UNONE::StrReplaceIW(to_path, src, dst);
		if (UNONE::FsIsDirW(path)) {
			if (!UNONE::FsIsExistedW(to_path)) UNONE::FsCreateDirW(to_path);
			ret = FsCopyDirectoryW(path, to_path);
		} else {
			ret = (CopyFileW(path, to_path.c_str(), FALSE) == TRUE);
		}
		return ret;
	});
	if (!ret) UNONE::FsDeleteDirectoryW(dst);

	return ret;
}

bool FsCopyFileW(const std::wstring &src, const std::wstring &dst)
{
	bool created = false;
	std::wstring &&dst_dir = UNONE::FsPathToDirW(dst);
	if (!UNONE::FsIsExistedW(dst_dir)) {
		UNONE::FsCreateDirW(dst_dir);
		created = true;
	}
	if (!CopyFileW(src.c_str(), dst.c_str(), FALSE)) {
		if (created) UNONE::FsDeleteDirectoryW(dst_dir);
		return false;
	}
	return true;
}

bool FsCopyW(const std::wstring &src, const std::wstring &dst)
{
	if (UNONE::FsIsDirW(src))
		return FsCopyDirectoryW(src, dst);
	else 
		return FsCopyFileW(src, dst);
}

void CopyFilePattern(const std::wstring &src, const std::wstring &pattern)
{
	std::vector<std::wstring> vec;
	UNONE::StrSplitW(pattern, L";", vec);
	if (vec.size() == 2) {
		std::wstring dst(src);
		UNONE::StrReplaceIW(dst, vec[0], vec[1]);
		if (FsCopyW(src, dst)) {
			wprintf(L"[+] Copy ok: %s => %s\n", src.c_str(), dst.c_str());
		} else {
			wprintf(L"[-] Copy failed: %s => %s\n", src.c_str(), dst.c_str());
		}
	} else {
		wprintf(L"[-] pattern:%s err format\n", pattern.c_str());
	}
}

}