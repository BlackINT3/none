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
void CopyFilePattern(const std::wstring &src, const std::wstring &pattern)
{
	std::vector<std::wstring> vec;
	UNONE::StrSplitW(pattern, L";", vec);
	if (vec.size() == 2) {
		std::wstring dst(src);
		UNONE::StrReplaceIW(dst, vec[0], vec[1]);
		if (UNONE::FsCopyW(src, dst)) {
			wprintf(L"[+] Copy ok: %s => %s\n", src.c_str(), dst.c_str());
		} else {
			wprintf(L"[-] Copy failed: %s => %s\n", src.c_str(), dst.c_str());
		}
	} else {
		wprintf(L"[-] pattern:%s err format\n", pattern.c_str());
	}
}

}