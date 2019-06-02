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

#ifdef _MSC_VER
#pragma warning (push)
#pragma warning (disable : 4099)

#include "../../unone/unone.h"
#include "../gtest/include/gtest.h"
#include <tchar.h>

#pragma warning (pop)
#endif

#include <stdio.h>
#include <string>
inline void Out(unsigned int num)
{
	printf("%d\n", num);
}
inline void Out64(unsigned long long num64)
{
	printf("%lld\n", num64);
}
inline void Out(std::string str)
{
	printf("%s\n", str.c_str());
}
inline void Out(std::wstring wstr)
{
	wprintf(L"%s\n", wstr.c_str());
}