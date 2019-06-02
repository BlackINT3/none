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
#include "unone-fs-test.h"

TEST(TestFsBaseOps, StrTest)
{
	{// fs test
		
	}
}

TEST(TestFsPath, StrTest)
{
	{// fs path to name test
		EXPECT_TRUE(UNONE::FsPathToNameA("C:\\Windows\\System32") == "System32");
		EXPECT_TRUE(UNONE::FsPathToNameA("C:/Windows/System32") == "System32");
		EXPECT_TRUE(UNONE::FsPathToNameW(L"C:\\Windows\\System32") == L"System32");
		EXPECT_TRUE(UNONE::FsPathToNameW(L"C:/Windows/System32") == L"System32");
	}

	{// fs path to dir test
		EXPECT_TRUE(UNONE::FsPathToDirA("C:\\Windows\\System32") == "C:\\Windows");
		EXPECT_TRUE(UNONE::FsPathToDirA("C:/Windows/System32") == "C:/Windows");
		EXPECT_TRUE(UNONE::FsPathToDirW(L"C:\\Windows\\System32") == L"C:\\Windows");
		EXPECT_TRUE(UNONE::FsPathToDirW(L"C:/Windows/System32") == L"C:/Windows");
	}
	
	{// fs path compose
		EXPECT_TRUE(UNONE::FsPathComposeA("C:\\Windows\\", "\\System32\\") == "C:\\Windows\\System32\\");
		EXPECT_TRUE(UNONE::FsPathComposeW(L"C:\\Windows\\", L"\\System32\\") == L"C:\\Windows\\System32\\");
	}

	{// fs path standardize
		EXPECT_TRUE(UNONE::FsPathStandardA("C:/Windows/System32\\") == "C:\\Windows\\System32");
		EXPECT_TRUE(UNONE::FsPathStandardW(L"C:/Windows/System32\\") == L"C:\\Windows\\System32");
	}
}