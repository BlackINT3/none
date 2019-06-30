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
#include <ntifs.h>
#include <ntdef.h>
#include <WinDef.h>
#include <ntstrsafe.h>

#define INVALID_VERSION -1

typedef enum _NTOS_VERSION {
	NTOS_UNKNOWN,
	NTOS_WINXP,
	NTOS_WINXPSP1,
	NTOS_WINXPSP2,
	NTOS_WINXPSP3,
	NTOS_WIN2003,
	NTOS_WIN2003SP1,
	NTOS_WIN2003SP2,
	NTOS_WINVISTA,
	NTOS_WINVISTASP1,
	NTOS_WINVISTASP2,
	NTOS_WIN7,
	NTOS_WIN7SP1,
	NTOS_WIN8,
	NTOS_WIN81,
	NTOS_WIN10_1507, //10240
	NTOS_WIN10_1511, //10586
	NTOS_WIN10_1607, //14393
	NTOS_WIN10_1703, //15063
	NTOS_WIN10_1709, //16299
	NTOS_WIN10_1803, //17134
	NTOS_WIN10_1809, //17763
	NTOS_WIN10_1903  //18362
} NTOS_VERSION, *PNTOS_VERSION;

namespace KNONE {

KNONE_API NTOS_VERSION OsNtVersion();
KNONE_API ULONG OsMajorVersion();
KNONE_API ULONG OsMinorVersion();
KNONE_API ULONG OsBuildNumber();
KNONE_API BOOLEAN OsGetVersionInfo(IN OUT RTL_OSVERSIONINFOEXW &info);


} // namespace KNONE


