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
#include "../common/knone-common.h"
#include "../internal/knone-internal.h"
#include "knone-os.h"

namespace KNONE {

/*++
Description:
	get os version
Arguments:
	void
Return:
	NTOS_VERSION
--*/
NTOS_VERSION OsNtVersion()
{
	RTL_OSVERSIONINFOEXW info;
	if (!OsGetVersionInfo(info)) return NTOS_UNKNOWN;
	
	switch (info.dwMajorVersion) {
	case 5: {
		if (info.dwMinorVersion == 1) {
			if (info.wServicePackMajor == 1) return NTOS_WINXPSP1;
			if (info.wServicePackMajor == 2) return NTOS_WINXPSP2;
			if (info.wServicePackMajor == 3) return NTOS_WINXPSP3;
			return NTOS_WINXP;
		}
		if (info.dwMinorVersion == 2) {
			if (info.wServicePackMajor == 1) return NTOS_WIN2003SP1;
			if (info.wServicePackMajor == 2) return NTOS_WIN2003SP2;
			return NTOS_WIN2003;
		}
		break;
	} case 6: {
		if (info.dwMinorVersion == 0) {
			if (info.wServicePackMajor == 1) return NTOS_WINVISTASP1;
			if (info.wServicePackMajor == 2) return NTOS_WINVISTASP2;
			return NTOS_WINVISTA;
		}
		if (info.dwMinorVersion == 1) {
			if (info.wServicePackMajor == 1) return NTOS_WIN7SP1;
			return NTOS_WIN7;
		}
		if (info.dwMinorVersion == 2) {
			return NTOS_WIN8;
		}
		if (info.dwMinorVersion == 3) {
			return NTOS_WIN81;
		}
		break;
	} case 10: {
		if (info.dwBuildNumber == 10240) return NTOS_WIN10_1507;
		if (info.dwBuildNumber == 10586) return NTOS_WIN10_1511;
		if (info.dwBuildNumber == 14393) return NTOS_WIN10_1607;
		if (info.dwBuildNumber == 15063) return NTOS_WIN10_1703;
		if (info.dwBuildNumber == 16299) return NTOS_WIN10_1709;
		if (info.dwBuildNumber == 17134) return NTOS_WIN10_1803;
		if (info.dwBuildNumber == 17763) return NTOS_WIN10_1809;
		if (info.dwBuildNumber == 18362) return NTOS_WIN10_1903;
		if (info.dwBuildNumber == 18363) return NTOS_WIN10_1909;
		if (info.dwBuildNumber == 19041) return NTOS_WIN10_2004;
		if (info.dwBuildNumber == 19042) return NTOS_WIN10_20H2;
		if (info.dwBuildNumber == 19043) return NTOS_WIN10_21H1;
		if (info.dwBuildNumber == 19044) return NTOS_WIN10_21H2;
		if (info.dwBuildNumber == 19045) return NTOS_WIN10_22H2;
		if (info.dwBuildNumber == 22000) return NTOS_WIN11_21H2;
		if (info.dwBuildNumber == 22621) return NTOS_WIN11_22H2;
		if (info.dwBuildNumber > 22621) return NTOS_WIN_MAX;
	}
	default:
		break;
	}
	return NTOS_UNKNOWN;
}

/*++
Description:
	get major version
Arguments:
	info - major version
Return:
	major version
--*/
ULONG OsMajorVersion()
{
	RTL_OSVERSIONINFOEXW info;
	if (!OsGetVersionInfo(info)) return INVALID_VERSION;
	return info.dwMajorVersion;
}

/*++
Description:
	get minor version
Arguments:
	info - minor version
Return:
	minor version
--*/
ULONG OsMinorVersion()
{
	RTL_OSVERSIONINFOEXW info;
	if (!OsGetVersionInfo(info)) return INVALID_VERSION;
	return info.dwMinorVersion;
}

/*++
Description:
	get build number
Arguments:
	info - build number
Return:
	build number
--*/
ULONG OsBuildNumber()
{
	RTL_OSVERSIONINFOEXW info;
	if (!OsGetVersionInfo(info)) return INVALID_VERSION;
	return info.dwBuildNumber;
}
/*++
Description:
	get version information
Arguments:
	info - version information
Return:
	BOOLEAN
--*/
BOOLEAN OsGetVersionInfo(IN OUT RTL_OSVERSIONINFOEXW &info)
{
	NTSTATUS status;
	RtlZeroMemory(&info, sizeof(info));
	info.dwOSVersionInfoSize = sizeof(info);
	status = RtlGetVersion((RTL_OSVERSIONINFOW*)&info);
	return NT_SUCCESS(status);
}

} // namespace KNONE