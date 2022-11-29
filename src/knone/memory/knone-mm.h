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
#include <common/knone-common.h>
#include <internal/knone-internal.h>
namespace KNONE {

KNONE_API VOID MmEnableWP();
KNONE_API VOID MmDisableWP();
KNONE_API VOID MmWriteProtectOn(IN KIRQL Irql);
KNONE_API KIRQL MmWriteProtectOff();
KNONE_API ULONG MmReadKernelMemory(PVOID addr, PVOID buf, ULONG len);
KNONE_API BOOLEAN MmWriteKernelMemory(PVOID addr, PVOID buf, ULONG len);
KNONE_API PVOID MmGetRoutineAddress(IN PCWSTR name);
KNONE_API PVOID MmGetModuleBase(IN PDRIVER_OBJECT drvobj, IN WCHAR* name);
KNONE_API BOOLEAN MmIsAddressValidSafe(PVOID addr, ULONG size = 1);

} // namespace KNONE
