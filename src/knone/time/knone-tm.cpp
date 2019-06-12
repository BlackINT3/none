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
#include "knone-tm.h"

#define DELAY_ONE_MICROSECOND   ( -10 )
#define DELAY_ONE_MILLISECOND  ( DELAY_ONE_MICROSECOND * 1000 )

namespace KNONE {

/*++
Description:
	sleep (implemented by KeDelayExecutionThread)
Arguments:
	ms - millisecond
Return:
	NTSTATUS
--*/
NTSTATUS TmSleepV1(IN LONG ms)
{
	LARGE_INTEGER interval;
	interval.QuadPart = DELAY_ONE_MILLISECOND;
	interval.QuadPart *= ms;
	return KeDelayExecutionThread(KernelMode, FALSE, &interval);
}

/*++
Description:
	sleep (implemented by KeWaitForSingleObject)
Arguments:
	ms - millisecond
Return:
	NTSTATUS
--*/
NTSTATUS TmSleepV2(IN LONG ms)
{
	KEVENT evt;
	LARGE_INTEGER	wait;
	KeInitializeEvent(&evt, SynchronizationEvent, FALSE);
	wait = RtlConvertLongToLargeInteger(ms * DELAY_ONE_MILLISECOND);
	return KeWaitForSingleObject(&evt, Executive, KernelMode, FALSE, &wait);
}

} // namespace KNONE
