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
#include <ntifs.h>

VOID __MmEnableWP()
{
	SIZE_T cr0 = (SIZE_T)__readcr0();
	cr0 |= 0x10000;
	__writecr0(cr0);
}

VOID __MmDisableWP()
{
	SIZE_T cr0 = (SIZE_T)__readcr0();
	cr0 &= ~((SIZE_T)1 << 16);
	__writecr0(cr0);
}

VOID __MmWriteProtectOn(IN KIRQL Irql)
{
	SIZE_T cr0 = (SIZE_T)__readcr0();
	cr0 |= 0x10000;
#ifdef _AMD64_
	_enable();
#else
	__asm cli
#endif
	__writecr0(cr0);
	KeLowerIrql(Irql);
}

KIRQL __MmWriteProtectOff()
{
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	SIZE_T cr0 = (SIZE_T)__readcr0();
	cr0 &= ~((SIZE_T)1 << 16);
	__writecr0(cr0);
#ifdef _AMD64_
	_disable();
#else
	__asm sti
#endif
	return irql;
}
