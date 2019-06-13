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
#include "rc-wrapper.h"
#include "rc4.h"
#include <unone.h>

namespace UNONE {
namespace Plugins {
namespace Cryptor {

/*++
Description:
	rc4 decrypt or encrypt
Arguments:
	key - key
	buffer - buffer
	bufsize - buffer size
Return:
	bool
--*/
bool RC4(__in char *key, __inout unsigned char *buffer, __in int bufsize)
{
	rc4_key key_impl;
	prepare_key(key, &key_impl);
	rc4_impl(buffer, bufsize, &key_impl);
	return true;
}
/*++
Description:
	rc4 decrypt or encrypt
Arguments:
	key - key
	data - buffer
Return:
	bool
--*/
bool RC4(__in const std::string &key, __inout std::string &data)
{
	return RC4((char*)key.c_str(), (unsigned char*)data.c_str(), (int)data.size());
}

} // namespace Cryptor
} // namespace Plugins
} // namespace UNONE