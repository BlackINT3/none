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
#include "md5c.h"
#include "md-wrapper.h"
#include <unone.h>

namespace UNONE {
namespace Plugins {
namespace Cryptor {

/*++
Description:
	get md5 hash by buffer data
Arguments:
	buf - buffer data
	size - buffer size
	hash - hash stream
Return:
	void
--*/
void GetMD5ByData(const char *buf, unsigned int size, char *hash)
{
	MD5_CTX	ctx = {0};
	MD5Init(&ctx);
	MD5Update(&ctx, (unsigned char*)buf, size);
	MD5Final((unsigned char*)hash, &ctx);
}

/*++
Description:
	get md5 hash by buffer data
Arguments:
	buf - buffer string
Return:
	hash stream
--*/
std::string GetMD5ByData(__in const std::string &buf)
{
	std::string hash;
	hash.resize(MD5_HASH_SIZE);
	GetMD5ByData(buf.data(), (unsigned int)buf.size(), (char*)hash.data());
	return hash;
}

/*++
Description:
	get md5 hash by file path
Arguments:
	file - file path
Return:
	hash stream
--*/
std::string GetMD5ByFile(__in const std::string &file)
{
	MD5_CTX	ctx = { 0 };
	MD5Init(&ctx);

	auto ret = UNONE::FsReadFileBlockA(file, PAGE_SIZE, [&ctx](const std::string &blk)->bool {
		MD5Update(&ctx, (unsigned char*)blk.data(), (unsigned int)blk.size());
		return true;
	});
	if (!ret) return "";

	std::string hash;
	hash.resize(MD5_HASH_SIZE);
	MD5Final((unsigned char*)hash.data(), &ctx);
	return hash;
}

} // namespace Cryptor
} // namespace Plugins
} // namespace UNONE