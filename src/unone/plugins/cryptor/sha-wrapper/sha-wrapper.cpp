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
#include "sha1c.h"
#include "sha256.h"
#include "sha-wrapper.h"
#include <unone.h>

namespace UNONE {
namespace Plugins {
namespace Cryptor {

/*++
Description:
	get sha1 hash by buffer data
Arguments:
	buf - buffer data
	size - buffer size
	hash - hash stream
Return:
	void
--*/
void GetSHA1ByData(const char *buf, unsigned int size, char *hash)
{
	int err;
	SHA1Context sha;
	err = SHA1Reset(&sha);
	if (err != shaSuccess) {
		return;
	}
	err = SHA1Input(&sha, (const unsigned char*)buf, size);
	if (err != shaSuccess) {
		return;
	}
	err = SHA1Result(&sha, (unsigned char*)hash);
	if (err != shaSuccess) {
		return;
	}
}

/*++
Description:
	get sha1 hash by buffer data
Arguments:
	buf - buffer data
	size - buffer size
	hash - hash stream
Return:
	void
--*/
void GetSHA2ByData(const char* buf, unsigned int size, char* hash)
{
	sha256 ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, buf, size);
	sha256_sum(&ctx, (unsigned char*)hash);
}

/*++
Description:
	get sha2 hash by buffer data
Arguments:
	buf - buffer string
Return:
	hash stream
--*/
std::string GetSHA1ByData(__in const std::string &buf)
{
	std::string hash;
	hash.resize(SHA1_HASH_SIZE);
	GetSHA1ByData(buf.data(), (unsigned int)buf.size(), (char*)hash.data());
	return hash;
}

/*++
Description:
	get sha2 hash by buffer data
Arguments:
	buf - buffer string
Return:
	hash stream
--*/
std::string GetSHA2ByData(__in const std::string& buf)
{
	std::string hash;
	hash.resize(SHA2_HASH_SIZE);
	GetSHA2ByData(buf.data(), (unsigned int)buf.size(), (char*)hash.data());
	return hash;
}

/*++
Description:
	get sha1 hash by file path
Arguments:
	file - file path
Return:
	hash stream
--*/
std::string GetSHA1ByFile(__in const std::string& file)
{
	int err;
	SHA1Context sha;
	err = SHA1Reset(&sha);
	if (err != shaSuccess) {
		return "";
	}

	auto ret = UNONE::FsReadFileBlockA(file, PAGE_SIZE, [&sha, &err](const std::string& blk)->bool {
		err = SHA1Input(&sha, (const unsigned char*)blk.data(), (unsigned int)blk.size());
		return err == shaSuccess;
	});
	if (!ret || err != shaSuccess) {
		return  "";
	}
	std::string hash;
	hash.resize(SHA1_HASH_SIZE);
	err = SHA1Result(&sha, (unsigned char*)hash.data());
	if (err != shaSuccess) {
		return "";
	}
	return hash;
}

/*++
Description:
	get sha2 hash by file path
Arguments:
	file - file path
Return:
	hash stream
--*/
std::string GetSHA2ByFile(__in const std::string& file)
{
	sha256 ctx;
	sha256_init(&ctx);

	auto ret = UNONE::FsReadFileBlockA(file, PAGE_SIZE, [&ctx](const std::string& blk)->bool {
		sha256_update(&ctx, blk.c_str(), blk.size());
		return true;
	});
	if (!ret) {
		return  "";
	}
	std::string hash;
	hash.resize(SHA2_HASH_SIZE);
	sha256_sum(&ctx, (unsigned char*)hash.c_str());
	return hash;
}

} // namespace Cryptor
} // namespace Plugins
} // namespace UNONE