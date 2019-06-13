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
#include <Ws2tcpip.h>
#include <Windows.h>
#include <common/unone-common.h>
#include <native/unone-native.h>
#include <internal/unone-internal.h>
#include <string/unone-str.h>
#include "unone-net.h"

#pragma comment(lib, "Ws2_32.lib")

namespace UNONE {

/*++
Description:
	get ip list
Arguments:
	domain - domain name
	ips - ip list
Return:
	bool
--*/
bool NetGetIpv4List(__in const std::string &domain, __out std::vector<std::string> &ips)
{
	bool ret = false;
	WSADATA wsa;
	WORD ver = MAKEWORD(2, 2);
	if (WSAStartup(ver, &wsa) != 0) {
		UNONE_ERROR("WSAStartup err:%d", WSAGetLastError());
		return false;
	}
	struct hostent* host = NULL;
	host = gethostbyname(domain.c_str());
	if (!host) {
		UNONE_ERROR("gethostbyname %s err:%d", domain.c_str(), WSAGetLastError());
		return false;
	}
	char **addrs = host->h_addr_list;
	for (int i = 0; addrs[i] != NULL; i++) {
		ips.push_back(inet_ntoa(*(struct in_addr*)addrs[i]));
	}
	WSACleanup();
	return true;
}

/*++
Description:
	get ip list
Arguments:
	domain - domain name
	ips - ip list
Return:
	bool
--*/
bool NetGetIpv4ListV2(__in const std::string &domain, __out std::vector<std::string> &ips)
{
	bool ret = false;
	WSADATA wsa;
	WORD ver = MAKEWORD(2, 2);
	if (WSAStartup(ver, &wsa) != 0) {
		UNONE_ERROR("WSAStartup err:%d", WSAGetLastError());
		return false;
	}
	struct addrinfo *info = NULL;
	struct addrinfo *res = NULL;
	struct addrinfo hints = { 0 };
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	int err = getaddrinfo(domain.c_str(), NULL, &hints, &res);
	if (err != 0) {
		UNONE_ERROR("getaddrinfo %s err:%d", domain.c_str(), err);
		return false;
	}
	for (info = res; info != NULL; info = info->ai_next) {
		switch (info->ai_family) {
		case AF_INET:
			sockaddr_in *addr = (struct sockaddr_in*)info->ai_addr;
			if (addr) ips.push_back(inet_ntoa(addr->sin_addr));
		}
	}
	freeaddrinfo(res);
	WSACleanup();
	return true;
}

} // namespace UNONE