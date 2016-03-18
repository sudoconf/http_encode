#include <stdio.h>

#include "HTTPRedirect.h"
#include "HTTPSeclusion.h"
#include "HTTPReconnect.h"
#include "FakeCommandLine.h"

#include "HookControl\HookHelp.h"
#include "CommonControl\Commondef.h"
#include <ws2tcpip.h>

#pragma  comment(lib,"WS2_32.lib")

#pragma  comment(lib,DIRECTORY_LIB_INTERNAL "HookControl.lib")
#pragma  comment(lib,DIRECTORY_LIB_INTERNAL "CommonControl.lib")

__declspec(dllexport) void _()
{

}

namespace Global {
	CDebug Log("Test.log");
	CHTTPReconnect cHttpReconnect;
}

namespace FUN {
	FUN::__pfnGetCommandLineW GetCommandLineW = NULL;

	FUN::__pfnGetProcAddress GetProcAddress = (FUN::__pfnGetProcAddress)::GetProcAddress(GetModuleHandle(_T("Kernel32.dll")), "GetProcAddress");
}

const char * __inet_ntop(int af, in_addr src_addr, char *dst, socklen_t cnt)
{
	if (af == AF_INET)
	{
		struct sockaddr_in in;
		memset(&in, 0, sizeof(in));
		in.sin_family = AF_INET;
		memcpy(&in.sin_addr, &src_addr, sizeof(struct in_addr));
		getnameinfo((struct sockaddr *)&in, sizeof(struct sockaddr_in), dst, cnt, NULL, 0, NI_NUMERICHOST);
		return dst;
	}
	else if (af == AF_INET6)
	{
		struct sockaddr_in6 in;
		memset(&in, 0, sizeof(in));
		in.sin6_family = AF_INET6;
		memcpy(&in.sin6_addr, &src_addr, sizeof(struct in_addr6));
		getnameinfo((struct sockaddr *)&in, sizeof(struct sockaddr_in6), dst, cnt, NULL, 0, NI_NUMERICHOST);
		return dst;
	}
	return NULL;
}

const wchar_t * __inet_ntopw(int af, in_addr src_addr, wchar_t *dst, socklen_t cnt)
{
	if (af == AF_INET)
	{
		struct sockaddr_in in;
		memset(&in, 0, sizeof(in));
		in.sin_family = AF_INET;
		memcpy(&in.sin_addr, &src_addr, sizeof(struct in_addr));
		GetNameInfoW((struct sockaddr *)&in, sizeof(struct sockaddr_in), dst, cnt, NULL, 0, NI_NUMERICHOST);
		return dst;
	}
	else if (af == AF_INET6)
	{
		struct sockaddr_in6 in;
		memset(&in, 0, sizeof(in));
		in.sin6_family = AF_INET6;
		memcpy(&in.sin6_addr, &src_addr, sizeof(struct in_addr6));
		GetNameInfoW((struct sockaddr *)&in, sizeof(struct sockaddr_in6), dst, cnt, NULL, 0, NI_NUMERICHOST);
		return dst;
	}
	return NULL;
}

int connectAndSendData(const char *szHost, unsigned short nPort, const char *pDataToSend, unsigned int nDataSize, char *pReceiveBuf = NULL, unsigned int *pnReceiveSize = NULL)
{
	WORD wVersionRequested = MAKEWORD(1, 1);
	WSADATA wsaData;

	int err = ::WSAStartup(wVersionRequested, &wsaData);
	if (0 != err)
	{
		printf("[connectAndSendData]: WSAStartup failed. return %d. \r\n", err);
		return -1;
	}

	if (wsaData.wVersion != wVersionRequested)
	{
		printf("[connectAndSendData]: wsaData.wVersion %d is not equal to wVersionRequested %d.\r\n", wsaData.wVersion, wVersionRequested);
		::WSACleanup();
		return -2;
	}

	SOCKET sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (INVALID_SOCKET == sock)
	{
		printf("[connectAndSendData]: socket error %d. \r\n", WSAGetLastError());
		return -3;
	}

	struct hostent *p_hostent = gethostbyname(szHost);
	if (NULL == p_hostent)
	{
		printf("[gethostbyname]: socket error %d. \r\n", WSAGetLastError());
		::closesocket(sock);
		::WSACleanup();
		return -4;
	}

	SOCKADDR_IN addr_server;
	addr_server.sin_family = AF_INET;
	addr_server.sin_addr = *((struct in_addr*)p_hostent->h_addr);
	memset(addr_server.sin_zero, 0, 8);
	addr_server.sin_port = htons(nPort);

	err = ::connect(sock, (SOCKADDR*)&addr_server, sizeof(addr_server));
	if (SOCKET_ERROR == err)
	{
		printf("[connectAndSendData]: connect %s:%d error %d. \r\n", szHost, nPort, WSAGetLastError());
		::closesocket(sock);
		::WSACleanup();
		return -5;
	}

	err = ::send(sock, pDataToSend, nDataSize, 0);
	if (SOCKET_ERROR == err)
	{
		printf("[connectAndSendData]: send error %d. \r\n", WSAGetLastError());
	}

	if (NULL != pReceiveBuf && NULL != pnReceiveSize)
	{
		char *p_receive = pReceiveBuf;
		char *p_buf = p_receive;
		int n_buf_len = *pnReceiveSize;
		int n_len = n_buf_len - 1;
		int n_read = 0;
		char temp[256];
		int n_head_len = -1;
		int n_content_len = -1;
		const char *content = NULL;

		while (1)
		{
			fd_set fds;
			FD_ZERO(&fds);
			FD_SET(sock, &fds);
			struct timeval timeo;
			timeo.tv_sec = 10;
			timeo.tv_usec = 1000;

			int ret = select(sock, &fds, NULL, NULL, &timeo);
			if (ret <= 0)
				break;

			if (FD_ISSET(sock, &fds))
			{
				n_read = ::recv(sock, p_buf, n_len, 0);
				if (n_read <= 0)
					break;

				p_buf += n_read;
				n_len -= n_read;
				if (n_len == 0)
					break;

				const char *rnrn = strstr(p_receive, "\r\n\r\n");
				if (NULL != rnrn && rnrn < p_buf)
				{
					rnrn += 4;
					content = rnrn;

					if (-1 == n_content_len)
					{
						const char *content_length = strstr(p_receive, "Content-Length: ");
						if (NULL != content_length && content_length < p_buf)
						{
							content_length += 16;
							const char *rn = strstr(content_length, "\r\n");
							if (NULL != rn && rn < p_buf)
							{
								int count = rn - content_length;
								strncpy(temp, content_length, count);
								temp[count] = '\0';
								n_content_len = atoi(temp);
							}
						}

						if (-1 == n_content_len)
						{
							const char *rn = strstr(rnrn, "\r\n");
							if (NULL != rn && rn < p_buf)
							{
								int count = rn - rnrn;
								strncpy(temp, rnrn, count);
								temp[count] = '\0';
								if (1 == sscanf(temp, "%x", &n_content_len))
								{
									n_content_len += 7; // 0D 0A 30 0D 0A 0D 0A  
									content = rn + 2;
								}
							}
						}

						if (-1 == n_content_len)
						{
							const char *connection = strstr(p_receive, "Connection: ");
							if (NULL != connection && connection < p_buf)
							{
								connection += 12;
								const char *rn = strstr(connection, "\r\n");
								if (NULL != rn && rn < p_buf)
								{
									int count = rn - connection;
									strncpy(temp, connection, count);
									temp[count] = '\0';
									connection = _strupr(temp);
									if (0 == strcmp(connection, "CLOSE"))
										n_content_len = 0;
								}
							}
						}
					}
				}

				if (NULL != content && n_content_len > 0)
				{
					n_head_len = content - p_receive;
					int n_cur_len = p_buf - p_receive;
					if (n_cur_len >= n_head_len + n_content_len)
						break;
				}
			}
		}

		n_len = n_buf_len - 1 - n_len;
		n_buf_len = n_len;
		p_receive[n_len] = '\0';
	}

	err = ::closesocket(sock);
	if (SOCKET_ERROR == err)
	{
		printf("[connectAndSendData]: closesocket error %d. \r\n", WSAGetLastError());
	}

	::WSACleanup();

	return 0;
}

#define MAX_IP4_STRING_LEN		16
#define MAX_IP6_STRING_LEN		46

#define MAX_IP_STRING_LEN		MAX_IP6_STRING_LEN

typedef struct _BUSINESS_DATA {
	USHORT usPACServerProt;
	CHAR szPACServerIP[MAX_IP_STRING_LEN + 1];
	USHORT usEncodeSockProt;
	CHAR szEncodeSockIP[MAX_IP_STRING_LEN + 1];
}BUSINESS_DATA,* PBUSINESS_DATA;

HANDLE WINAPI SetBusinessData(sockaddr_in * paddrPACSocket, sockaddr_in * paddrEncodeSocket)
{
	BUSINESS_DATA tbdBusinessData = { 0 };

	CHAR szBuffer[MAX_IP_STRING_LEN + 1] = { 0 };

	__inet_ntop(AF_INET, paddrPACSocket->sin_addr, szBuffer, MAX_IP_STRING_LEN);

	strcpy(tbdBusinessData.szPACServerIP, szBuffer);
	tbdBusinessData.usPACServerProt = ntohs(paddrPACSocket->sin_port);

	__inet_ntop(AF_INET, paddrEncodeSocket->sin_addr, szBuffer, MAX_IP_STRING_LEN);

	strcpy(tbdBusinessData.szEncodeSockIP, szBuffer);
	tbdBusinessData.usEncodeSockProt = ntohs(paddrEncodeSocket->sin_port);

	return Common::SetBufferToShareMap("GLOBAL_LINGPAO8_ENCODE_BUSINESS_DATA", &tbdBusinessData, sizeof(BUSINESS_DATA));
}

DWORD WINAPI StartBusiness_Thread(void *)
{
	PBUSINESS_DATA pBusinessData = NULL;
	CHAR szBuffer[MAX_IP_STRING_LEN + 1] = { 0 };
	WCHAR wszBuffer[MAX_IP_STRING_LEN + 1] = { 0 };

	if (false == Common::GetBufferToShareMap("GLOBAL_LINGPAO8_ENCODE_BUSINESS_DATA", (void**)&pBusinessData))
	{
		Global::Log.PrintA(LOGOutputs, "[% 5u] StartBusiness failed: %u", GetCurrentProcessId(), ::GetLastError());
		return -1;
	}

	Global::Log.PrintA(LOGOutputs, "[% 5u] PAC:(%s,%u)", GetCurrentProcessId(), pBusinessData->szPACServerIP, pBusinessData->usPACServerProt);

	Global::Log.PrintA(LOGOutputs, "[% 5u] ENCODE:(%s,%u)", GetCurrentProcessId(), pBusinessData->szEncodeSockIP, pBusinessData->usEncodeSockProt);

	//Global::cHttpReconnect.SetWebBrowserProxy(pcszProxyHost, usProxyPort);

	if (0 != pBusinessData->usEncodeSockProt)
	{
		sockaddr_in serv_addr = {0};

		serv_addr.sin_family = AF_INET;
		serv_addr.sin_port = htons(pBusinessData->usEncodeSockProt);
		serv_addr.sin_addr.s_addr = inet_addr(pBusinessData->szEncodeSockIP);

		StartHTTPSeclusion(serv_addr);
	}

	if (0 != pBusinessData->usPACServerProt)
	{
		SetGlobalWebBrowserProxy(pBusinessData->szPACServerIP, pBusinessData->usPACServerProt);

		Hook::StartChromeProxyConfigHook(Common::STR2WSTR(pBusinessData->szPACServerIP, wszBuffer), pBusinessData->usPACServerProt);
	}

	return 0;
}

DWORD WINAPI StartBusiness(void *)
{
	DWORD dwThreadId = 0;

	Hook::StartCommandLineHook();
	CloseHandle(CreateThread(NULL, 0, StartBusiness_Thread, NULL, 0, &dwThreadId));

	return dwThreadId;
}


DWORD WINAPI Thread_TEST(void *)
{
	unsigned short usProxyPort = 0;
	const char * pcszProxyHost = NULL;
	SOCKADDR_IN addrSocketProxy = { 0 };

	usProxyPort = 2016;
	pcszProxyHost = "127.0.0.1";

	addrSocketProxy.sin_port = htons(usProxyPort);
	addrSocketProxy.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	//Global::cHttpReconnect.SetWebBrowserProxy(pcszProxyHost, usProxyPort);

	//if(Common::IsCurrentProcess(_T("firefox.exe")) || GetModuleHandle(_T("xul.dll")))
	SetGlobalWebBrowserProxy(pcszProxyHost, usProxyPort);

	//StartHTTPSeclusion(addrSocketProxy);

	return -1;
}

BOOL APIENTRY DllMain(_In_ HINSTANCE hDllHandle, _In_ DWORD dwReason, _In_opt_ void * _Reserved)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		StartBusiness(NULL);
		break;
	case DLL_PROCESS_DETACH:
		break;
	default:
		break;
	}

	return TRUE;
}