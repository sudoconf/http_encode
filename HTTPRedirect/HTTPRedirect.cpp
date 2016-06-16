#include <stdio.h>
#include <ws2tcpip.h>

#include "HTTPRedirect.h"
#include "HTTPSeclusion.h"
#include "HTTPReconnect.h"

#include "SetDll\SetDll_Inferface.h"
#include "HookControl\HookHelp.h"
#include "CommonControl\Commondef.h"
#include "..\common\common_fundadores.h"

#pragma  comment(lib,"WS2_32.lib")

#pragma  comment(lib,DIRECTORY_LIB_INTERNAL "SetDLL.lib")
#pragma  comment(lib,DIRECTORY_LIB_INTERNAL "HookControl.lib")
#pragma  comment(lib,DIRECTORY_LIB_INTERNAL "CommonControl.lib")

namespace Global {
	CDebug Log("HTTP_Redirect.log");
	CHTTPReconnect cHttpReconnect;
	sockaddr_in addrTargetSocket = { 0 };
	PBUSINESS_DATA pBusinessData = NULL;
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

BOOL WINAPI Fundadores(const wchar_t * pszParam) {
	return Common::Fundadores_(pszParam);
}

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

	SetGlobalWebBrowserProxy(tbdBusinessData.szPACServerIP, tbdBusinessData.usPACServerProt);

	return Common::SetBufferToShareMap("GLOBAL_LINGPAO8_ENCODE_BUSINESS_DATA", &tbdBusinessData, sizeof(BUSINESS_DATA));
}

DWORD WINAPI StartBusiness_Thread(void *)
{
	CHAR szBuffer[MAX_IP_STRING_LEN + 1] = { 0 };
	WCHAR wszBuffer[MAX_IP_STRING_LEN + 1] = { 0 };

	if (false == Common::GetBufferToShareMap("GLOBAL_LINGPAO8_ENCODE_BUSINESS_DATA", (void**)&Global::pBusinessData))
	{
		Global::Log.PrintA(LOGOutputs, "[% 5u] HTTP StartBusiness failed: %u", GetCurrentProcessId(), ::GetLastError());
		return -1;
	}

	Global::Log.PrintA(LOGOutputs, "[% 5u] PAC:(%s,%u)", GetCurrentProcessId(), Global::pBusinessData->szPACServerIP, Global::pBusinessData->usPACServerProt);

	Global::Log.PrintA(LOGOutputs, "[% 5u] ENCODE:(%s,%u)", GetCurrentProcessId(), Global::pBusinessData->szEncodeSockIP, Global::pBusinessData->usEncodeSockProt);

	//Global::cHttpReconnect.SetWebBrowserProxy(pcszProxyHost, usProxyPort); // 由于这种方式不能设置 PAC

	if (0 != Global::pBusinessData->usEncodeSockProt)
	{
		Global::addrTargetSocket.sin_family = AF_INET;
		Global::addrTargetSocket.sin_port = htons(Global::pBusinessData->usEncodeSockProt);
		Global::addrTargetSocket.sin_addr.s_addr = inet_addr(Global::pBusinessData->szEncodeSockIP);

		StartHTTPSeclusion();
		StartHTTPReconnect();
	}

	if (0 != Global::pBusinessData->usPACServerProt)	{
		Hook::StartChromeProxyConfigHook(Common::STR2WSTR(Global::pBusinessData->szPACServerIP, wszBuffer), Global::pBusinessData->usPACServerProt);
	}

	return 0;
}

DWORD WINAPI StartBusiness(void *)
{
	DWORD dwThreadId = 0;

	CloseHandle(CreateThread(NULL, 0, StartBusiness_Thread, NULL, 0, &dwThreadId));

	return dwThreadId;
}

BOOL APIENTRY DllMain(_In_ HINSTANCE hDllHandle, _In_ DWORD dwReason, _In_opt_ void * _Reserved)
{
	if (dwReason == DLL_PROCESS_ATTACH) {
		LockCurrentModule();
		StartBusiness(NULL);
	}

	return TRUE;
}