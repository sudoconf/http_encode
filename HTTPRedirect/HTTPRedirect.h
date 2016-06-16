#pragma once
#include <tchar.h>
#include <assert.h>
#include <winsock2.h>

#include "CommonControl\Log.h"
#include "CommonControl\Commonfun.h"

#define ASSERT assert
#define ARR_COUNT(_array) (sizeof(_array) / sizeof(_array[0]))

#define NAME_FUNCTION_SEND												"send"
#define NAME_FUNCTION_WSASEND										"WSASend"
#define NAME_FUNCTION_WSPSTARTUP								"WSPStartup"

#define NAME_FUNCTION_CONNECT												"connect"
#define NAME_FUNCTION_WSACONNECT										"WSAConnect"

#define NAME_NETWORK_SOCKETDLL									_T("WS2_32.dll")

#define MAX_IP4_STRING_LEN		16
#define MAX_IP6_STRING_LEN		46

#define MAX_IP_STRING_LEN		MAX_IP6_STRING_LEN

typedef struct
{
	BOOL    fAutoDetect;
	LPWSTR  lpszAutoConfigUrl;
	LPWSTR  lpszProxy;
	LPWSTR  lpszProxyBypass;
} WINHTTP_CURRENT_USER_IE_PROXY_CONFIG;

typedef struct _BUSINESS_DATA {
	USHORT usPACServerProt;
	CHAR szPACServerIP[MAX_IP_STRING_LEN + 1];
	USHORT usEncodeSockProt;
	CHAR szEncodeSockIP[MAX_IP_STRING_LEN + 1];
}BUSINESS_DATA, *PBUSINESS_DATA;

namespace FUN {
	typedef FARPROC(WINAPI * __pfnGetProcAddress)(_In_ HMODULE hModule, _In_ LPCSTR lpProcName);

	typedef int (WSAAPI * __pfnWSASend) (__in SOCKET s, __in_ecount(dwBufferCount) LPWSABUF lpBuffers, __in DWORD dwBufferCount, __out_opt LPDWORD lpNumberOfBytesSent, __in DWORD dwFlags, __inout_opt LPWSAOVERLAPPED lpOverlapped, _In_opt_ LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

	typedef LPSTR(WINAPI * __pfnGetCommandLineA)(VOID);
	typedef LPWSTR(WINAPI * __pfnGetCommandLineW)(VOID);

	typedef BOOL(WINAPI * __pfnWinHttpGetIEProxyConfigForCurrentUser) (_Inout_ WINHTTP_CURRENT_USER_IE_PROXY_CONFIG *pProxyConfig);

}

namespace FUN {
	extern FUN::__pfnGetProcAddress GetProcAddress;
	extern FUN::__pfnGetCommandLineW GetCommandLineW;
}

namespace Global {
	extern CDebug Log;
	extern sockaddr_in addrTargetSocket;
	extern PBUSINESS_DATA pBusinessData;
}

inline bool LockCurrentModule() {
	char szModuleName[MAX_PATH + 1] = { 0 };
	GetModuleFileNameA(Common::GetModuleHandleByAddr(LockCurrentModule), szModuleName, MAX_PATH);

	return NULL != LoadLibraryA(szModuleName);
}

inline bool LockModule(_In_opt_ LPCSTR lpModuleName, _Out_ HMODULE * phModule)
{
	BOOL bIsOK = FALSE;

#ifdef _DEBUG
	bIsOK = GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_PIN, lpModuleName, phModule);
#else
	bIsOK = GetModuleHandleEx(0, lpModuleName, phModule);
#endif

	if (bIsOK)
		ASSERT(NULL != *phModule);
//	else
//		ASSERT(NULL == GetModuleHandle(lpModuleName));

	return TRUE == bIsOK;
}

inline bool UnlockModule(HMODULE hModule)
{
	return TRUE == FreeLibrary(hModule);
}

