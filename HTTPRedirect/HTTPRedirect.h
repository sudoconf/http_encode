#pragma once
#include <tchar.h>
#include <assert.h>
#include <winsock2.h>

#include "CommonControl\Log.h"
#include <wininet.h>

#define ASSERT assert

#define NAME_FUNCTION_SEND												"send"
#define NAME_FUNCTION_WSASEND										"WSASend"
#define NAME_FUNCTION_WSPSTARTUP								"WSPStartup"

#define NAME_NETWORK_SOCKETDLL									_T("WS2_32.dll")

typedef struct
{
	BOOL    fAutoDetect;
	LPWSTR  lpszAutoConfigUrl;
	LPWSTR  lpszProxy;
	LPWSTR  lpszProxyBypass;
} WINHTTP_CURRENT_USER_IE_PROXY_CONFIG;

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

namespace HookControl {
	typedef bool(*PFN_TCPSEND)(__in SOCKET s, __in_ecount(dwBufferCount) LPWSABUF lpBuffers, __in DWORD dwBufferCount, __out_opt LPDWORD lpNumberOfBytesSent, __in int * pnErrorcode, __in LPWSAOVERLAPPED lpOverlapped, __in LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine, void * pExdata);

	bool OnAfterTCPSend(__in SOCKET s, __in_ecount(dwBufferCount) LPWSABUF lpBuffers, __in DWORD dwBufferCount, __out_opt LPDWORD lpNumberOfBytesSent, __in int * pnErrorcode, __in LPWSAOVERLAPPED lpOverlapped, __in LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine, void * pExdata, PFN_TCPSEND pfnTCPSend);
	bool OnBeforeTCPSend(__in SOCKET s, __in_ecount(dwBufferCount) LPWSABUF lpBuffers, __in DWORD dwBufferCount, __out_opt LPDWORD lpNumberOfBytesSent, __in int * pnErrorcode, __in LPWSAOVERLAPPED lpOverlapped, __in LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine, void * pExdata, PFN_TCPSEND pfnTCPSend);
}

namespace Global {
	extern CDebug Log;
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

