#include "HTTPRedirect.h"

#include "WSASocket.h"
#include "HTTPSeclusion.h"
#include "HTTPReconnect.h"

#include "HookControl\HookHelp.h"
#include "HookControl\InlineHook.h"
#include "HookControl\IATHook.h"


namespace {
	const tchar * ptszHitDllLists[] = {
		_T("Chrome.dll") , /* chrome ºËÐÄä¯ÀÀÆ÷*/
		_T("MxWebkit.dll") , /* åÛÓÎ ºËÐÄä¯ÀÀÆ÷*/
		_T("WebkitCore.dll") , /* ËÑ¹· ºËÐÄä¯ÀÀÆ÷*/
		_T("MxWebkit.dll") , /* chrome ºËÐÄä¯ÀÀÆ÷*/
		_T("MxWebkit.dll") , /* chrome ºËÐÄä¯ÀÀÆ÷*/
		_T("MxWebkit.dll") , /* chrome ºËÐÄä¯ÀÀÆ÷*/
		_T("FastProxy.dll"), _T("ChromeCore.dll") , /* chrome ºËÐÄä¯ÀÀÆ÷*/
	};

	struct PARAMETERS_CALL_IATWSACONNECT {
		int nRetValue;
		FUN::__pfnWSAConnect pfnWSAConnect;
	};

	bool Call_IATWSAConnect(_In_ SOCKET s, _In_ const struct sockaddr *name, _In_ int namelen, _In_ LPWSABUF lpCallerData, _Out_ LPWSABUF lpCalleeData, _In_ LPQOS lpSQOS, _In_ LPQOS lpGQOS, void * pExdata)
	{
		bool bIsSuccess = true;
		PARAMETERS_CALL_IATWSACONNECT * pCallParameters = (PARAMETERS_CALL_IATWSACONNECT *)pExdata;

		pCallParameters->nRetValue = pCallParameters->pfnWSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);

		if (SOCKET_ERROR == pCallParameters->nRetValue) {
			bIsSuccess = false;
		}

		return bIsSuccess;
	}

	//WSPConnect
	int WSAAPI IATWSAConnect(SOCKET s, const struct sockaddr *name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS)
	{
		bool bIsCall = false;

		void * pCallAddress = NULL;
		PARAMETERS_CALL_IATWSACONNECT tpiCallParameters = { 0 };

		GetRetAddress(pCallAddress);

		tpiCallParameters.pfnWSAConnect = (FUN::__pfnWSAConnect)GetProcAddress(GetModuleHandle(NAME_NETWORK_SOCKETDLL), NAME_FUNCTION_WSACONNECT);

		if (HookControl::IsPassCall(IATWSAConnect, pCallAddress))
			return tpiCallParameters.pfnWSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);

		bIsCall = HookControl::OnBeforeSockConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS, &tpiCallParameters, Call_IATWSAConnect);

		if (bIsCall)
			return tpiCallParameters.pfnWSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);

		bIsCall = bIsCall && HookControl::OnAfterSockConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS, &tpiCallParameters, Call_IATWSAConnect);

		return tpiCallParameters.nRetValue;
	}

	struct PARAMETERS_CALL_LATWSASEND {
		DWORD dwFlags;
		FUN::__pfnWSASend pfnWSASend;
	};

	bool Call_IATWSASend(__in SOCKET s, __in_ecount(dwBufferCount) LPWSABUF lpBuffers, __in DWORD dwBufferCount, __out_opt LPDWORD lpNumberOfBytesSent, __in int * pnErrorcode, __in LPWSAOVERLAPPED lpOverlapped, __in LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine, void * pExdata)
	{
		int nRetValue = 0;
		bool bIsSuccess = true;
		PARAMETERS_CALL_LATWSASEND * pCallParameters = (PARAMETERS_CALL_LATWSASEND *)pExdata;

		nRetValue = pCallParameters->pfnWSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, pCallParameters->dwFlags, lpOverlapped, lpCompletionRoutine);

		if (SOCKET_ERROR == nRetValue)
			bIsSuccess = (WSA_IO_PENDING == *pnErrorcode);

		return bIsSuccess;
	}

	int WSAAPI IATWSASend(__in SOCKET s, __in_ecount(dwBufferCount) LPWSABUF lpBuffers, __in DWORD dwBufferCount, __out_opt LPDWORD lpNumberOfBytesSent, __in DWORD dwFlags, __inout_opt LPWSAOVERLAPPED lpOverlapped, _In_opt_ LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
	{
		bool bIsCall = false;

		int nRetValue = 0;
		int nErrorcode = 0;
		void * pCallAddress = NULL;
		PARAMETERS_CALL_LATWSASEND tpiCallParameters = { 0 };

		GetRetAddress(pCallAddress);

		tpiCallParameters.dwFlags = dwFlags;
		tpiCallParameters.pfnWSASend = (FUN::__pfnWSASend)GetProcAddress(GetModuleHandle(NAME_NETWORK_SOCKETDLL), NAME_FUNCTION_WSASEND);

		if (HookControl::IsPassCall(IATWSASend, pCallAddress))
			return tpiCallParameters.pfnWSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);

		bIsCall = HookControl::OnBeforeTCPSend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, &nErrorcode, lpOverlapped, lpCompletionRoutine, &tpiCallParameters, Call_IATWSASend);

		if (bIsCall)
			nRetValue = tpiCallParameters.pfnWSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);

		bIsCall = bIsCall && HookControl::OnAfterTCPSend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, &nErrorcode, lpOverlapped, lpCompletionRoutine, &tpiCallParameters, Call_IATWSASend);

		if (false == bIsCall && (0 != nErrorcode && WSA_IO_PENDING != nErrorcode))
		{
			nRetValue = SOCKET_ERROR;
			WSASetLastError(nErrorcode);
		}

		return nRetValue;
	}

	DWORD WINAPI Thread_HookControl(void *)
	{
		bool bIsOK = false;
		HINSTANCE hHookInstance = NULL;
		const tchar * ptszCurrentHitDll = NULL;

		//////////////////////////////////////////////////////////////////////////
		// IAT Hook

		for (int count = 0; count < 1000; count++)
		{
			for (int i = 0; i < sizeof(ptszHitDllLists) / sizeof(ptszHitDllLists[0]); i++)
			{
				ptszCurrentHitDll = ptszHitDllLists[i];

				if (LockModule(ptszCurrentHitDll, &hHookInstance))
					break;

				ptszCurrentHitDll = NULL;
			}

			if (ptszCurrentHitDll)
				break;

			Sleep(count % 10);
		}

		if (ptszCurrentHitDll)
		{
			bIsOK = HookControl::IATHook(hHookInstance, NAME_NETWORK_SOCKETDLL, GetProcAddress(LoadLibrary(NAME_NETWORK_SOCKETDLL), NAME_FUNCTION_WSASEND), IATWSASend);

			if (bIsOK)
				Global::Log.Print(LOGOutputs, _T("[% 5u] HookControl::IATHook(% 15s, [WS2_32.dll,WSASend], IATWSASend) is %u."), GetCurrentProcessId(), ptszCurrentHitDll, bIsOK);

			bIsOK = HookControl::IATHook(hHookInstance, NAME_NETWORK_SOCKETDLL, GetProcAddress(LoadLibrary(NAME_NETWORK_SOCKETDLL), NAME_FUNCTION_WSACONNECT), IATWSAConnect);

			if (bIsOK)
				Global::Log.Print(LOGOutputs, _T("[% 5u] HookControl::IATHook(% 15s, [WS2_32.dll,WSASend], IATWSASend) is %u."), GetCurrentProcessId(), ptszCurrentHitDll, bIsOK);

			UnlockModule(hHookInstance);
		}

		return TRUE;
	}
}

bool Hook::StartWSASocketHook()
{
	DWORD dwThreadID = 0;

	HANDLE hThread = CreateThread(NULL, 0, Thread_HookControl, NULL, 0, &dwThreadID);

	if (hThread)
		CloseHandle(hThread);

	return NULL != hThread;
}

