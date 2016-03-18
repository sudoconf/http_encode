#include "HTTPRedirect.h"

#include "TridentSocket.h"

#include "HookControl\IATHook.h"
#include "HookControl\FakeSend.h"

namespace {
	const tchar * ptszHitDllLists[] = {
		_T("Wininet.dll")/* IE ºËÐÄä¯ÀÀÆ÷*/,
		_T("WebkitCore.dll")/* ËÑ¹· ºËÐÄä¯ÀÀÆ÷*/,
		_T("MxWebkit.dll")/* åÛÓÎ ºËÐÄä¯ÀÀÆ÷*/,
		_T("FastProxy.dll"), _T("ChromeCore.dll"),/* °Ù¶È ºËÐÄä¯ÀÀÆ÷*/
	};

	struct PARAMETERS_CALL_LATSEND {
		int nFlags;
		HookControl::__pfnsend pfnSend;
	};

	bool Call_IATSend(__in SOCKET s, __in_ecount(dwBufferCount) LPWSABUF lpBuffers, __in DWORD dwBufferCount, __out_opt LPDWORD lpNumberOfBytesSent, __in int * pnErrorcode, __in LPWSAOVERLAPPED lpOverlapped, __in LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine, void * pExdata)
	{
		int nRetValue = 0;
		bool bIsSuccess = true;
		PARAMETERS_CALL_LATSEND * pCallParameters = (PARAMETERS_CALL_LATSEND *)pExdata;

		nRetValue = pCallParameters->pfnSend(s, lpBuffers->buf, lpBuffers->len, pCallParameters->nFlags);

		if (SOCKET_ERROR == nRetValue)
			bIsSuccess = (WSA_IO_PENDING == *pnErrorcode);

		return bIsSuccess;
	}

	int PASCAL FAR IATSend(__in SOCKET s, __in_bcount(len) const char FAR * buf, __in int len, __in int flags)
	{
		bool bIsCall = false;

		int nRetValue = 0;
		int nErrorcode = 0;
		void * pCallAddress = NULL;

		WSABUF wsaBuffers = { 0 };
		DWORD dwNumberOfBytesSent = 0;
		PARAMETERS_CALL_LATSEND tpiCallParameters = { 0 };

		GetRetAddress(pCallAddress);

		wsaBuffers.len = len;
		wsaBuffers.buf = (char FAR *)buf;

		tpiCallParameters.nFlags = flags;
		tpiCallParameters.pfnSend = (HookControl::__pfnsend)FUN::GetProcAddress(GetModuleHandle(NAME_NETWORK_SOCKETDLL), NAME_FUNCTION_SEND);

		if (HookControl::IsPassCall(IATSend, pCallAddress))
			return tpiCallParameters.pfnSend(s, wsaBuffers.buf, wsaBuffers.len, flags);

		bIsCall = HookControl::OnBeforeTCPSend(s, &wsaBuffers, 1, &dwNumberOfBytesSent, &nErrorcode, NULL, NULL, &tpiCallParameters, Call_IATSend);

		if (bIsCall)
			return tpiCallParameters.pfnSend(s, wsaBuffers.buf, wsaBuffers.len, flags);

		bIsCall = bIsCall && HookControl::OnAfterTCPSend(s, &wsaBuffers, 1, &dwNumberOfBytesSent, &nErrorcode, NULL, NULL, &tpiCallParameters, Call_IATSend);

		nRetValue = wsaBuffers.len;

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

		for (int count = 0; count < 1000;count ++ )
		{
			for (int i = 0; i < sizeof(ptszHitDllLists) / sizeof(ptszHitDllLists[0]); i++)
			{
				ptszCurrentHitDll = ptszHitDllLists[i];

				if (LockModule(ptszCurrentHitDll, &hHookInstance))
					break;

				ptszCurrentHitDll = NULL;
			}

			if(ptszCurrentHitDll)
				break;

			Sleep(count % 10);
		}

		if(ptszCurrentHitDll)
		{
			bIsOK = HookControl::StartSocketsendHook();

			if (bIsOK)
				Global::Log.Print(LOGOutputs, _T("[% 5u] HookControl::StartSocketsendHook() is %u."), GetCurrentProcessId(), bIsOK);

			bIsOK = HookControl::IATHook(hHookInstance, NAME_NETWORK_SOCKETDLL, GetProcAddress(LoadLibrary(NAME_NETWORK_SOCKETDLL), NAME_FUNCTION_SEND), IATSend);

			if (bIsOK)
				Global::Log.Print(LOGOutputs, _T("[% 5u] HookControl::IATHook(% 15s, [WS2_32.dll,send], IATSend) is %u."), GetCurrentProcessId(), ptszCurrentHitDll, bIsOK);

			UnlockModule(hHookInstance);
		}

		return TRUE;
	}
}

bool Hook::StartTridentSocketHook()
{
	DWORD dwThreadID = 0;

	HANDLE hThread = CreateThread(NULL, 0, Thread_HookControl, NULL, 0, &dwThreadID);

	if (hThread)
		CloseHandle(hThread);

	return NULL != hThread;
}

struct PARAMETERS_CALL_INLINESEND {
	int nFlags;
};

bool Call_InlineSend(__in SOCKET s, __in_ecount(dwBufferCount) LPWSABUF lpBuffers, __in DWORD dwBufferCount, __out_opt LPDWORD lpNumberOfBytesSent, __in int * pnErrorcode, __in LPWSAOVERLAPPED lpOverlapped, __in LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine, void * pExdata)
{
	int nRetValue = 0;
	bool bIsSuccess = true;
	PARAMETERS_CALL_INLINESEND * pCallParameters = (PARAMETERS_CALL_INLINESEND *)pExdata;

	nRetValue = HookControl::pfnsend(s, lpBuffers->buf, lpBuffers->len, pCallParameters->nFlags);

	if (SOCKET_ERROR == nRetValue)
		bIsSuccess = (WSA_IO_PENDING == *pnErrorcode);

	return bIsSuccess;
}

bool HookControl::OnBeforeSocketsend(HOOKCONTROL_SOCKET_SEND * retStatuse, SOCKET s, const char *buf, int len, int flags)
{
	bool bIsCall = true;

	int nErrorcode = 0;

	WSABUF wsaBuffers = { 0 };
	DWORD dwNumberOfBytesSent = 0;
	PARAMETERS_CALL_INLINESEND tpiCallParameters = { 0 };

	wsaBuffers.len = len;
	wsaBuffers.buf = (char FAR *)buf;

	tpiCallParameters.nFlags = flags;

	bIsCall = HookControl::OnBeforeTCPSend(s, &wsaBuffers, 1, &dwNumberOfBytesSent, &nErrorcode, NULL, NULL, &tpiCallParameters, Call_InlineSend);

	retStatuse->RetValue = wsaBuffers.len;

	if (false == bIsCall && (0 != nErrorcode && WSA_IO_PENDING != nErrorcode))
	{
		retStatuse->RetValue = SOCKET_ERROR;
		WSASetLastError(nErrorcode);
	}

	return bIsCall;
}

bool HookControl::OnAfterSocketsend(HOOKCONTROL_SOCKET_SEND * retStatuse, SOCKET s, const char *buf, int len, int flags)
{
	bool bIsCall = true;

	int nErrorcode = 0;

	WSABUF wsaBuffers = { 0 };
	DWORD dwNumberOfBytesSent = 0;
	PARAMETERS_CALL_INLINESEND tpiCallParameters = { 0 };

	wsaBuffers.len = len;
	wsaBuffers.buf = (char FAR *)buf;

	tpiCallParameters.nFlags = flags;

	bIsCall = HookControl::OnAfterTCPSend(s, &wsaBuffers, 1, &dwNumberOfBytesSent, &nErrorcode, NULL, NULL, &tpiCallParameters, Call_InlineSend);

	retStatuse->RetValue = wsaBuffers.len;

	if (false == bIsCall && (0 != nErrorcode && WSA_IO_PENDING != nErrorcode))
	{
		retStatuse->RetValue = SOCKET_ERROR;
		WSASetLastError(nErrorcode);
	}

	return bIsCall;
}
