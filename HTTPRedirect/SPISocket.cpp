#include <ws2spi.h>
#include <errno.h>
#include <fstream>

#include "HookControl\HookHelp.h"
#include "HookControl\InlineHook.h"

#include "SPISocket.h"
#include "SPIInstaller.h"
#include "HTTPRedirect.h"
#include "HTTPSeclusion.h"
#include "HTTPReconnect.h"

namespace Global {
	WSPPROC_TABLE ProcTable = { 0 };

	DWORD dwProtoInfoSize = 0;
	LPWSAPROTOCOL_INFOW pProtocalsInfo = NULL;
}

bool Hook::StartSPISocketHook()
{
	bool bIsOK = false;
	WCHAR wszModuleName[MAX_PATH + 1] = { 0 };

	//////////////////////////////////////////////////////////////////////////
	// LSP 协议安装

	::GetModuleFileNameW(Common::GetModuleHandleByAddr(Common::GetModuleHandleByAddr), wszModuleName, MAX_PATH);

	LoadLibraryW(wszModuleName);
	bIsOK = SPIInstall(L"LSP_TEST", wszModuleName);

	Global::Log.PrintW(LOGOutputs, L"[% 5u] SPIInstall(LSP_TEST, %s) = %u.", GetCurrentProcessId(), wszModuleName, bIsOK);

	return bIsOK;
}

int LSPEnumProtocols()
{
	int nErrorcode = 0;
	int nTotalProtos = 0;

	Global::dwProtoInfoSize = 0;
	Global::pProtocalsInfo = NULL;

	if (WSCEnumProtocols(NULL, Global::pProtocalsInfo, &Global::dwProtoInfoSize, &nErrorcode) == SOCKET_ERROR && WSAENOBUFS != nErrorcode)
		return 0;

	if ((Global::pProtocalsInfo = (LPWSAPROTOCOL_INFOW)GlobalAlloc(GPTR, Global::dwProtoInfoSize)) == NULL)
		return 0;

	if ((nTotalProtos = WSCEnumProtocols(NULL, Global::pProtocalsInfo, &Global::dwProtoInfoSize, &nErrorcode)) == SOCKET_ERROR)
		return 0;

	return nTotalProtos;
}
// 释放内存
void FreeLSP()
{
	if (Global::pProtocalsInfo)
		GlobalFree(Global::pProtocalsInfo);
}

/********************************* 改写WSP函数，只有WSPConnect被改写成调用socksProxy函数，其它的直接调用下层WSP函数 ****************************************/

struct PARAMETERS_CALL_LSPWSASEND {
	int nRetValue;
	DWORD dwFlags;
	LPWSATHREADID lpThreadId;
};

bool Call_LSPWSPSend(__in SOCKET s, __in_ecount(dwBufferCount) LPWSABUF lpBuffers, __in DWORD dwBufferCount, __out_opt LPDWORD lpNumberOfBytesSent, __in int * pnErrorcode, __in LPWSAOVERLAPPED lpOverlapped, __in LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine, void * pExdata)
{
	bool bIsSuccess = true;
	PARAMETERS_CALL_LSPWSASEND * pCallParameters = (PARAMETERS_CALL_LSPWSASEND *)pExdata;

	pCallParameters->nRetValue = Global::ProcTable.lpWSPSend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, pCallParameters->dwFlags, lpOverlapped, lpCompletionRoutine, pCallParameters->lpThreadId, pnErrorcode);

	if (SOCKET_ERROR == pCallParameters->nRetValue)
		bIsSuccess = (WSA_IO_PENDING == *pnErrorcode);

	return bIsSuccess;
}

//WSPSend
int WINAPI LSPWSPSend(__in SOCKET s, __in LPWSABUF lpBuffers, __in DWORD dwBufferCount, __out LPDWORD lpNumberOfBytesSent, __in DWORD dwFlags, __in LPWSAOVERLAPPED lpOverlapped, __in LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine, __in LPWSATHREADID lpThreadId, __out LPINT lpErrno)
{
	bool bIsCall = false;

	int nRetValue = 0;
	void * pCallAddress = NULL;
	PARAMETERS_CALL_LSPWSASEND tpiCallParameters = { 0 };

	GetRetAddress(pCallAddress);

	tpiCallParameters.dwFlags = dwFlags;
	tpiCallParameters.lpThreadId = lpThreadId;

	if (HookControl::IsPassCall(LSPWSPSend, pCallAddress))
		return Global::ProcTable.lpWSPSend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);

	bIsCall = HookControl::OnBeforeTCPSend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, lpErrno, lpOverlapped, lpCompletionRoutine, &tpiCallParameters, Call_LSPWSPSend);

	if (bIsCall)
		return Global::ProcTable.lpWSPSend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);

	bIsCall = bIsCall && HookControl::OnAfterTCPSend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, lpErrno, lpOverlapped, lpCompletionRoutine, &tpiCallParameters, Call_LSPWSPSend);

	if (false == bIsCall && (0 != *lpErrno && WSA_IO_PENDING != *lpErrno))
		tpiCallParameters.nRetValue = SOCKET_ERROR;

	return tpiCallParameters.nRetValue;
}

struct PARAMETERS_CALL_LSPWSACONNECT {
	int nRetValue;
	LPINT lpErrno;
};

bool Call_LSPWSPConnect(_In_ SOCKET s, _In_ const struct sockaddr *name, _In_ int namelen, _In_ LPWSABUF lpCallerData, _Out_ LPWSABUF lpCalleeData, _In_ LPQOS lpSQOS, _In_ LPQOS lpGQOS, void * pExdata)
{
	bool bIsSuccess = true;
	PARAMETERS_CALL_LSPWSACONNECT * pCallParameters = (PARAMETERS_CALL_LSPWSACONNECT *)pExdata;

	pCallParameters->nRetValue = Global::ProcTable.lpWSPConnect(s, name, namelen, lpCallerData,lpCalleeData, lpSQOS, lpGQOS, pCallParameters->lpErrno);

	if (SOCKET_ERROR == pCallParameters->nRetValue) {
		bIsSuccess = false;
	}

	return bIsSuccess;
}

//WSPConnect
int WSPAPI LSPWSPConnect(SOCKET s, const struct sockaddr *name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS, LPINT lpErrno)
{
	bool bIsCall = false;

	void * pCallAddress = NULL;
	PARAMETERS_CALL_LSPWSACONNECT tpiCallParameters = { 0 };

	GetRetAddress(pCallAddress);

	tpiCallParameters.lpErrno = lpErrno;

	if (HookControl::IsPassCall(LSPWSPConnect, pCallAddress))
		return Global::ProcTable.lpWSPConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS, lpErrno);

	bIsCall = HookControl::OnBeforeSockConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS, &tpiCallParameters, Call_LSPWSPConnect);

	if (bIsCall)
		return Global::ProcTable.lpWSPConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS, lpErrno);

	bIsCall = bIsCall && HookControl::OnAfterSockConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS, &tpiCallParameters, Call_LSPWSPConnect);

	return tpiCallParameters.nRetValue;
}

//WSPSocket
SOCKET WINAPI WSPSocket(__in int af, __in int type, __in int protocol, __in LPWSAPROTOCOL_INFOW lpProtocolInfo, __in GROUP g, DWORD dwFlags, __out LPINT lpErrno)
{
	return Global::ProcTable.lpWSPSocket(af, type, protocol, lpProtocolInfo, g, dwFlags, lpErrno);
}

//WSPBind
int WINAPI WSPBind(__in SOCKET s, __in const struct sockaddr *name, __in int namelen, __out LPINT lpErrno)
{
	return Global::ProcTable.lpWSPBind(s, name, namelen, lpErrno);
}

//WSPSendTo
int WINAPI WSPSendTo(__in SOCKET s, __in LPWSABUF lpBuffers, __in DWORD dwBufferCount, __out LPDWORD lpNumberOfBytesSent, __in DWORD dwFlags, __in const struct sockaddr *lpTo, __in int iTolen, __in LPWSAOVERLAPPED lpOverlapped, __in LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine, __in LPWSATHREADID lpThreadId, __out LPINT lpErrno)
{
	return Global::ProcTable.lpWSPSendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);
}

//WSPRecv
int WINAPI WSPRecv(__in SOCKET s, __inout LPWSABUF lpBuffers, __in DWORD dwBufferCount, __out LPDWORD lpNumberOfBytesRecvd, __inout LPDWORD lpFlags, __in LPWSAOVERLAPPED lpOverlapped, __in LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine, __in LPWSATHREADID lpThreadId, __out LPINT lpErrno)
{
	return Global::ProcTable.lpWSPRecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);
}

//WSPRecvFrom
int WINAPI WSPRecvFrom(__in SOCKET s, __inout LPWSABUF lpBuffers, __in DWORD dwBufferCount, __out LPDWORD lpNumberOfBytesRecvd, __inout LPDWORD lpFlags, __out struct sockaddr *lpFrom, __inout LPINT lpFromlen, __in LPWSAOVERLAPPED lpOverlapped, __in LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine, __in LPWSATHREADID lpThreadId, __inout LPINT lpErrno)
{
	return Global::ProcTable.lpWSPRecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);
}

//WSPStartup
int WSPAPI WSPStartup(WORD wversionrequested, LPWSPDATA lpwspdata, LPWSAPROTOCOL_INFOW lpProtoInfo, WSPUPCALLTABLE upcalltable, LPWSPPROC_TABLE lpproctable)
{
	int nErrorcode = 0;
	DWORD dwNextLayerID = 0;
	DWORD dwCurrentLayerID = 0;
	HINSTANCE hHinstance = NULL;
	int nFilterPathLen = MAX_PATH;
	WCHAR wszFilterPath[MAX_PATH + 1] = { 0 };
	LPWSPSTARTUP pfnWSPStartup = NULL;

	if (lpProtoInfo->ProtocolChain.ChainLen <= 1)
		return FALSE;

	int nTotalProtos = LSPEnumProtocols();

	for (int i = 0; i < nTotalProtos; i++)
	{
		if (memcmp(&Global::pProtocalsInfo[i].ProviderId, &GUID_SPIProvider, sizeof(GUID)) == 0)
		{
			dwCurrentLayerID = Global::pProtocalsInfo[i].dwCatalogEntryId;
			break;
		}
	}

	for (int i = 0; i < lpProtoInfo->ProtocolChain.ChainLen; i++)
	{
		if (lpProtoInfo->ProtocolChain.ChainEntries[i] == dwCurrentLayerID)
		{
			dwNextLayerID = lpProtoInfo->ProtocolChain.ChainEntries[i + 1];
			break;
		}
	}

	nFilterPathLen = MAX_PATH;

	for (int i = 0; i < nTotalProtos; i++)
	{
		if (dwNextLayerID == Global::pProtocalsInfo[i].dwCatalogEntryId)
		{
			if (WSCGetProviderPath(&Global::pProtocalsInfo[i].ProviderId, wszFilterPath, &nFilterPathLen, &nErrorcode) == SOCKET_ERROR)
			{
				FreeLSP();

				return WSAEPROVIDERFAILEDINIT;
			}

			break;
		}
	}

	do
	{
		nErrorcode = WSAEPROVIDERFAILEDINIT;

		if (!ExpandEnvironmentStringsW(wszFilterPath, wszFilterPath, MAX_PATH))
			break;

		if (NULL == (hHinstance = LoadLibraryW(wszFilterPath)))
			break;

		if (NULL == (pfnWSPStartup = (LPWSPSTARTUP)FUN::GetProcAddress(hHinstance, NAME_FUNCTION_WSPSTARTUP)))
			break;

		if ((nErrorcode = pfnWSPStartup(wversionrequested, lpwspdata, lpProtoInfo, upcalltable, lpproctable)) != ERROR_SUCCESS)
			return nErrorcode;

		Global::ProcTable = *lpproctable;// 保存原来的入口函数表

										 //改写函数
		lpproctable->lpWSPBind = WSPBind;
		lpproctable->lpWSPRecv = WSPRecv;
		lpproctable->lpWSPSocket = WSPSocket;
		lpproctable->lpWSPSendTo = WSPSendTo;
		lpproctable->lpWSPRecvFrom = WSPRecvFrom;

		lpproctable->lpWSPSend = LSPWSPSend;
		lpproctable->lpWSPConnect = LSPWSPConnect;
	} while (false);

	FreeLSP();

	return 0;
}