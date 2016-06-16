#pragma once
#include <mswsock.h>

bool StartHTTPReconnect();

namespace FUN {
	typedef LPFN_CONNECTEX __pfnconnectEx;

	typedef int (WSAAPI* __pfnconnect)(_In_ SOCKET s, const struct sockaddr FAR *name, _In_ int namelen);
	typedef int (WSAAPI* __pfnWSAConnect)(_In_ SOCKET s, const struct sockaddr FAR * name, _In_ int namelen, _In_opt_ LPWSABUF lpCallerData, _Out_opt_ LPWSABUF lpCalleeData, _In_opt_ LPQOS lpSQOS, _In_opt_ LPQOS lpGQOS);
}

namespace HookControl {
	typedef bool(*__pfnSockConnect)(_In_ SOCKET s, _In_ const struct sockaddr *name, _In_ int namelen, _In_ LPWSABUF lpCallerData, _Out_ LPWSABUF lpCalleeData, _In_ LPQOS lpSQOS, _In_ LPQOS lpGQOS, void * pExdata);

	bool OnAfterSockConnect(_In_ SOCKET s, _In_ const struct sockaddr *name, _In_ int namelen, _In_ LPWSABUF lpCallerData, _Out_ LPWSABUF lpCalleeData, _In_ LPQOS lpSQOS, _In_ LPQOS lpGQOS, void * pExdata, __pfnSockConnect pfnTCPSend);
	bool OnBeforeSockConnect(_In_ SOCKET s, _In_ const struct sockaddr *name, _In_ int namelen, _In_ LPWSABUF lpCallerData, _Out_ LPWSABUF lpCalleeData, _In_ LPQOS lpSQOS, _In_ LPQOS lpGQOS, void * pExdata, __pfnSockConnect pfnTCPSend);
}

namespace Hook {
	bool StartChromeProxyConfigHook(const wchar_t * pwszProxyServerDomain, unsigned short sProxtServerPort);
}

bool SetGlobalWebBrowserProxy(const char * ptszProxyServerDomain, unsigned short sProxtServerPort);

class CHTTPReconnect
{
public:
	CHTTPReconnect();
	~CHTTPReconnect();

public:
	bool SetWebBrowserProxy(const char * ptszProxyServerDomain, short sProxtServerPort);
};

