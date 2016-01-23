#pragma once

namespace Hook {
	bool StartChromeProxyConfigHook(const wchar_t * pwszProxyServerDomain, short sProxtServerPort);
}

bool SetGlobalWebBrowserProxy(const char * ptszProxyServerDomain, short sProxtServerPort);

class CHTTPReconnect
{
public:
	CHTTPReconnect();
	~CHTTPReconnect();

public:
	bool SetWebBrowserProxy(const char * ptszProxyServerDomain, short sProxtServerPort);
};

