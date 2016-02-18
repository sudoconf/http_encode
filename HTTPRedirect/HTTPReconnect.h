#pragma once

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

