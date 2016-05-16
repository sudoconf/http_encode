#include "HTTPRedirect.h"
#include "HTTPReconnect.h"

#include <stdio.h>
#include <wininet.h>

#include "HookControl\IATHook.h"
#include "CommonControl\Commonfun.h"

#pragma comment(lib,"Wininet.lib")


namespace {
	wchar_t g_wszInternetOptionString[MAX_PATH + 1] = { 0 };

	const tchar * ptszHitDllLists[] = {
		_T("chrome.dll") , /* chrome/360∞≤»´/360º´ÀŸ/UC/2345/¡‘±™/QQ ‰Ø¿¿∆˜*/
		_T("chromecore.dll") , /* ∞Ÿ∂» ‰Ø¿¿∆˜*/
		_T("WebkitCore.dll") , /* À—π∑ ‰Ø¿¿∆˜*/
		_T("MxWebkit.dll") , /* Â€”Œ‘∆ ‰Ø¿¿∆˜*/
		_T("xul.dll") , /* Â€”Œ‘∆ ‰Ø¿¿∆˜*/
	};

	BOOL WINAPI IATWinHttpGetIEProxyConfigForCurrentUser(_Inout_ WINHTTP_CURRENT_USER_IE_PROXY_CONFIG *pProxyConfig)
	{
		LPWSTR pwszOldAutoConfigUrl = NULL;
		FUN::__pfnWinHttpGetIEProxyConfigForCurrentUser pfnWinHttpGetIEProxyConfigForCurrentUser = (FUN::__pfnWinHttpGetIEProxyConfigForCurrentUser)GetProcAddress(LoadLibrary("Winhttp.dll"), "WinHttpGetIEProxyConfigForCurrentUser");

		if (FALSE == pfnWinHttpGetIEProxyConfigForCurrentUser(pProxyConfig))
			return FALSE;

		pProxyConfig->fAutoDetect = TRUE;
		pwszOldAutoConfigUrl = pProxyConfig->lpszAutoConfigUrl;

		Global::Log.PrintW(LOGOutputs, L"[% 5u] HookControl::IATWinHttpGetIEProxyConfigForCurrentUser(%s,%s)", GetCurrentProcessId(), pProxyConfig->lpszAutoConfigUrl, g_wszInternetOptionString);

		pProxyConfig->lpszAutoConfigUrl = (LPWSTR)GlobalAlloc(GMEM_FIXED, (wcslen(g_wszInternetOptionString) + 1) * sizeof(g_wszInternetOptionString));

		if (NULL == pProxyConfig->lpszAutoConfigUrl)
		{
			pProxyConfig->lpszAutoConfigUrl = pwszOldAutoConfigUrl;
			Global::Log.PrintW(LOGOutputs, L"[% 5u] HookControl::IATWinHttpGetIEProxyConfigForCurrentUser(%s,%s) Failed!!!", GetCurrentProcessId(), pProxyConfig->lpszAutoConfigUrl, g_wszInternetOptionString);
			return TRUE;
		}

		if (pwszOldAutoConfigUrl)
			GlobalFree(pwszOldAutoConfigUrl);

		wcscpy(pProxyConfig->lpszAutoConfigUrl, g_wszInternetOptionString);
		
		return TRUE;
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
			{
				bIsOK = HookControl::IATHook(hHookInstance, _T("Winhttp.dll"), GetProcAddress(LoadLibrary("Winhttp.dll"), "WinHttpGetIEProxyConfigForCurrentUser"), IATWinHttpGetIEProxyConfigForCurrentUser);

				if (bIsOK)
					Global::Log.Print(LOGOutputs, _T("[% 5u] HookControl::IATHook(% 15s, [Winhttp.dll,WinHttpGetIEProxyConfigForCurrentUser], IATWinHttpGetIEProxyConfigForCurrentUser) is %u."), GetCurrentProcessId(), ptszCurrentHitDll, bIsOK);

				UnlockModule(hHookInstance);
			}

			Sleep(count % 10);
		}

		return TRUE;
	}
}

bool Hook::StartChromeProxyConfigHook(const wchar_t * pwszProxyServerDomain,unsigned short sProxtServerPort)
{
	DWORD dwThreadID = 0;

	swprintf(g_wszInternetOptionString,L"http://%s:%u/proxy.pac",pwszProxyServerDomain, sProxtServerPort);

	HANDLE hThread = CreateThread(NULL, 0, Thread_HookControl, NULL, 0, &dwThreadID);

	if (hThread)
		CloseHandle(hThread);

	return NULL != hThread;
}


bool SetGlobalWebBrowserProxy(const char * ptszProxyServerDomain, unsigned short sProxtServerPort)
{
	bool bIsOK = false;
	char szInternetOptionString[MAX_PATH + 1] = { 0 };

	//////////////////////////////////////////////////////////////////////////
	// …Ë÷√»´æ÷¥˙¿Ì

	INTERNET_PER_CONN_OPTION  proxyInternetOptions[5] = { 0 };
	INTERNET_PER_CONN_OPTION_LIST proxyInternetOptionList = { 0 };

	sprintf(szInternetOptionString,
		"http://%s:%u/proxy.pac",
		ptszProxyServerDomain, sProxtServerPort,
		ptszProxyServerDomain, sProxtServerPort);

	proxyInternetOptions[0].dwOption = INTERNET_PER_CONN_AUTOCONFIG_URL;
	proxyInternetOptions[0].Value.pszValue = szInternetOptionString;

	proxyInternetOptions[1].dwOption = INTERNET_PER_CONN_AUTODISCOVERY_FLAGS;
	proxyInternetOptions[1].Value.dwValue = 0;

	proxyInternetOptions[2].dwOption = INTERNET_PER_CONN_FLAGS;
	proxyInternetOptions[2].Value.dwValue = (PROXY_TYPE_AUTO_PROXY_URL | PROXY_TYPE_DIRECT);

	proxyInternetOptions[3].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
	proxyInternetOptions[3].Value.pszValue = "<local>";

	proxyInternetOptions[4].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
	proxyInternetOptions[4].Value.pszValue = NULL;

	proxyInternetOptionList.dwOptionError = 0;
	proxyInternetOptionList.pszConnection = NULL;

	proxyInternetOptionList.dwSize = sizeof(INTERNET_PER_CONN_OPTION_LIST);

	proxyInternetOptionList.pOptions = proxyInternetOptions;
	proxyInternetOptionList.dwOptionCount = sizeof(proxyInternetOptions) / sizeof(proxyInternetOptions[0]);

	bIsOK = TRUE == InternetSetOption(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, &proxyInternetOptionList, sizeof(INTERNET_PER_CONN_OPTION_LIST));

	//////////////////////////////////////////////////////////////////////////
	// ±£¥Ê…Ë÷√

	InternetSetOption(NULL, INTERNET_OPTION_REFRESH, NULL, NULL);

	return bIsOK;
}


CHTTPReconnect::CHTTPReconnect()
{
}


CHTTPReconnect::~CHTTPReconnect()
{
}

bool CHTTPReconnect::SetWebBrowserProxy(const char * ptszProxyServerDomain, short sProxtServerPort)
{
	bool bIsOK = false;
	char szInternetOptionString[MAX_PATH + 1] = { 0 };
	INTERNET_PROXY_INFO proxyInternetProxyInfo = { 0 };

	sprintf(szInternetOptionString,
		"http=%s:%u;"
		"https=%s:%u",
		ptszProxyServerDomain, sProxtServerPort,
		ptszProxyServerDomain, sProxtServerPort);

	proxyInternetProxyInfo.lpszProxyBypass = "local";
	proxyInternetProxyInfo.lpszProxy = szInternetOptionString;
	proxyInternetProxyInfo.dwAccessType = INTERNET_OPEN_TYPE_PROXY;

	bIsOK = TRUE == InternetSetOption(NULL, INTERNET_OPTION_PROXY, &proxyInternetProxyInfo, sizeof(INTERNET_PROXY_INFO));

	//////////////////////////////////////////////////////////////////////////
	// ±£¥Ê…Ë÷√

	InternetSetOption(NULL, INTERNET_OPTION_REFRESH, NULL, NULL);

	return bIsOK;
}
