#include "CMDRedirect.h"
#include <Winhttp.h>

#include "FakeGetProcAddress.h"

#include "HookControl\InlineHook.h"

namespace {
	typedef BOOL (WINAPI* __pfnWinHttpGetIEProxyConfigForCurrentUser)(_Inout_ WINHTTP_CURRENT_USER_IE_PROXY_CONFIG *pProxyConfig);
}

namespace {
	wchar_t g_wszInternetOptionString[MAX_PATH + 1] = { 0 };
	__pfnWinHttpGetIEProxyConfigForCurrentUser pfnWinHttpGetIEProxyConfigForCurrentUser = NULL;

	BOOL WINAPI FakeHttpGetIEProxyConfigForCurrentUser(_Inout_ WINHTTP_CURRENT_USER_IE_PROXY_CONFIG *pProxyConfig) {
		LPWSTR pwszOldAutoConfigUrl = NULL;

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

		if (Common::IsCurrentProcess(_T("f1browser.exe"))) { // F1 浏览器设置代理后会打不开网页
			wcscpy(pProxyConfig->lpszAutoConfigUrl, L"");
		}

		return TRUE;
	}
}

namespace Hook {

#define MAX_IP4_STRING_LEN		16
#define MAX_IP6_STRING_LEN		46

#define MAX_IP_STRING_LEN		MAX_IP6_STRING_LEN

	typedef struct _BUSINESS_DATA {
		USHORT usPACServerProt;
		CHAR szPACServerIP[MAX_IP_STRING_LEN + 1];
		USHORT usEncodeSockProt;
		CHAR szEncodeSockIP[MAX_IP_STRING_LEN + 1];
	}BUSINESS_DATA, *PBUSINESS_DATA;


	bool StartWinHttpGetIEProxyConfigForCurrentUserHook()
	{
		bool bIsHook = true;
		PBUSINESS_DATA pBusinessData = NULL;

		if (false == Common::GetBufferToShareMap("GLOBAL_LINGPAO8_ENCODE_BUSINESS_DATA", (void**)&pBusinessData))
		{
			Global::Log.PrintA(LOGOutputs, "[% 5u] Init WinHttpGetIEProxyConfigForCurrentUser data failed: %u", GetCurrentProcessId(), ::GetLastError());
			return false;
		}

		if (0 != pBusinessData->usPACServerProt) {
			WCHAR wszBuffer[MAX_IP_STRING_LEN + 1] = { 0 };
			swprintf(g_wszInternetOptionString, L"http://%s:%u/proxy.pac", Common::STR2WSTR(pBusinessData->szPACServerIP, wszBuffer), pBusinessData->usPACServerProt);
		}

		if (NULL == pfnWinHttpGetIEProxyConfigForCurrentUser) {
			bIsHook = HookControl::InlineHook(GetProcAddress(LoadLibrary(_T("Winhttp.dll")), "WinHttpGetIEProxyConfigForCurrentUser"), FakeHttpGetIEProxyConfigForCurrentUser, (void **)&pfnWinHttpGetIEProxyConfigForCurrentUser);

			Global::Log.Print(LOGOutputs, _T("[HOOK] start hook control WinHttpGetIEProxyConfigForCurrentUser stutus is %u."), bIsHook);
		}

		return bIsHook;
	}
}