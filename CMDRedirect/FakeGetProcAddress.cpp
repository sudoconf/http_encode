#include "CMDRedirect.h"

#include "FakeGetProcAddress.h"

#include "HookControl\InlineHook.h"

namespace {
	typedef FARPROC(WINAPI * __pfnGetProcAddress)(__in HMODULE hModule, __in LPCSTR lpProcName);
}

namespace {
	__pfnGetProcAddress pfnGetProcAddress = NULL;

	LPSTR WINAPI GetCommandLineA(VOID) {
		return ::GetCommandLineA();
	}

	LPWSTR WINAPI GetCommandLineW(VOID) {
		return ::GetCommandLineW();
	}

	void WINAPI Unknown() {

	}

	FARPROC WINAPI FakeGetProcAddress(__in HMODULE hModule, __in LPCSTR lpProcName) {
		char szModulePath[MAX_PATH + 1] = { 0 };

		if (::GetModuleHandle(_T("Kernel32.dll")) == hModule && 0 == strcmp(lpProcName, "GetCommandLineA")) {
			return (FARPROC)GetCommandLineA;
		}

		if (::GetModuleHandle(_T("Kernel32.dll")) == hModule && 0 == strcmp(lpProcName, "GetCommandLineW")) {
			return (FARPROC)GetCommandLineW;
		}

		return pfnGetProcAddress(hModule, lpProcName);
	}
}

namespace Hook {

	bool StartGetProcAddressHook()
	{
		bool bIsHook = true;

		// 所有附加广告
		if (NULL == pfnGetProcAddress) {
			bIsHook = HookControl::InlineHook(GetProcAddress(LoadLibrary(_T("Kernel32.dll")), "GetProcAddress"), FakeGetProcAddress, (void **)&pfnGetProcAddress);

			Global::Log.Print(LOGOutputs, _T("[HOOK] start hook control GetProcAddress stutus is %u."), bIsHook);
		}

		return bIsHook;
	}
}