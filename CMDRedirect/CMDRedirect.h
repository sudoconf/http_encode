#pragma once
#include <tchar.h>
#include <assert.h>
#include <windows.h>

#include "CommonControl\Log.h"
#include <wininet.h>

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
