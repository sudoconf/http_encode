#pragma once
#include <tchar.h>
#include <assert.h>
#include <winsock2.h>

#include "CommonControl\Log.h"
#include <wininet.h>

#define ASSERT assert
#define count(_array) (sizeof(_array) / sizeof(_array[0]))

typedef LPWSTR(WINAPI *__pfnGetCommandLineW) (VOID);

namespace Global {
	extern CDebug Log;
	extern __pfnGetCommandLineW pfnGetCommandLineW;
}
