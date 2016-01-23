#pragma once
#include <guiddef.h>

// 要安装的LSP的硬编码，在移除的时候还要使用它
// {A7EFF9A7-3AB2-4421-98F8-2BEB95B93FBB}
static GUID GUID_SPIProvider = { 0xa7eff9a7, 0x3ab2, 0x4421,{ 0x98, 0xf8, 0x2b, 0xeb, 0x95, 0xb9, 0x3f, 0xbb } };


bool SPIInstall(const wchar_t * pwszLSPProtocolName, const wchar_t *pwszPathName);