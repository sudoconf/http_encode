#include "SPIInstaller.h"

#define UNICODE
#define _UNICODE
#include <Ws2spi.h>
#include <Sporder.h> // 定义了WSCWriteProviderOrder函数
#include <windows.h>
#include <stdio.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Rpcrt4.lib") // 实现了UuidCreate函数

LPWSAPROTOCOL_INFOW GetAllProvider(int * pnProtocalsNumber)
{
	int nError = 0;
	DWORD dwNeedSize = 0;
	LPWSAPROTOCOL_INFOW pProtoInfo = NULL;

	// 取得需要的长度
	if (::WSCEnumProtocols(NULL, pProtoInfo, &dwNeedSize, &nError) == SOCKET_ERROR && WSAENOBUFS != nError)
		return NULL;

	pProtoInfo = (LPWSAPROTOCOL_INFOW)::GlobalAlloc(GPTR, dwNeedSize);

	*pnProtocalsNumber = ::WSCEnumProtocols(NULL, pProtoInfo, &dwNeedSize, &nError);

	return pProtoInfo;
}

void FreeProvider(LPWSAPROTOCOL_INFOW pProtoInfo)
{
	::GlobalFree(pProtoInfo);
}

bool SPIInstall(const wchar_t * pwszLSPProtocolName, const wchar_t *pwszPathName)
{
	int nError = 0;
	int nProtocols = 0;
	PDWORD pdwProtocalOrders = NULL;
	LPWSAPROTOCOL_INFOW pAllProtocolsInfo = NULL;

	int nArrayCount = 0;
	bool bIsSuccess = false;
	DWORD dwInstallCatalogID = 0;
	DWORD dwOrigCatalogId[3] = { 0 };
	WSAPROTOCOL_INFOW wpiLayeredProtocolInfo = { 0 };
	WSAPROTOCOL_INFOW wpiOriginalProtocolInfo[3] = { 0 };


	if (NULL == (pAllProtocolsInfo = GetAllProvider(&nProtocols)))//枚举所有服务程序提供者
		return FALSE;

	BOOL bFindTcp = FALSE;
	BOOL bFindUdp = FALSE;
	BOOL bFindRaw = FALSE;

	for (int i = 0; i < nProtocols; i++)	// 找到我们的下层协议，将信息放入数组中
	{
		if (pAllProtocolsInfo[i].iAddressFamily != AF_INET)
			continue;

		if (3 == nArrayCount)
			break;

		switch (pAllProtocolsInfo[i].iProtocol)
		{
		case IPPROTO_IP:
		{
			if (bFindRaw)
				break;

			memcpy(&wpiOriginalProtocolInfo[nArrayCount], &pAllProtocolsInfo[i], sizeof(WSAPROTOCOL_INFOW));
			wpiOriginalProtocolInfo[nArrayCount].dwServiceFlags1 = wpiOriginalProtocolInfo[nArrayCount].dwServiceFlags1 & (~XP1_IFS_HANDLES);
			bFindRaw = TRUE;
			dwOrigCatalogId[nArrayCount++] = pAllProtocolsInfo[i].dwCatalogEntryId;

			break;
		}
		case IPPROTO_TCP:
		{
			if (bFindTcp)
				break;

			memcpy(&wpiOriginalProtocolInfo[nArrayCount], &pAllProtocolsInfo[i], sizeof(WSAPROTOCOL_INFOW));
			wpiOriginalProtocolInfo[nArrayCount].dwServiceFlags1 = wpiOriginalProtocolInfo[nArrayCount].dwServiceFlags1 & (~XP1_IFS_HANDLES);

			bFindTcp = TRUE;
			dwOrigCatalogId[nArrayCount++] = pAllProtocolsInfo[i].dwCatalogEntryId;

			break;
		}
		case IPPROTO_UDP:
		{
			if (bFindUdp)
				break;

			memcpy(&wpiOriginalProtocolInfo[nArrayCount], &pAllProtocolsInfo[i], sizeof(WSAPROTOCOL_INFOW));
			wpiOriginalProtocolInfo[nArrayCount].dwServiceFlags1 = wpiOriginalProtocolInfo[nArrayCount].dwServiceFlags1 & (~XP1_IFS_HANDLES);

			bFindUdp = TRUE;
			dwOrigCatalogId[nArrayCount++] = pAllProtocolsInfo[i].dwCatalogEntryId;
			break;
		}
		}
	}

	memcpy(&wpiLayeredProtocolInfo, &wpiOriginalProtocolInfo[0], sizeof(WSAPROTOCOL_INFOW)); // 安装我们的分层协议，获取一个dwLayeredCatalogId, 随便找一个下层协议的结构复制过来即可

	wcscpy_s(wpiLayeredProtocolInfo.szProtocol, pwszLSPProtocolName);

	wpiLayeredProtocolInfo.dwProviderFlags |= PFL_HIDDEN;
	wpiLayeredProtocolInfo.ProtocolChain.ChainLen = LAYERED_PROTOCOL; 	 // 修改协议名称，类型，设置PFL_HIDDEN标志

	do
	{
		if (::WSCInstallProvider(&GUID_SPIProvider, pwszPathName, &wpiLayeredProtocolInfo, 1, &nError) == SOCKET_ERROR) // 安装
			break;

		FreeProvider(pAllProtocolsInfo);

		if (NULL == (pAllProtocolsInfo = GetAllProvider(&nProtocols)))// 重新枚举协议，获取分层协议的目录ID号
			break;

		for (int i = 0; i < nProtocols; i++)
		{
			if (memcmp(&pAllProtocolsInfo[i].ProviderId, &GUID_SPIProvider, sizeof(GUID_SPIProvider)) == 0)
			{
				dwInstallCatalogID = pAllProtocolsInfo[i].dwCatalogEntryId;
				break;
			}
		}

		WCHAR wszChainName[WSAPROTOCOL_LEN + 1] = { 0 }; // 安装协议链 修改协议名称，类型

		for (int i = 0; i < nArrayCount; i++)
		{
			swprintf_s(wszChainName, L"%ws over %ws", pwszLSPProtocolName, wpiOriginalProtocolInfo[i].szProtocol);

			wcscpy_s(wpiOriginalProtocolInfo[i].szProtocol, wszChainName);

			if (wpiOriginalProtocolInfo[i].ProtocolChain.ChainLen == 1)
			{
				wpiOriginalProtocolInfo[i].ProtocolChain.ChainEntries[1] = dwOrigCatalogId[i];
			}
			else
			{
				for (int j = wpiOriginalProtocolInfo[i].ProtocolChain.ChainLen; j > 0; j--)
					wpiOriginalProtocolInfo[i].ProtocolChain.ChainEntries[j] = wpiOriginalProtocolInfo[i].ProtocolChain.ChainEntries[j - 1];
			}

			wpiOriginalProtocolInfo[i].ProtocolChain.ChainLen++;
			wpiOriginalProtocolInfo[i].ProtocolChain.ChainEntries[0] = dwInstallCatalogID;
		}

		GUID GUID_SPIProviderChain = { 0 };
		if (::UuidCreate(&GUID_SPIProviderChain) != RPC_S_OK) // 获取一个Guid，安装之
			break;

		if (::WSCInstallProvider(&GUID_SPIProviderChain, pwszPathName, wpiOriginalProtocolInfo, nArrayCount, &nError) == SOCKET_ERROR)
			break;

		bIsSuccess = true;

		MessageBoxA(NULL, "调整顺序", ("调整顺序后, QQ 飞车安装一个无效的LSP会导致断网   返回后,会导致 LSP 无效"), MB_OK);//return bIsSuccess;	// 调整顺序后, QQ 飞车安装一个无效的LSP会导致断网   返回后,会导致 LSP 无效

		FreeProvider(pAllProtocolsInfo);

		if (NULL == (pAllProtocolsInfo = GetAllProvider(&nProtocols)))// 重新排序Winsock目录，将我们的协议链提前
			break;

		int nIndex = 0;
		PDWORD pdwProtocalOrders = (PDWORD)malloc(sizeof(DWORD) * nProtocols);

		for (int i = 0; i < nProtocols; i++) // 添加我们的协议链
		{
			if ((pAllProtocolsInfo[i].ProtocolChain.ChainLen > 1) && (pAllProtocolsInfo[i].ProtocolChain.ChainEntries[0] == dwInstallCatalogID))
				pdwProtocalOrders[nIndex++] = pAllProtocolsInfo[i].dwCatalogEntryId;
		}

		// 添加其它协议
		for (int i = 0; i < nProtocols; i++)
		{
			if ((pAllProtocolsInfo[i].ProtocolChain.ChainLen <= 1) || (pAllProtocolsInfo[i].ProtocolChain.ChainEntries[0] != dwInstallCatalogID))
				pdwProtocalOrders[nIndex++] = pAllProtocolsInfo[i].dwCatalogEntryId;
		}

		if ((nError = ::WSCWriteProviderOrder(pdwProtocalOrders, nIndex)) != ERROR_SUCCESS) // 重新排序Winsock目录
			break;

	} while (false);

	if (pAllProtocolsInfo)
		FreeProvider(pAllProtocolsInfo);

	return bIsSuccess;
}

BOOL SPIRemove()
{
	int i = 0;
	int nError = 0;
	int nProtocols = 0;
	DWORD dwLayeredCatalogId = 0;
	LPWSAPROTOCOL_INFOW pProtoInfo = NULL;

	pProtoInfo = GetAllProvider(&nProtocols); // 根据Guid取得分层协议的目录ID号

	for (i = 0; i < nProtocols; i++)
	{
		if (memcmp(&GUID_SPIProvider, &pProtoInfo[i].ProviderId, sizeof(GUID_SPIProvider)) == 0)
		{
			dwLayeredCatalogId = pProtoInfo[i].dwCatalogEntryId;
			break;
		}
	}

	if (i < nProtocols)
	{
		for (i = 0; i < nProtocols; i++) // 移除协议链
		{
			if ((pProtoInfo[i].ProtocolChain.ChainLen > 1) && (pProtoInfo[i].ProtocolChain.ChainEntries[0] == dwLayeredCatalogId))
				::WSCDeinstallProvider(&pProtoInfo[i].ProviderId, &nError);
		}

		::WSCDeinstallProvider(&GUID_SPIProvider, &nError); // 移除分层协议
	}
	else 
		return FALSE;

	return TRUE;
}