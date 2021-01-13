BOOL hook_iat(LPCSTR szDllName, PROC pfnOrg, PROC pfnNew)
{
	HMODULE hMod;
	LPCSTR szLibName;
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
	PIMAGE_THUNK_DATA pThunk;
	DWORD dwOldProtect, dwRVA;
	PBYTE pAddr;

	// hMod, pAddr = ImageBase of calc.exe
	//             = VA to MZ signature (IMAGE_DOS_HEADER)
	hMod = GetModuleHandle(NULL);
	pAddr = (PBYTE)hMod;

	// pAddr = VA to PE signature (IMAGE_NT_HEADERS)
	pAddr += *((DWORD*)&pAddr[0x3C]);

	// dwRVA = RVA to IMAGE_IMPORT_DESCRIPTOR Table
	dwRVA = *((DWORD*)&pAddr[0x80]);

	// pImportDesc = VA to IMAGE_IMPORT_DESCRIPTOR Table
	pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)hMod + dwRVA);

	for (; pImportDesc->Name; pImportDesc++)
	{
		// szLibName = VA to IMAGE_IMPORT_DESCRIPTOR.Name
		szLibName = (LPCSTR)((DWORD)hMod + pImportDesc->Name);
		if (!_stricmp(szLibName, szDllName))
		{
			// pThunk = IMAGE_IMPORT_DESCRIPTOR.FirstThunk
			//        = VA to IAT(Import Address Table)
			pThunk = (PIMAGE_THUNK_DATA)((DWORD)hMod +
				pImportDesc->FirstThunk);

			// pThunk->u1.Function = VA to API
			for (; pThunk->u1.Function; pThunk++)
			{
				if (pThunk->u1.Function == (DWORD)pfnOrg)
				{
					// 메모리 속성을 E/R/W 로 변경
					VirtualProtect((LPVOID)&pThunk->u1.Function,
						4,
						PAGE_EXECUTE_READWRITE,
						&dwOldProtect);

					// IAT 값을 변경
					pThunk->u1.Function = (DWORD)pfnNew;

					// 메모리 속성 복원
					VirtualProtect((LPVOID)&pThunk->u1.Function,
						4,
						dwOldProtect,
						&dwOldProtect);

					return TRUE;
				}
			}
		}
	}

	return FALSE;
}

