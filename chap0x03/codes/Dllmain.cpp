BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		// ����ԭʼAPI��ַ
		g_pOrgFunc = GetProcAddress(GetModuleHandle(L"user32.dll"),
			"SetWindowTextW");

		// # hook
		// ��hookiat.MySetWindowText()��ȡuser32.SetWindowTextW()
		hook_iat("user32.dll", g_pOrgFunc, (PROC)MySetWindowTextW);
		break;

	case DLL_PROCESS_DETACH:
		// # unhook
		//  ��calc.exe��IAT�ָ�ԭֵ
		hook_iat("user32.dll", (PROC)MySetWindowTextW, g_pOrgFunc);
		break;
	}

	return TRUE;
}
