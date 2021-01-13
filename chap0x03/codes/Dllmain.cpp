BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		// 保存原始API地址
		g_pOrgFunc = GetProcAddress(GetModuleHandle(L"user32.dll"),
			"SetWindowTextW");

		// # hook
		// 用hookiat.MySetWindowText()钩取user32.SetWindowTextW()
		hook_iat("user32.dll", g_pOrgFunc, (PROC)MySetWindowTextW);
		break;

	case DLL_PROCESS_DETACH:
		// # unhook
		//  将calc.exe的IAT恢复原值
		hook_iat("user32.dll", (PROC)MySetWindowTextW, g_pOrgFunc);
		break;
	}

	return TRUE;
}
