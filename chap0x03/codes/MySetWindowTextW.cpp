BOOL WINAPI MySetWindowTextW(HWND hWnd, LPWSTR lpString)
{
	wchar_t* pNum = L"��һ�����������߰˾�";
	wchar_t temp[2] = { 0, };
	int i = 0, nLen = 0, nIndex = 0;

	nLen = wcslen(lpString);
	for (i = 0; i < nLen; i++)
	{
		// '��'���ڸ� '�ѱ�'���ڷ� ��ȯ
		//   lpString �� wide-character (2 byte) ���ڿ�
		if (L'0' <= lpString[i] && lpString[i] <= L'9')
		{
			temp[0] = lpString[i];
			nIndex = _wtoi(temp);
			lpString[i] = pNum[nIndex];
		}
	}

	// user32!SetWindowTextW() API ȣ��
	//   (������ lpString ���� ������ �����Ͽ���)
	return ((PFSETWINDOWTEXTW)g_pOrgFunc)(hWnd, lpString);
}
