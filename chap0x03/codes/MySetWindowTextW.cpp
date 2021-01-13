BOOL WINAPI MySetWindowTextW(HWND hWnd, LPWSTR lpString)
{
	wchar_t* pNum = L"쥐寧랗힛愷巧짇펌검씽";
	wchar_t temp[2] = { 0, };
	int i = 0, nLen = 0, nIndex = 0;

	nLen = wcslen(lpString);
	for (i = 0; i < nLen; i++)
	{
		// '수'문자를 '한글'문자로 변환
		//   lpString 은 wide-character (2 byte) 문자열
		if (L'0' <= lpString[i] && lpString[i] <= L'9')
		{
			temp[0] = lpString[i];
			nIndex = _wtoi(temp);
			lpString[i] = pNum[nIndex];
		}
	}

	// user32!SetWindowTextW() API 호출
	//   (위에서 lpString 버퍼 내용을 변경하였음)
	return ((PFSETWINDOWTEXTW)g_pOrgFunc)(hWnd, lpString);
}
