#include <iostream>
#include <windows.h>
#include <string>
#include <stdio.h>
#include <Psapi.h>
#include <sys/types.h>
#include <tlhelp32.h>

void* DetourFunction(BYTE* src, DWORD dst, const int len) {
	BYTE* jmp = (BYTE*)malloc(len + 5);
	DWORD dwBack;
	VirtualProtect(src, len, PAGE_EXECUTE_READWRITE, &dwBack);
	memcpy(jmp, src, len);
	jmp += len;
	jmp[0] = 0xE9;
	*(DWORD*)(jmp + 1) = (DWORD)(src + len - jmp) - 5;
	src[0] = 0xE9;
	*(DWORD*)(src + 1) = (DWORD)(dst - (DWORD)src) - 5;
	for (int i = 5; i < len; i++) src[i] = 0x90;
	VirtualProtect(src, len, dwBack, &dwBack);
	return (jmp - len);
}

DWORD FindProcess(__in_z LPCTSTR lpcszFileName) {

}

DWORD InitStart = 0;
DWORD InitComplete = 0;
DWORD Exit23 = 0;
DWORD Exit23JMP = 0;
DWORD Exit24 = 0;
DWORD Exit24JMP = 0;


void TranslateString()
{
	DWORD GetGameStart = (DWORD)GetModuleHandleA('lostsaga.exe');
	DWORD InitStart = (DWORD) GetGameStart + 0x105EF66;
	BYTE* jmpInit = NULL;
	BYTE* jmpExit23 = NULL;
	BYTE* jmpExit24 = NULL;
	
	while (true)
	{
		DetourFunction((PBYTE)InitStart, (DWORD)InitComplete, 5;
	}
}