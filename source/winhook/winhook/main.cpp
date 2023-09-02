#include <iostream>

#include "winhook.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

typedef VOID (WINAPI * __OutputDebugStringA)(_In_opt_ LPCSTR lpOutputString);

typedef int (*__asm_func)();

uint8_t* Trampoline;
unsigned int TrampolineFreed;

int new_asm_func()
{
	unsigned int OldTrampolineFreed = InterlockedCompareExchange(&TrampolineFreed, 1, 0);
	if (!OldTrampolineFreed) {
		((__asm_func)Trampoline)();
	}
	printf("new_asm_func\n");
	return 0x12121212;
}

extern "C"
{
	int asm_func();
}

DWORD WINAPI ThreadFunction(LPVOID lpThreadParameter)
{
	while (true)
	{
		asm_func();
		//Sleep(100);
	}
	return 0;
}

int main()
{
	HANDLE hThread = CreateThread(NULL, 0, ThreadFunction, NULL, 0, NULL);
	if (hThread != NULL) {
		while (true)
		{
			InterlockedExchange(&TrampolineFreed, 0);
			winhook_hook(14, (uint8_t*)asm_func, (uint8_t*)new_asm_func, &Trampoline);
			InterlockedExchange(&TrampolineFreed, 1);
			winhook_unhook(14, (uint8_t*)asm_func, Trampoline);
			//Sleep(1000);
			//printf("\n");
			//printf("\n");
		}

		WaitForSingleObject(hThread, INFINITE);
	}
	//blxc();
	return 0;
}

void my_main()
{
	main();
}
