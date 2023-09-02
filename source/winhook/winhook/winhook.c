#include "winhook.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <tlhelp32.h>

// Check windows
#if _WIN32 || _WIN64
#if _WIN64
#define ENVIRONMENT64
#else
#define ENVIRONMENT32
#endif
#endif
// Check GCC
#if __GNUC__
#if __x86_64__ || __ppc64__
#define ENVIRONMENT64
#else
#define ENVIRONMENT32
#endif
#endif

#ifdef ENVIRONMENT64
#define Xip Rip
#define JMP_LEN 14
#define write_jmp write_FF_25

static void write_FF_25(uint8_t* buffer, uint8_t* target)
{
	*(uint16_t*)buffer = 0x25FF;
	buffer += sizeof(uint16_t);
	*(int32_t*)buffer = 0;
	buffer += sizeof(int32_t);
	*(uint8_t**)buffer = target;
}

#else

#define Xip Eip
#define JMP_LEN 5
#define write_jmp write_E9

static void write_E9(uint8_t* buffer, uint8_t* target)
{
	*buffer = 0xE9;
	*(int32_t*)(buffer + 1) = target - (buffer + 5);
}

#endif // ENVIRONMENT64

#define THREAD_ACCESS (THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT)

static void* my_memcpy(void* _Dst, void const* _Src, size_t _Size)
{
	char* dp = (char*)_Dst;
	char* sp = (char*)_Src;

	for (size_t i = 0; i < _Size; i++) {
		dp[i] = sp[i];
	}

	return _Dst;
}

static void* my_memset(void* _Dst, int _Val, size_t _Size)
{
	char* q = (char*)_Dst;
	while (_Size--) {
		*q++ = _Val;
	}
	return _Dst;
}

void winhook_hook(size_t Size, uint8_t* OldFunction, uint8_t* NewFunction, uint8_t** Trampoline)
{
	size_t TrampolineSize = Size + JMP_LEN;
	(*Trampoline) = (uint8_t*)VirtualAlloc(NULL, TrampolineSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if ((*Trampoline) != NULL) {
		my_memcpy((*Trampoline), OldFunction, Size);
		write_jmp((*Trampoline) + Size, OldFunction + Size);
		FlushInstructionCache(GetCurrentProcess(), (*Trampoline), TrampolineSize);

		DWORD CurrentThreadId = GetCurrentThreadId();
		DWORD CurrentProcessId = GetCurrentProcessId();
		THREADENTRY32 threadEntry32;
		threadEntry32.dwSize = sizeof(THREADENTRY32);
		HANDLE threadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (threadSnapshot != INVALID_HANDLE_VALUE) {
			BOOL hasNext;
			hasNext = Thread32First(threadSnapshot, &threadEntry32);
			while (hasNext) {
				if (threadEntry32.th32OwnerProcessID == CurrentProcessId) {
					if (threadEntry32.th32ThreadID != CurrentThreadId) {
						HANDLE hThread = OpenThread(THREAD_ACCESS, FALSE, threadEntry32.th32ThreadID);
						if (hThread != NULL) {
							SuspendThread(hThread);
							CONTEXT context;
							context.ContextFlags = CONTEXT_CONTROL;
							if (GetThreadContext(hThread, &context)) {
								if ((uintptr_t)OldFunction <= context.Xip && context.Xip < (uintptr_t)OldFunction + Size) {
									context.Xip = (uintptr_t)(*Trampoline) + (context.Xip - (uintptr_t)OldFunction);
									SetThreadContext(hThread, &context);
								}
							}
							CloseHandle(hThread);
						}
					}
				}
				hasNext = Thread32Next(threadSnapshot, &threadEntry32);
			}

			DWORD Protect = PAGE_EXECUTE_READWRITE;
			VirtualProtect(OldFunction, Size, Protect, &Protect);
			write_jmp(OldFunction, NewFunction);
			VirtualProtect(OldFunction, Size, Protect, &Protect);
			FlushInstructionCache(GetCurrentProcess(), OldFunction, Size);

			hasNext = Thread32First(threadSnapshot, &threadEntry32);
			while (hasNext) {
				if (threadEntry32.th32OwnerProcessID == CurrentProcessId) {
					if (threadEntry32.th32ThreadID != CurrentThreadId) {
						HANDLE hThread = OpenThread(THREAD_ACCESS, FALSE, threadEntry32.th32ThreadID);
						if (hThread != NULL) {
							ResumeThread(hThread);
							CloseHandle(hThread);
						}
					}
				}
				hasNext = Thread32Next(threadSnapshot, &threadEntry32);
			}
			CloseHandle(threadSnapshot);
		}
	}
}

void winhook_unhook(size_t Size, uint8_t* OldFunction, uint8_t* Trampoline)
{
	DWORD CurrentThreadId = GetCurrentThreadId();
	DWORD CurrentProcessId = GetCurrentProcessId();
	THREADENTRY32 threadEntry32;
	threadEntry32.dwSize = sizeof(THREADENTRY32);
	HANDLE threadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (threadSnapshot != INVALID_HANDLE_VALUE) {
		BOOL hasNext;
		hasNext = Thread32First(threadSnapshot, &threadEntry32);
		while (hasNext) {
			if (threadEntry32.th32OwnerProcessID == CurrentProcessId) {
				if (threadEntry32.th32ThreadID != CurrentThreadId) {
					HANDLE hThread = OpenThread(THREAD_ACCESS, FALSE, threadEntry32.th32ThreadID);
					if (hThread != NULL) {
						SuspendThread(hThread);
						CONTEXT context;
						context.ContextFlags = CONTEXT_CONTROL;
						if (GetThreadContext(hThread, &context)) {
							if ((uintptr_t)Trampoline <= context.Xip && context.Xip <= (uintptr_t)Trampoline + Size) {
								context.Xip = (uintptr_t)OldFunction + (context.Xip - (uintptr_t)Trampoline);
								SetThreadContext(hThread, &context);
							}
						}
						CloseHandle(hThread);
					}
				}
			}
			hasNext = Thread32Next(threadSnapshot, &threadEntry32);
		}

		DWORD Protect = PAGE_EXECUTE_READWRITE;
		VirtualProtect(OldFunction, Size, Protect, &Protect);
		my_memcpy(OldFunction, Trampoline, Size);
		VirtualProtect(OldFunction, Size, Protect, &Protect);
		FlushInstructionCache(GetCurrentProcess(), OldFunction, Size);

		VirtualFree(Trampoline, 0, MEM_RELEASE);

		hasNext = Thread32First(threadSnapshot, &threadEntry32);
		while (hasNext) {
			if (threadEntry32.th32OwnerProcessID == CurrentProcessId) {
				if (threadEntry32.th32ThreadID != CurrentThreadId) {
					HANDLE hThread = OpenThread(THREAD_ACCESS, FALSE, threadEntry32.th32ThreadID);
					if (hThread != NULL) {
						ResumeThread(hThread);
						CloseHandle(hThread);
					}
				}
			}
			hasNext = Thread32Next(threadSnapshot, &threadEntry32);
		}
		CloseHandle(threadSnapshot);
	}
}
