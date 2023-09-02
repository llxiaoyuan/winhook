#pragma once
#include <stdint.h>

/*

//before
OldFunction proc
	nop
	nop
	nop
	nop
	nop
	mov eax, 12345678h
	retn
OldFunction endp

//after
OldFunction proc
	jmp new_asm_func
	mov eax, 12345678h
	retn
OldFunction endp

Trampoline proc
	nop
	nop
	nop
	nop
	nop
	jmp OldFunction
Trampoline endp

NewFunction proc
	call Trampoline
	retn
NewFunction endp

*/

#ifdef __cplusplus
extern "C" {
#endif

	void winhook_hook(size_t Size, uint8_t* OldFunction, uint8_t* NewFunction, uint8_t** Trampoline);
	void winhook_unhook(size_t Size, uint8_t* OldFunction, uint8_t* Trampoline);

#ifdef __cplusplus
}
#endif
