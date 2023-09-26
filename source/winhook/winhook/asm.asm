IFDEF RAX

    .data

    .code

    asm_func proc
        nop
        nop
        nop
        nop
        nop

        nop
        nop
        nop
        nop
        nop

        nop
        nop
        nop
        nop

        mov eax, 12345678h
        ret
    asm_func endp

ELSE

    .model flat, C 
    .data

    .code

    asm_func proc
        nop
        nop
        nop
        nop
        nop
        mov eax, 12345678h
        retn
    asm_func endp

ENDIF

END

