    .global neutron_dynamic_fast_call
neutron_dynamic_fast_call:
    push %rcx
    push %rdx
    push %rsi
    push %rdi

    push %r8
    push %r9
    push %r10
    push %r11

    movq %rdi, %rbp
    movq %rsi, %rcx

    call *%rax

    pop %r11
    pop %r10
    pop %r9
    pop %r8

    pop %rdi
    pop %rsi
    pop %rdx
    pop %rcx

    ret
