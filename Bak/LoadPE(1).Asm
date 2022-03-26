.586
.model flat,stdcall
option casemap:none

   include windows.inc
   include user32.inc
   include kernel32.inc 
   include msvcrt.inc
   includelib user32.lib
   includelib kernel32.lib
   includelib msvcrt.LIB


IMAGE_SIZE equ 00020000h
.data
   g_szExeName db "winmine.exe",0
   g_szLoadError db "加载dll失",0

.data?
   hInstance HINSTANCE ?
   CommandLine LPSTR ?

.code
	db IMAGE_SIZE dup(0)
	org IMAGE_SIZE

; ---------------------------------------------------------------------------
LoadPe proc
	LOCAL @hFile:HANDLE
	LOCAL @hFileMap:HANDLE
	LOCAL @lpMapAddr:LPVOID
	LOCAL @dwFileSize:DWORD
	LOCAL @dwNumberOfsection:DWORD
	LOCAL @dwNumOfHeaders:DWORD
	LOCAL @pSecHdr:ptr IMAGE_SECTION_HEADER
	LOCAL @hInst:HANDLE
	LOCAL @dwOldProc:DWORD
	LOCAL @pImpHdr:ptr IMAGE_IMPORT_DESCRIPTOR
	LOCAL @zeroImp:IMAGE_IMPORT_DESCRIPTOR
	LOCAL @hDll:HANDLE
	LOCAL @pTempThunk: ptr IMAGE_DATA_THUNK
	LOCAL @dwPFNAddr:dword
	LOCAL @dwIAT:DWORD
	LOCAL @dwOep:DWORD
	
	int 3;
	invoke GetModuleHandle,NULL
	mov @hInst,eax
	
	
	invoke RtlZeroMemory,addr @zeroImp,sizeof IMAGE_IMPORT_DESCRIPTOR
	
	
	;映射文件
	invoke CreateFile,offset g_szExeName,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL
	.if eax ==INVALID_HANDLE_VALUE
		
		xor eax,eax
		ret	
	.endif
	mov @hFile,eax
	
	invoke CreateFileMapping,@hFile,NULL,PAGE_READONLY,0,0,NULL
	.if eax==NULL
		invoke CloseHandle,@hFile
		ret
	.endif
	
	mov @hFileMap,eax
	
	invoke MapViewOfFile,@hFileMap,FILE_MAP_READ,0,0,0
	
	.if eax==NULL
		invoke CloseHandle,@hFileMap
		invoke CloseHandle,@hFile
		xor eax,eax
		ret
	.endif 
	
	mov @lpMapAddr,eax
	assume esi:nothing
	
	;拷贝PE
	mov esi,@lpMapAddr
	assume esi:ptr IMAGE_DOS_HEADER
	;指向新的NT头地址
	add esi,[esi].e_lfanew
	assume esi:ptr IMAGE_NT_HEADERS
	
	
	mov eax,[esi].OptionalHeader.SizeOfHeaders
	mov @dwNumOfHeaders,eax
	
	;节表数量
	movzx eax,[esi].FileHeader.NumberOfSections
	mov @dwNumberOfsection,eax
	
	;存储的是节表头地址
	movzx eax,[esi].FileHeader.SizeOfOptionalHeader
	lea ebx,[esi].OptionalHeader
	add eax,ebx
	mov @pSecHdr,eax
	
	int 3;
	push [esi].OptionalHeader.AddressOfEntryPoint
	pop @dwOep
	mov eax,@hInst
	add @dwOep,eax
	
	;得到导入表的地址
	lea eax,[esi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT * sizeof IMAGE_DATA_DIRECTORY ]
	assume eax:ptr IMAGE_DATA_DIRECTORY
	
	mov eax,[eax].VirtualAddress
	add eax,@hInst
	
	mov @pImpHdr,eax
	
	assume eax:nothing	
	assume esi:nothing
	
	assume eax:ptr IMAGE_DATA_DIRECTORY
	
		
	;拷贝PE头
	;修改内存数据

	
	invoke VirtualProtect,@hInst,IMAGE_SIZE,PAGE_EXECUTE_READWRITE,addr @dwOldProc
	
	
	invoke crt_memcpy,@hInst,@lpMapAddr,@dwNumOfHeaders
	
	
	;拷贝节
	xor ebx,ebx
	
	
	 
	.while ebx < @dwNumberOfsection
		mov ecx,@pSecHdr
		assume ecx:ptr IMAGE_SECTION_HEADER
		;源
		mov esi,[ecx].PointerToRawData
		add esi,@lpMapAddr
		
		;目的
		mov edi,[ecx].VirtualAddress
		add edi,@hInst
		
		
		invoke crt_memcpy,edi,esi,[ecx].SizeOfRawData
		assume ecx:nothing
		
		
		add @pSecHdr,sizeof IMAGE_SECTION_HEADER
		inc ebx
	.endw
	
	
	;处理导入表
	.while TRUE
	;遇到全0项目，遍历结束
	 	invoke crt_memcmp,@pImpHdr,addr @zeroImp,sizeof IMAGE_IMPORT_DESCRIPTOR
	 	.if eax == 0
	  		.break
	  	.endif
	  
	 	mov esi,@pImpHdr
	 	assume esi:ptr IMAGE_IMPORT_DESCRIPTOR
		
		;获取dll的名称
		
		mov eax,[esi].Name1
		add eax,@hInst
		
		invoke LoadLibrary,eax
		.if eax==NULL
		 	;
		 	invoke MessageBox,NULL,offset g_szLoadError,offset g_szLoadError,MB_OK
			.break
		.endif
		
		mov @hDll,eax
		
		
		.if [esi].FirstThunk ==NULL
			.break
		.endif
		mov eax,[esi].FirstThunk
		add eax,@hInst
		mov @dwIAT,eax
		
		
		
		mov eax,[esi].OriginalFirstThunk
		mov @pTempThunk,eax
		
		.if @pTempThunk ==NULL
			mov eax,[esi].FirstThunk
			mov @pTempThunk,eax	
		.endif
		
		mov eax,@hInst
		add @pTempThunk,eax
		
		
		
		
		mov ebx,@pTempThunk
		.while dword ptr [ebx]!=NULL
			.if dword ptr[ebx] &  8000000h
				;序号导入
				movzx eax,word ptr [ebx] ;低字为序号
				invoke GetProcAddress,@hDll,eax
				;check
				mov @dwPFNAddr,eax
			
			.else
				;名称导入
				mov eax,[ebx]
				add eax,@hInst ;ptr IMAGE_IMPORT_BY_NAME 前面有一个word
				add eax,sizeof word;导入函数地址
				invoke GetProcAddress,@hDll,eax
				mov @dwPFNAddr,eax
				
			.endif
			
			
			;填充IAT
			mov eax,@dwIAT
			push @dwPFNAddr
			pop dword ptr [eax]
			
			
			add ebx,4
			add @dwIAT,4
		.endw
		
		 
		
		
		
	 	assume esi:nothing
	 	add @pImpHdr,sizeof IMAGE_IMPORT_DESCRIPTOR;下一项
	.endw
	;清理
	invoke UnmapViewOfFile,@lpMapAddr
	invoke CloseHandle,@hFileMap
	invoke CloseHandle,@hFile
	
	;返回oep地址
	mov eax,@dwOep
	ret

LoadPe endp

start:
	invoke LoadPe
	.if eax!=NULL
		jmp eax
	.endif
	
 invoke ExitProcess,0


end start
