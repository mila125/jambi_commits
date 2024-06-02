.386
.model flat, stdcall
option casemap : none

include \masm32\include\msvcrt.inc
include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\user32.inc 
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\user32.lib
includelib \masm32\lib\msvcrt.lib

.data
errorMsgCaption db "Error!", 0
errorMsgText db "Error finding first file!", 0
errorMsgText2 db "Error opening file!", 0
errorMsgText3 db "Error seeking file!", 0
errorMsgText4 db "Error telling file size!", 0
errorMsgText5 db "Error reading the file!", 0
errorMsgText6 db "Error writing into the file!", 0
mode db "rb", 0
file_regex db "*.exe", 0
buffer db 256 dup(0)
format db "File size: %d", 0
msgCaption db "File Info", 0

.data?
filesearchhandle dd ?
filehandle dd ?
filesize dd ?
fileptr dd ?
win32finddata WIN32_FIND_DATA <>
filebuffer db 4096 dup(?)

.code

start:
    invoke FindFirstFileA, addr file_regex, addr win32finddata
    cmp eax, INVALID_HANDLE_VALUE
    je findfirstfile_failed
    mov filesearchhandle, eax

search_exe_loop:
    invoke MessageBoxA, NULL, addr win32finddata.cFileName, addr msgCaption, MB_OK
    
    invoke crt_fopen, addr win32finddata.cFileName, addr mode
    mov filehandle, eax
    cmp filehandle, 0
    je open_failed

    invoke crt_fseek, filehandle, 0, 2 ; SEEK_END is 2
    cmp eax, 0
    jne fseek_failed

    invoke crt_ftell, filehandle
    cmp eax, -1
    je ftell_failed

    mov filesize, eax
    invoke wsprintf, addr buffer, addr format, filesize
    invoke MessageBoxA, NULL, addr buffer, addr msgCaption, MB_OK

    add eax, 5000h
    invoke VirtualAlloc, 0, eax, MEM_COMMIT, PAGE_READWRITE
    mov fileptr, eax
    cmp eax, 0
    je syserr

    invoke crt_fseek, filehandle, 0, 0 ; SEEK_SET is 0
    cmp eax, 0
    jne fseek_failed

    ; Leer el archivo usando crt_fgets
    invoke crt_fgets, addr filebuffer, sizeof filebuffer, filehandle
    cmp eax, 0
    je syserr

    invoke MessageBoxA, NULL, addr filebuffer, addr msgCaption, MB_OK

    ; Cierra el archivo y libera la memoria
    invoke crt_fclose, filehandle
    invoke VirtualFree, fileptr, 0, MEM_RELEASE

find_next:
    invoke FindNextFileA, filesearchhandle, addr win32finddata
    cmp eax, 0
    je exit_search_exe

    jmp search_exe_loop

findfirstfile_failed:
    invoke MessageBoxA, NULL, addr errorMsgText, addr errorMsgCaption, MB_OK
    jmp exit_search_exe

open_failed:
    invoke MessageBoxA, NULL, addr errorMsgText2, addr errorMsgCaption, MB_OK
    jmp find_next

fseek_failed:
    invoke MessageBoxA, NULL, addr errorMsgText3, addr msgCaption, MB_OK
    invoke ExitProcess, 2

ftell_failed:
    invoke MessageBoxA, NULL, addr errorMsgText4, addr msgCaption, MB_OK
    invoke ExitProcess, 3

syserr:
    invoke MessageBoxA, NULL, addr errorMsgText5, addr errorMsgCaption, MB_OK
    jmp search_exe_loop

error_writing_file:
    invoke MessageBoxA, NULL, addr errorMsgText6, addr msgCaption, MB_OK
    invoke crt_fclose, filehandle
    invoke ExitProcess, 1

exit_search_exe:
    invoke FindClose, filesearchhandle
    invoke ExitProcess, 0

end start