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

.DATA
    msgCaption db "Information", 0
    fileName db "calc.exe", 0    ; Nombre del archivo a leer
    file_buffer db 256 dup(0)    ; Buffer de 256 bytes para leer datos
    format db "File content: %s", 0
    outputBuffer db 512 dup(0)
    mode db "rb", 0
    errormsg1 db "Error opening file", 0
    errormsg2 db "Error reading file", 0
.DATA?
    fileHandle dd ?
    bytesRead dd ?

.CODE
start:
    ; Abrir archivo
    invoke crt_fopen, addr fileName, addr mode
    mov fileHandle, eax

    ; Verificar si el archivo se abrió correctamente
    cmp fileHandle, 0
    je error_open_file

    ; Leer archivo
    invoke crt_fread, addr file_buffer, 1, 256, fileHandle
    mov bytesRead, eax

    ; Verificar si la lectura fue exitosa
    cmp bytesRead, 0
    je error_read_file

    ; Cerrar archivo
    invoke crt_fclose, fileHandle

    ; Mostrar contenido leído (posición inicial)
    lea esi, file_buffer
    invoke MessageBoxA, NULL, esi, addr msgCaption, MB_OK

    ; Mostrar contenido leído (posición 16)
    lea esi, file_buffer
    add esi, 16
    invoke MessageBoxA, NULL, esi, addr msgCaption, MB_OK

    ; Mostrar contenido leído (posición 128)
    lea esi, file_buffer
    add esi, 128
    invoke MessageBoxA, NULL, esi, addr msgCaption, MB_OK

    ; Formatear y mostrar el contenido completo del buffer
    invoke wsprintf, addr outputBuffer, addr format, addr file_buffer
    invoke MessageBoxA, NULL, addr outputBuffer, addr msgCaption, MB_OK

    ; Finalizar programa
    invoke ExitProcess, 0

error_open_file:
    invoke MessageBoxA, NULL, addr errormsg1, addr msgCaption, MB_OK
    invoke ExitProcess, 1

error_read_file:
    invoke MessageBoxA, NULL, addr errormsg2, addr msgCaption, MB_OK
    invoke ExitProcess, 1

END start