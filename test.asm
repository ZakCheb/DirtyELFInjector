; Shellcode inpired fro https://www.matteomalvica.com/blog/2019/05/18/injecting-shellcode-into-x64-elf-binaries/


  nop
  nop
  nop
  push rax         ; save all clobbered registers
  mov rax,0xdeadbeef
  pop rax
  jmp 0x6130  ;ENTRY
