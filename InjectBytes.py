from pwn import *
'''
[+] CAVE DETECTED!
[!] Section Name: .bss
[!] Section Offset: 0x215e8
[!] Section Size: 0x12d8 (4824 bytes)
[!] Section Flags: SHF_WRITE+SHF_ALLOC
[!] Virtual Address: 0x2273d
[!] Cave Begin: 0x21725
[!] Cave End: 0x21768
[!] Cave Size: 0x43 (67 bytes)
'''
write_add=0x21725

e=ELF("ls")

e.write(write_add,asm('nop; pop eax;pop ebx;nop')) # Works!


e.save("ls_injected")
