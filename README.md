# Quick and Dirty Backdooring script x64 ELF binaries

## Disclaimer
I'm not responsible for the malicious any usage of this script, execute the binary generated by the script on machines with permission of the owners.
This tool is only 

## How it works
This was inspired by reading Practical Binary Analysis book, it was a great ressource to get the basics right.
How the `Inject` script work.

1. Inject new read/write/execute section, used with objcopy.
2. Change Entry point to the new section with  radare2.
3. Put the payload in the new section, used nasm+ld to compile the Trampoline payload, the default paylaod is a bind shell that listens on 5000.
3. Jump back to the original Entrypoint when at the end of the Trampoline payload.

The trick is to set the section offset on unused code to avoid seg faults.
Successfull test on ls with 0xbeef section offset, no detection from [AV](https://www.virustotal.com/gui/file/cf69e2fe0329c43a8ec0f14599f26d0a78f15aa22cf30336dd59d374a30ea895/detection) like symantec, Kaspersky, fortinet ... was quite surprised for a first attempt.
UPDATE 2020-07-18 got detected by Avast, AVG.

## Requirements

- radare2
- python
