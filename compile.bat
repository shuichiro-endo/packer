@ECHO OFF

nasm -f bin stub.asm -o stub.bin
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp packer.cpp /link /OUT:packer.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

del *.obj

