@echo off
yasm -fbin -DBIN ExecPIC.asm -o ExecPIC.bin
yasm -fbin -DBIN LoadDLLPIC.asm -o LoadDLLPIC.bin
yasm -fbin -DBIN CreateThreadPIC.asm -o CreateThreadPIC.bin
bin2sc ExecPIC.bin 64 >winexec.h
bin2sc LoadDLLPIC.bin 64 >loadlib.h
bin2sc CreateThreadPIC.bin 64 >createthread.h
cl /nologo /c pi.c 
link /nologo /subsystem:console pi.obj /out:pi64.exe
del *.obj