This is an in memory version of the Uacme privelege elevation tool. The purpose of the tool is to execute elevated shellcode stealthily, in order to understand microsoft windows operating system security. If uac level 2 is enabled, shellcode is executed without writing to disk. If uac 3 is enabled, a dll is written to disk.

The end stage of the tool implements persistence by installing a phony printer driver for an older model of printer which does not have signatures for its executable code.

Written in C, the tool is optimized to be small and single stage, its size mostly taken up by the jpg file it masquerades as. It never makes a callback until it is installed.
