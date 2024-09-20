This is an in memory version of the Uacme privelege elevation tool. The purpose of the tool is to execute elevated shellcode stealthily, in order to understand microsoft windows operating system security. If uac level 2 is enabled, shellcode is executed without writing to disk. If uac 3 is enabled, a dll is written to disk.
The end stage of the tool implements persistence by installing a phony printer driver for an older model of printer which does not have signatures for its executable code.
Written in C, the tool is optimized to be small and single stage, its size mostly taken up by the jpg file it masquerades as. It never makes a callback until it is installed.

## Units

- Akagi, x64/x86-32 main executable file, contain payload/data units.
- Akatsuki, x64 payload, WOW64 logger.
- Fubuki, x64/x86-32 payload, general purpose.
- Kamikaze, data, MMC snap-in.
- Naka, x64/x86-32 compressor for other payload/data units.
- Yuubari, x64 UAC info data dumper.

## Other

- Shared, contain headers and source code shared between several projects.
