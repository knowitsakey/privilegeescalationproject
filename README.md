This is an in memory version of the Uacme privelege elevation tool. The point of the tool is to execute elevated shellcode stealthily, and if uac level 2 enabled, without writing to disk. If uac 3 enabled, writes to disk briefly.
The end stage of the tool implements persistence by installing a "printer driver" for an old printer.
Written in C, the tool is optimized to be small, its size mostly taken up by the jpg file it masquerades as, never downloading a second stage or making a callback until it's installed.

## Units

- Akagi, x64/x86-32 main executable file, contain payload/data units.
- Akatsuki, x64 payload, WOW64 logger.
- Fubuki, x64/x86-32 payload, general purpose.
- Kamikaze, data, MMC snap-in.
- Naka, x64/x86-32 compressor for other payload/data units.
- Yuubari, x64 UAC info data dumper.

## Other

- Shared, contain headers and source code shared between several projects.
