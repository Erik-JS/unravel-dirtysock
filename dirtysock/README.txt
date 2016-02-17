Welcome to the Unravel dirtysock project.

README.txt => some cheap text file written in Notepad.

dirtysock.cbp => Code::Blocks project file.

main.cpp => main.cpp.

main.h => main.h.

OK, so there's no sln or vcproj here because Visual Studio doesn't support inline asm for 64-bit projects.

GCC from MinGW-w64 or TDM-GCC does support inline x64 asm, but the syntax used there is a bit different from VS...

After several Google searches and a bunch of trial and error, I finally found out how to do "jump to the address of var" with GCC.

Aside from Code::Blocks as IDE, I used TDM-GCC as compiler, with "-m64" (to compile into 64-bit binary).

http://www.codeblocks.org/
http://tdm-gcc.tdragon.net/