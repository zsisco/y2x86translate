# y2x86translate
## y86 to x86 binary translator
## Author: Zach Sisco

y2x86translate takes a y86 binary file and lifts the op codes to x86. 
With the x86 op codes, the translator lifts the program to VEX-IR. 

Command line arguments:
        -h, --help     print help text
        -b <filename>  y86 binary file to translate/lift 
        -w <filename>  write translated binary to <filename>
        -i             lift to VEX-IR (using PyVEX)

To lift y86 to VEX-IR and integrate with PyVEX, install with pip:
    pip install pyvex 


~~~~~~~~
OVERVIEW
~~~~~~~~
(I) Motivation
(II) Methodology
(III) Implementation
(IV) Future Work
(V) References

~~~~~~~~~~~~~~
(I) Motivation
~~~~~~~~~~~~~~
y2x86translate exists as part of RATS (a Reversing Analysis Tool Suite). This 
tool helps lift y86 binary code to an intermediate representation (IR). At the 
time of writing, RATS supports higher-level analyses (like taint analysis and 
forward symbolic execution) using the VEX-IR. VEX is the intermediate language 
used by Valgrind, a dynamic binary instrumentation tool [1]. Angr, a binary 
analysis framework, also uses VEX-IR for performing analyses on binary code [2].
An overview of VEX-IR is found here: https://docs.angr.io/docs/ir.html 
A more detailed specification of VEX-IR is found here: 
https://github.com/angr/vex/blob/master/pub/libvex_ir.h

Libraries already exist that lift x86 (among other architectures such as ARM, 
PowerPC, and MIPS) to VEX-IR. For the sake of time and reduced complexity, 
the process of lifting y86 binary code to VEX-IR leverages the existing libvex 
library that is part of Valgrind and used in Angr. 

~~~~~~~~~~~~~~~~
(II) Methodology
~~~~~~~~~~~~~~~~
y2x86translate leverages the fact that y86 is a simplified subset of the x86 
instruction set architecture. So to lift y86 code to VEX-IR, this tool first 
translates y86 opcodes to x86 opcodes. 

First, y2x86translate references a mapping from each y86 opcode to the 
semantically equivalent x86 opcode. This mapping exists in a separate file in
this repository; please see: "y86-to-x86-opcode-translations.txt" 
References to the Intel IA-32 Architecture manual [4] and x86asm.net [5] ensure 
that the chosen x86 opcode matches the semantics of the original y86 opcode. 
Some differences between y86 and x86 revolve around jump destinations. y86 uses
direct addressing for jump destinations. x86 uses signed offsets for most jump 
instructions---although there are both offset and direct addressing opcodes for 
unconditional jumps in x86. The implementation (Section III) handles these 
differences. 

Additionally, y2x86translate supports "extended" y86 ISA with limited system 
calls. To support the emulator component of the RATS toolchain (developed by 
Jacob Saunders) which allows basic system calls in y86 such as print, and file 
input and output, y2x86translate reflexively maps the "int 0x80" instruction 
(opcode CD80). 

~~~~~~~~~~~~~~~~~~~~
(III) Implementation
~~~~~~~~~~~~~~~~~~~~
Implemented in Python, y2x86translate takes as argument a y86 binary file. 
Optionally, the tool can also write the translated x86 opcodes to a binary file. 

Once y2x86translate loads a y86 binary file, it performs binary translation by 
making two passes over the y86 opcodes. The first pass translates opcodes for 
all y86 instructions based on the first two hexadecimal digits of the opcode 
and sets placeholders for the x86 jump destinations. The second pass resolves 
the jump destinations for the x86 opcodes. The tool does this by calculating 
the offset from the x86 destination location to the end of the jump opcode. 
Then, the pass computes the 2's complement value of the offset, flips the bytes
to little endian format and replaces the placeholder value with the offset.  

With a string of translated x86 opcodes, y2x86translate can now lift the 
opcodes to VEX-IR. The tool leverages the PyVEX library---found as part of the 
Angr framework [2]. PyVEX lifts x86 binary code to VEX-IR and also provides a 
programmatic interface to the intermediate representation [3]. This eases the 
development of binary analysis tools by parsing the IR and providing a developer 
methods to iterate over instructions and filter for certain types of 
instructions (such as jumps or data movement instructions, for instance). An 
overview of PyVEX is found here: https://github.com/angr/pyvex 

In the test-binaries folder of this repository are three y86 binary files based 
off of examples from Jacob Saunders' y86-emulator implementation. For each 
binary file (.yo file extension) is a corresponding .txt file that provides the 
y86 mnemonics, y86 opcodes, and x86 opcodes for verification. 

~~~~~~~~~~~~~~~~
(IV) Future Work
~~~~~~~~~~~~~~~~
A direction for future work is to directly incorporate y86 into the PyVEX 
library. This will take more effort, but the process of lifting y86 to VEX-IR 
will then be independent of any changes to the x86 instruction set architecture 
that may break the mappings in y2x86translate. 

Additionally, the binary translator can be used for lifting y86 to other IR's 
that support x86. This is useful if RATS supports other IR's in the future.

~~~~~~~~~~~~~~
(V) References
~~~~~~~~~~~~~~
[1] Nethercote, N., & Seward, J. (2007). Valgrind: a framework for heavyweight 
    dynamic binary instrumentation. In ACM Sigplan notices (Vol. 42, No. 6, 
    pp. 89-100). ACM. 

[2] Shoshitaishvili, Y., Wang, R., Salls, C., Stephens, N., Polino, M., Dutcher, 
    A., Grosen, J., Feng, S., Hauser, C., Kruegel, C. and Vigna, G. (2016). 
    SOK:(State of) The Art of War: Offensive Techniques in Binary Analysis. In 
    Security and Privacy (SP), 2016 IEEE Symposium on (pp. 138-157). IEEE.

[3] Shoshitaishvili, Y., Wang, R., Hauser, C., Kruegel, C., & Vigna, G. (2015).
    Firmalice-Automatic Detection of Authentication Bypass Vulnerabilities in 
    Binary Firmware. In NDSS.

[4] Intel. (2016). Intel 64 and IA-32 Architectures Software Developer’s Manual. 
    Vol: 2B, Instruction Set Reference: M-U. 
    
[5] x86asm.net (2017). X86 Opcode and Instruction Reference. 
    URL: http://ref.x86asm.net/

