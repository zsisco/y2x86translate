# y2x86translate.py
# y86 to x86 opcode translator
# Author: Zach Sisco

import archinfo
import binascii
import getopt
import pyvex
import sys

def flipBytes(a):
    b = ''
    for i in range(len(a) - 2, -2, -2):
        b += a[i:i + 2]
    
    return b

def modRM(preamble, reg1, reg2):
    breg1 = '{0:03b}'.format(int(reg1))
    breg2 = '{0:03b}'.format(int(reg2))
    return '%02X' % int(preamble + breg1 + breg2, 2)

def translate(y86ops):
    # Translated x86 opcodes
    x86ops = ''
    # Map y86 instruction location to new x86 instruction location
    ytox = {}
    # Map x86 jump destination location to y86 destination value
    jumpMarker = {}

    i = 0
    while i < len(y86ops):
        ytox[i] = len(x86ops)
        op = y86ops[i:i+2]

        if   op == '00':   # halt
            x86ops += 'f4'
            i += 2
        elif op == '10':   # nop
            x86ops += '90'
            i += 2
        elif op == '20':   # rrmovl
            x86ops += '89' + modRM('11', y86ops[i + 2], y86ops[i + 3])
            i += 4
        elif op == '21':   # cmovle
            x86ops += '0f4e' + modRM('11', y86ops[i + 2], y86ops[i + 3])
            i += 4
        elif op == '22':   # cmovl
            x86ops += '0f4c' + modRM('11', y86ops[i + 2], y86ops[i + 3])
            i += 4
        elif op == '23':   # cmove
            x86ops += '0f44' + modRM('11', y86ops[i + 2], y86ops[i + 3])
            i += 4
        elif op == '24':   # cmovne
            x86ops += '0f45' + modRM('11', y86ops[i + 2], y86ops[i + 3])
            i += 4
        elif op == '25':   # cmovge
            x86ops += '0f4d' + modRM('11', y86ops[i + 2], y86ops[i + 3])
            i += 4
        elif op == '26':   # cmovg
            x86ops += '0f4f' + modRM('11', y86ops[i + 2], y86ops[i + 3])
            i += 4
        elif op == '30':   # irmovl
            hreg = '%01X' % (int(y86ops[i + 3]) + 8)
            x86ops += 'b' + hreg + y86ops[i + 4 : i + 12]
            i += 12
        elif op == '40':   # rmmovl
            x86ops += '89' + modRM('10', y86ops[i + 2], y86ops[i + 3]) + y86ops[i + 4 : i + 12]
            i += 12
        elif op == '50':   # mrmovl
            x86ops += '8b' + modRM('10', y86ops[i + 2], y86ops[i + 3]) + y86ops[i + 4 : i + 12]
            i += 8
        elif op == '60':   # addl
            x86ops += '01' + modRM('11', y86ops[i + 2], y86ops[i + 3])
            i += 4
        elif op == '61':   # subl
            x86ops += '29' + modRM('11', y86ops[i + 2], y86ops[i + 3])
            i += 4
        elif op == '62':   # andl
            x86ops += '21' + modRM('11', y86ops[i + 2], y86ops[i + 3])
            i += 4
        elif op == '63':   # xorl
            x86ops += '31' + modRM('11', y86ops[i + 2], y86ops[i + 3])
            i += 4
        elif op[0] in ('7', '8'):
            prefix = ''
            if   op == '70':   # jmp 
                prefix = 'e9'
            elif op == '71':   # jle 
                prefix = '0f8e' 
            elif op == '72':   # jl 
                prefix = '0f8c'
            elif op == '73':   # je 
                prefix = '0f84'
            elif op == '74':   # jne 
                prefix = '0f85' 
            elif op == '75':   # jge 
                prefix = '0f8d' 
            elif op == '76':   # jg 
                prefix = '0f8f' 
            elif op == '80':   # call 
                prefix = 'e8'

            dest = y86ops[i + 2 : i + 10]
            jumpMarker[len(x86ops) + len(prefix)] = int(flipBytes(dest), 16) * 2
            x86ops += prefix + dest
            i += 10
        elif op == '90':   # ret
            x86ops += 'c3'
            i += 2
        elif op.lower() == 'a0':   # pushl
            x86ops += '5' + y86ops[i + 2]
            i += 4
        elif op.lower() == 'b0':   # popl
            hreg = '%01X' % (int(y86ops[i + 2]) + 8)
            x86ops += '5' + hreg
            i += 4
        elif op.lower() == 'cd':   # int (syscall)
            x86ops += op + y86ops[i + 2 : i + 4]
            i += 4

    # resolve jump destinations
    for jmp, dest in jumpMarker.iteritems(): 
        if dest in ytox:
            # calculate offset
            offset = (ytox[dest] - (jmp + 8)) / 2
            # compute 2's complement of offset
            offset = (offset + (1 << 32)) % (1 << 32)
            # covert jump location to hex and flip the bytes
            xDest = flipBytes('%08X' % offset)
            # replace placeholder jump destination
            x86ops = x86ops[0:jmp] + xDest + x86ops[jmp + 8:]

    return x86ops

def helpText():
    print '--------------'
    print 'y2x86translate'
    print '--------------\n'
    print 'Command line arguments:'
    print '-h, --help    \n\t print help text'
    print '-b <filename> \n\t y86 binary file to translate/lift [REQUIRED]'
    print '-w <filename> \n\t write translated binary to <filename>'
    print '-i            \n\t lift to VEX-IR\n'

def main(argv):
    # Command-line getopt boilerplate code from Python 2 documentation
    # https://docs.python.org/2/library/getopt.html 
    try:
        opts, args = getopt.getopt(argv, 'hb:w:i', ['help'])
    except getopt.GetoptError as err:
        helpText()
        sys.exit(2)

    binName = ''
    writeName = ''
    lift = False
    for o, a in opts:
        if o in ('-h', '--help'):
            helpText()
            sys.exit()
        elif o == '-b':
            binName = a
        elif o == '-w':
            writeName = a
        elif o == '-i':
            lift = True
        else:
            assert False, 'Usage error! Unrecognized option!'

    # dump binary file data
    if binName != '':
        with open(binName, mode='rb') as binFile:
            binData = binascii.hexlify(binFile.read())
    else:
        print 'Usage error! Please provide a y86 binary file.\n'
        helpText()
        sys.exit(2)

    # translate
    x86ops = translate(binData)

    # lift and print to VEX-IR
    if lift:
        ir = pyvex.IRSB(x86ops, 0, archinfo.ArchX86())
        ir.pp()
    else:
        print x86ops

    # write to file
    if writeName != '':
        with open(writeName, 'wb') as wb:
            wb.write(binascii.unhexlify(x86ops))


if __name__ == "__main__":
    main(sys.argv[1:])
