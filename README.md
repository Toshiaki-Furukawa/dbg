# dbg

## Installation
```
mkdir build
make
```

## usage
### run
```
./wg path/to/file
```
### commands

```
b 0xADDR         set breakpoint at 0xADDR
c                continue
s                single step
r                reset

i sym            print symbol information
i sec            print section information
i bps            print breakpoint info
i regs           print register states
vmmap            print vmmap

ds sym           disassemble symbol sym
dw 0xADDR n      disassemble n words from 0xADDR
db 0xADDR n      disassemble n bytes form 0xADDR

xw 0xADDR n    inspect n words from address
xl 0xADDR n    inspect n long from address
```

## TODO:
- update regs after program has exited

