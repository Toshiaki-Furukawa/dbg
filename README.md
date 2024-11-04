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
r 0xADDR         resets to stored checkpoint

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
log            creates a log of current debugger state
```

## TODO:
- update regs after program has exited

