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
r nr             resets to stored checkpoint

i sym                    print symbol information
i sec                    print section information
i bps                    print breakpoint info
i regs                   print register states
vmmap                    print vmmap

ds (sym|0xADDR|reg) [n]    disassemble symbol sym (n bytes)

xw 0xADDR [n]              inspect n words from address  (n bytes)
x (0xADDR|sym|reg) [n]     inspect n words from address  (n bytes)
xl (0xADDR|sym|reg) [n]    inspect n long from address   (n bytes)

log            creates a log of current debugger state
```


