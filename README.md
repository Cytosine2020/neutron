# Neutron

RISC-V Linux process level virtual machine.

Need to set environment variable `RISCV_SYSROOT` to run. i.e.:

```
RISCV_SYSROOT=/usr/opt/riscv32/ ./neutron-riscv-linux a.out
```
 
 Now supports

  - RV32IMA instruction set
  - ELF and ELF Interpreter
  - basic system call
  - gdb debugging
  