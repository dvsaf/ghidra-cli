# ghidra-cli
Extensions for Ghidra SRE framework to support Common Language Infrastructure (CLI)

This repository contains a modified version of Ghidra's Base package and a PeCoffCli project, which adds support for Portable Executable files containing CIL code.

## Base package
Base package modified to fix this bug: https://github.com/NationalSecurityAgency/ghidra/issues/423

# PeCoffCli
Project contains a SLEIGH module for CIL. This module is based on x86 module with additional processor flag `cliMode` for areas of CIL code. Areas without `cilMode` flag are disassembled as x86 code. So mixed mode PE files supported.
For now CIL dissassembler is very simple. There is no semantic information for decompilation support. There is no even translation of metadata tokens to class/method/field/etc name.
