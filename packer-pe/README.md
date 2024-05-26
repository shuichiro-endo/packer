# packer pe
packer pe

## Installation
### Install dependencies
- x86_64 architecture, 64bit, little endian
- visual studio community (Desktop development with C++)
    1. install Desktop development with C++
- nasm

### Install
1. download the latest [packer](https://github.com/shuichiro-endo/packer)
```
git clone https://github.com/shuichiro-endo/packer.git
```
2. run x64 Native Tools Command Prompt for VS 2022
3. build
```
cd packer\packer-pe
compile.bat
```

## Usage
```
usage   : packer.exe pe_file
example : packer.exe main.exe
```

## License
This project is licensed under the MIT License.

See the [LICENSE](https://github.com/shuichiro-endo/packer/blob/main/LICENSE) file for details.

## Reference
- [https://github.com/aaaddress1/theArk](https://github.com/aaaddress1/theArk)
- [https://github.com/hasherezade/pe_to_shellcode](https://github.com/hasherezade/pe_to_shellcode)
