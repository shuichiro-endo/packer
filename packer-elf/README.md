# packer elf
packer elf

## Installation
### Install dependencies
- c++ compiler (g++)
- nasm
- libc libc.so.6
- zlib 1.3.1 libz.so (compress, decompress)

### Install
1. download the latest [packer](https://github.com/shuichiro-endo/packer)
```
git clone https://github.com/shuichiro-endo/packer.git
```
2. build
```
cd packer/packer-elf
./compile.sh
```

## Usage
```
usage   : ./packer elf_file deflate_compression_level(1-9)
example : ./packer main 9
```

## License
This project is licensed under the MIT License.

See the [LICENSE](https://github.com/shuichiro-endo/packer/blob/main/LICENSE) file for details.
