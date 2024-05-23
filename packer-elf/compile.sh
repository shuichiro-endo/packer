#!/bin/bash

nasm -f bin stub.asm -o stub.bin -w-number-overflow
g++ packer.cpp -o packer -lz
