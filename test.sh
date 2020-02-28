#!/bin/sh

gcc brute.c -Wall -o brute.exe -lcrypto -std=c99

echo
./brute.exe -f flag.txt.enc
echo
./brute.exe -c flag{}
echo
./brute.exe -s 2048
