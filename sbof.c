#include <stdio.h>
#include <string.h>

int main(int argc, char const *argv[])
{
  char buffer[4];
  strcpy(buffer, argv[1]);
  printf("%s\n", "I'm a good guy");
  return 0;
}
