#include <unistd.h>
#include <stdio.h>

int main(int argc, char** argv) {

  int opt;
  while ((opt = getopt(argc, argv, ":t:")) != -1) {
    switch(opt) {
      case 't':
        printf("OptOpt: %c\nArgument: %s\n", optopt, optarg);
        break;
      case ':':
        printf("Missing argument!\n");
        break;
      case '?':
        printf("This is a test of getopt. The only supported option is -t,"
            " which needs an argument.\n");
        break;
    }
  }

  return 0;
}
