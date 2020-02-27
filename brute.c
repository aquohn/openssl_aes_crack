#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <string.h>
#include <inttypes.h>
#include <limits.h>

#ifdef _WIN32
#  ifdef _WIN64
#    define _SIZETF PRIu64
#  else
#    define _SIZETF PRIu32
#  endif
#else
#  define _SIZETF "zu"
#endif

int buffer_setup(char *ct, char *pt, size_t *ct_size, int argc, char** argv);
int lalpha_crack(char *pass, const int len, int rpos);
void cleanup(char *ct, char *pt);

int main(int argc, char *argv[])
{ 
  /* Load the human readable error strings for libcrypto */
  ERR_load_crypto_strings();

  /* Load all digest and cipher algorithms */
  OpenSSL_add_all_algorithms();

  /* Load config file, and other important initialisation */
  /* OPENSSL_config(NULL); // deprecated */

  CONF_modules_load_file(NULL, NULL, CONF_MFLAGS_DEFAULT_SECTION);

  printf("Crypto setup done\n");

  char *ct = NULL;
  char *pt = NULL;
  size_t *ct_size;
  *ct_size = 1024;
  if (!buffer_setup(ct, pt, ct_size, argc, argv)) {
    cleanup(ct, pt);
    return 1;
  }
  
  printf("Buffer setup done\n");


  /* ... Do some crypto stuff here ... */

  char pass[] = {'a', 'a', 'a', 'a', 'a'};
  lalpha_crack(pass, 5, 5);


  cleanup(ct, pt);
  return 0;
}

int buffer_setup(char *ct, char *pt, size_t *ct_size, int argc, char** argv) {

  /* Set up buffers and do IO stuff */

  FILE *ct_fp = NULL;
  char *ct_str = NULL;
  int opt;

  while ((opt = getopt(argc, argv, ":c:f:s:")) != -1) {
    switch(opt) {
      case 's':
        if (sscanf(optarg, "%" _SIZETF, ct_size) == 0) {
          printf("Please provide a valid ciphertext size!\n");
          return 0;
        } else if (*ct_size == SIZE_MAX) {
          printf("Ciphertext too large!\n");
          return 0;
        }
        break;

      case 'c':
        ct_str = optarg;
        printf("Ciphertext: %s\n", optarg);
        break;

      case 'f':
        ct_fp = fopen(optarg, "r");
        printf("Filename: %s\n", optarg);
        break;

      case ':':
        printf("Argument required for -%c!\n", optopt);
        return 0;
        break;

      case '?':
        printf("Use -c to supply a base64 ciphertext or -f to specify a file"
            " containing a base64 ciphertext, and use -s to specify the size of"
            " the ciphertext (default 1MB). Only the first line is read from a"
            " file.\n");
        break;
    }
  }

  printf("Options parsed\n");

  int bufdone = 0;

  ct = malloc((*ct_size + 1) * sizeof(char));
  pt = malloc((*ct_size + 1) * sizeof(char));

  if (ct_fp != NULL && ct_str != NULL) {
    printf("Please supply only one ciphertext!");
  } else if (ct_fp != NULL) {
    if (fgets(ct, *ct_size, ct_fp) == NULL) {
      printf("Failed to read ciphertext from file! Error code %d.\n",
          ferror(ct_fp));
    } else {
      bufdone = 1;
    }
  } else if (ct_str != NULL) {
    strncpy(ct, ct_str, *ct_size);
    bufdone = 1;
  } else {
    printf("No ciphertext to decrypt!\n");
  }

  if (bufdone) {
    ct[*ct_size] = '0';
    return 1;
  } else {
    cleanup(ct, pt);
    return 0;
  }
}

int lalpha_crack(char *pass, const int len, int rpos) {
  if (rpos == 1) {
    
  }
  return 0;
}

void cleanup(char *ct, char *pt) {
  /* Clean up */

  /* Removes all digests and ciphers */
  EVP_cleanup();

  /* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
  CRYPTO_cleanup_all_ex_data();

  /* Remove error strings */
  ERR_free_strings();

  if (ct) free(ct);
  if (pt) free(pt);
}
