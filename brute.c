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

//int lalpha_crack(char *pass, int len);
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

  /* Set up buffers and do IO stuff */

  size_t ct_size = 1024;
  FILE *ct_fp = NULL;
  char *ct_str = NULL;
  int opt;

  while ((opt = getopt(argc, argv, ":c:f:s:")) != -1) {
    switch(opt) {
      case 's':
        if (sscanf(optarg, "%" _SIZETF, &ct_size) == 0) {
          printf("Please provide a valid ciphertext size!\n");
          return 1;
        } else if (ct_size == SIZE_MAX) {
          printf("Ciphertext too large!\n");
          return 1;
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
        return 1;
        break;

      case '?':
        printf("Use -c to supply a base64 ciphertext or -f to specify a file"
            " containing a base64 ciphertext, and use -s to specify the size of"
            " the ciphertext (default 1MB). The first string is read and"
            " leading and trailing whitespace are stripped.\n");
        break;
    }
  }

  printf("Options parsed\n");

  int bufdone = 0;

  char *ct = malloc((ct_size + 1) * sizeof(char));
  ct[ct_size] = '0';
  char *pt = malloc((ct_size + 1) * sizeof(char));
  pt[ct_size] = '0';
  char *ct_fstr = malloc((ct_size + 1) * sizeof(char));
  sprintf(ct_fstr, " %" _SIZETF "%%s", ct_size);

  if (ct_fp != NULL && ct_str != NULL) {
    printf("Please supply only one ciphertext!");
  } else if (ct_fp != NULL) {
    if (fscanf(ct_fp, ct_fstr, ct) == 0) {
      printf("Failed to read ciphertext from file! Error code %d.\n",
          ferror(ct_fp));
      printf("fscanf: %s\n", ct);
      fgets(ct, ct_size, ct_fp);
      printf("fgets: %s\n", ct);
    } else {
      bufdone = 1;
    }
  } else if (ct_str != NULL) {
    if (sscanf(ct_str, ct_fstr, ct) == 0) {
      printf("Failed to read ciphertext argument!\n");
    } else {
      bufdone = 1;
    }
  } else {
    printf("No ciphertext to decrypt!\n");
  }

  free(ct_fstr);
  if (!bufdone) {
    cleanup(ct, pt);
    return 1;
  }

  printf("Buffer setup done\n");

  /* ... Do some crypto stuff here ... */

  char pass[] = {'a', 'a', 'a', 'a', 'a'};
  //lalpha_crack(pass, 5);

  
  cleanup(ct, pt);
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

  free(ct);
  free(pt);
}


