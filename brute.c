#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <string.h>
#include <inttypes.h>
#include <limits.h>

#include <time.h>

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
int lalpha_crack(char *pass, int pos, const int len);
// int lalpha_iter_crack(char *pass, const int len);
void cleanup(char *ct, char *pt);

FILE *out = NULL;
char *key = NULL;
char *iv = NULL;

int main(int argc, char *argv[]) { 
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
  size_t _ct_size = 1024;
  size_t *ct_size = &_ct_size;
  if (!buffer_setup(ct, pt, ct_size, argc, argv)) {
    cleanup(ct, pt);
    return 1;
  }

  printf("Buffer setup done\n");

  /* ... Do some crypto stuff here ... */

  char pass[] = {'a', 'a', 'a', 'a', 'a', 0};
  out = fopen("out.txt", "w");
  key = malloc(129 * sizeof(char));
  iv = malloc(129 * sizeof(char));
  key[129] = 0;
  iv[129] = 0;

  clock_t begin, end;
  begin = clock();
  lalpha_crack(pass, 0, 5);
  end = clock();
  printf("Recursion took %lf seconds!\n", ((double) end - begin) / CLOCKS_PER_SEC);

  /* begin = clock();
     lalpha_iter_crack(pass, 5);
     end = clock();
     printf("Iteration took %lf seconds!\n", ((double) end - begin) / CLOCKS_PER_SEC);
     */

  fclose(out);
  cleanup(ct, pt);
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
      fclose(ct_fp);
      bufdone = 1;
    }
  } else if (ct_str != NULL) {
    strncpy(ct, ct_str, *ct_size);
    bufdone = 1;
  } else {
    printf("No ciphertext to decrypt!\n");
  }

  if (bufdone) {
    fclose(ct_fp);
    ct[*ct_size] = '0';
  } else {
    cleanup(ct, pt);
  }
  return bufdone;
}

int lalpha_crack(char *pass, int pos, const int len) {
  if (len - pos == 0) { // base case
    EVP_BytesToKey(EVP_aes_128_ecb(), EVP_sha256(), NULL, 
        (unsigned char *) pass, 5, 1, (unsigned char *) key, (unsigned char *) iv);
    return 0;
  } else {
    if (lalpha_crack(pass, pos + 1, len)) {
      return 1;
    } else if (pass[pos] == 'z') {
      pass[pos] = 'a';     
      return 0;
    } else {
      ++pass[pos];
      return lalpha_crack(pass, pos, len);
    }
  }
}

/* May be slightly faster but commenting out because it's ugly

   int lalpha_iter_crack(char *pass, const int len) {
   for (; pass[0] < 'z' + 1; ++pass[0]) {
   for (; pass[1] < 'z' + 1; ++pass[1]) {
   for (; pass[2] < 'z' + 1; ++pass[2]) {
   for (; pass[3] < 'z' + 1; ++pass[3]) {
   for (; pass[4] < 'z' + 1; ++pass[4]) {
   EVP_BytesToKey(EVP_aes_128_ecb(), EVP_sha256(), NULL, 
   (unsigned char *) pass, 5, 1, (unsigned char *) key, 
   (unsigned char *) iv);
   }
   pass[4] = 'a';
   }
   pass[3] = 'a';
   }
   pass[2] = 'a';
   }
   pass[1] = 'a';
   }
   return 0;
   } */

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
