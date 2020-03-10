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

#define FULL_UCHAR 255

int buffer_setup(char *ct, char *pt, size_t *ct_size, int argc, char** argv);
int lalpha_crack(char *pass, int pos, const int len);
// int lalpha_iter_crack(char *pass, const int len);
size_t decode_b64(const char *msg, unsigned char **res, size_t len);
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

  char pass[] = "aaaaa";
  out = fopen("out.txt", "w");
  key = malloc(129 * sizeof(char));
  iv = malloc(129 * sizeof(char));
  key[129] = 0;
  iv[129] = 0;

  clock_t begin, end;
  begin = clock();
  //lalpha_crack(pass, 0, 5);
  end = clock();
  printf("Recursion took %lf seconds!\n", ((double) end - begin) / CLOCKS_PER_SEC);

  /* char test[] = "aGVsbG8gd29ybGQ=";
  unsigned char *test_ptr = NULL;
  printf("Converted %" _SIZETF " characters\n", decode_b64(test, &test_ptr,
        strlen(test)));
  printf("%s\n", test_ptr);
  free(test_ptr);
  */

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
            " the ciphertext in bytes, (default 1MB). Only the first line is "
            " read from a file.\n");
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
    ct[*ct_size] = 0;
  } else {
    cleanup(ct, pt);
  }
  return bufdone;
}

int lalpha_crack(char *pass, int pos, const int len) {
  if (len - pos == 0) { // base case
    EVP_BytesToKey(EVP_aes_128_ecb(), EVP_sha256(), NULL, 
        (unsigned char *) pass, 5, 1, (unsigned char *) key, (unsigned char *) iv);

    // fprintf(out, "%s\n", pass);
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

/**
 * Decodes a byte string from base64 format.
 *
 * @param[in] msg The base64 string to decode.
 * @param[out] res The buffer to store the decoded result in. THE CALLER IS IN
 * CHARGE OF FREEING THIS MEMORY.
 * @param[in] len The length of msg, as returned by strlen().
 * @return The length of the decoded result, as returned by strlen().
 */

size_t decode_b64(const char *msg, unsigned char **res, size_t len) {
  /* algo should work for non-8-bit chars, but just in case */
  /*if (CHAR_BIT != 8) {
    *res = NULL;
    printf("Only 8-bit characters supported!\n");
    return 0;
  }*/

  size_t dec_len = 3 * (len / 4);
  /* account for padding */
  if (msg[len - 1] == '=') {
    --dec_len;
    if (msg[len - 2] == '=') {
      --dec_len;
    } 
  }

  printf("Message: %s\n", msg);
  printf("Decode Length: %" _SIZETF "\n", dec_len);
  unsigned char *dec_buf = malloc((dec_len + 1) * sizeof(unsigned char));
  dec_buf[dec_len] = 0;

  BIO *msg_bio, *b64_bio;
  msg_bio = BIO_new_mem_buf(msg, len + 1);
  b64_bio = BIO_new(BIO_f_base64());
  msg_bio = BIO_push(b64_bio, msg_bio);
  BIO_set_flags(msg_bio, BIO_FLAGS_BASE64_NO_NL);
  size_t succ_len = BIO_read(msg_bio, dec_buf, len);
  BIO_free_all(msg_bio);

  *res = dec_buf;
  return succ_len;
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
