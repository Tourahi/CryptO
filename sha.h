#ifndef _SHA_H_
#define _SHA_H_


#include <openssl/sha.h>
#include <stdint.h>

#define SHA1 0
#define SHA224 1
#define SHA256 2
#define SHA384 3
#define SHA512 4

#define SHA1_DL SHA_DIGEST_LENGTH
#define SHA224_DL SHA224_DIGEST_LENGTH
#define SHA256_DL SHA256_DIGEST_LENGTH
#define SHA384_DL SHA384_DIGEST_LENGTH
#define SHA512_DL SHA512_DIGEST_LENGTH

uint8_t *sha_hash_gen(uint8_t type, char *s);

uint8_t *sha1(int8_t const *s, size_t len, uint8_t digest[SHA1_DL]);
uint8_t *sha224(int8_t const *s, size_t len, uint8_t digest[SHA224_DL]);
uint8_t *sha256(int8_t const *s, size_t len, uint8_t digest[SHA256_DL]);
uint8_t *sha384(int8_t const *s, size_t len, uint8_t digest[SHA384_DL]);
uint8_t *sha512(int8_t const *s, size_t len, uint8_t digest[SHA512_DL]);


#endif
