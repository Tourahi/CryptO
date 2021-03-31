#include "sha.h"
#include <string.h>

uint8_t *sha_hash_gen(uint8_t type, char *s)
{
  size_t len = strlen(s);
  uint8_t hash_sha1[SHA1_DL];
  uint8_t hash_sha224[SHA224_DL];
  uint8_t hash_sha256[SHA256_DL];
  uint8_t hash_sha384[SHA384_DL];
  uint8_t hash_sha512[SHA512_DL];

  switch(type)
  {
  case SHA1:
    return sha1((int8_t *)s, len, hash_sha1);
    break;
  case SHA224:
    return sha224((int8_t *)s, len, hash_sha224);
    break;
  case SHA256:
    return sha256((int8_t *)s, len, hash_sha256);
    break;
  case SHA384:
    return sha384((int8_t *)s, len, hash_sha384);
    break;
  case SHA512:
    return sha512((int8_t *)s, len, hash_sha512);
    break;
  }
  return 0;
}

uint8_t *sha1(int8_t const *s, size_t len, uint8_t digest[SHA1_DL])
{
  if (digest == NULL)
    return NULL;
  SHA_CTX c;
  if (SHA1_Init(&c))
  {
    int up = SHA1_Update(&c, s, len);
    int fnl = SHA1_Final(digest, &c);
    if (up && fnl)
      return digest;
  }
  return 0;
}

uint8_t *sha224(int8_t const *s, size_t len, uint8_t digest[SHA224_DL])
{
  if (digest == NULL)
    return NULL;
  SHA256_CTX c;
  if (SHA224_Init(&c))
  {
    int up = SHA224_Update(&c, s, len);
    int fnl = SHA224_Final(digest, &c);
    if (up && fnl)
      return digest;
  }
  return 0;
}

uint8_t *sha256(int8_t const *s, size_t len, uint8_t digest[SHA256_DL])
{
  if (digest == NULL)
    return NULL;
  SHA256_CTX c;
  if (SHA256_Init(&c))
  {
    int up = SHA256_Update(&c, s, len);
    int fnl = SHA256_Final(digest, &c);
    if (up && fnl)
      return digest;
  }
  return 0;
}

uint8_t *sha384(int8_t const *s, size_t len, uint8_t digest[SHA384_DL])
{
  if (digest == NULL)
    return NULL;
  SHA512_CTX c;
  if (SHA384_Init(&c))
  {
    int up = SHA384_Update(&c, s, len);
    int fnl = SHA384_Final(digest, &c);
    if (up && fnl)
      return digest;
  }
  return 0;
}

uint8_t *sha512(int8_t const *s, size_t len, uint8_t digest[SHA512_DL])
{
  if (digest == NULL)
    return NULL;
  SHA512_CTX c;
  if (SHA512_Init(&c))
  {
    int up = SHA512_Update(&c, s, len);
    int fnl = SHA512_Final(digest, &c);
    if (up && fnl)
      return digest;
  }
  return 0;
}
