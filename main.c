#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha.h"

void _print_hex_buffer(uint8_t const *buf, size_t len)
{
	size_t i;

	for (i = 0; buf && i < len; i++)
		printf("%02x", buf[i]);
}

int main(int ac, char **av)
{
  uint8_t *test_ptr;

  if (ac < 2)
  {
      fprintf(stderr, "Usage: %s arg\n", av[0]);
      return (EXIT_FAILURE);
  }

  /* Test `sha256()` */
  test_ptr = sha_hash_gen(SHA1, av[1]);
  if (!test_ptr)
  {
      fprintf(stderr, "sha256() failed\n");
      return (EXIT_FAILURE);
  }


  printf("\"%s\" hash is: ", av[1]);
  _print_hex_buffer(test_ptr, SHA1_DL);
  printf("\n");

  return (EXIT_SUCCESS);
}
