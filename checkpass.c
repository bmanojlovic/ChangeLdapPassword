#include <stdio.h>
#include "lpass.h"

int
main (int argc, char *argv[])
{
  int r;
  if (argc < 3)
    {
      printf ("Usage: %s <username> <password>\n", argv[0]);
      exit (-1);
    }
  r = check_ldap_user (argv[1], argv[2]);
  if (r != 0)
    {
      printf ("Wrong password\n");
      return r;
    }
  else
    {
      printf ("Password ok\n");
      return r;
    }
}
