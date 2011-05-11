#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include "lpass.h"

int
main (int argc, char *argv[])
{
  int r;
  if (getuid () != 0)
    {
      printf (" root privileges needed! You don't have what it needs\n");
      exit (-1);
    }
  if (argc < 3)
    {
      printf ("Usage: %s <username> <password>\n", argv[0]);
      exit (-1);
    }
  r = update_ldap_password (argv[1], argv[2]);
  return r;
}
