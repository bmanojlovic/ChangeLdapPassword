#include <stdio.h>
#include "lpass.h"

int
main (int argc, char *argv[])
{
  int r;
  if (argc < 4)
    {
      printf ("Usage: %s <username> <oldpassword> <newpassword>\n", argv[0]);
      exit (-1);
    }
  r = check_ldap_user (argv[1], argv[2]);
  if (r != 0)
    {
      printf ("Password NOT changed wrong old password\n");
      return r;
    }
  r = update_ldap_password (argv[1], argv[3]);
  if (r != 0)
    {
      printf ("something went wrong !!!\n");
      return r;
    }
  else
    {
      printf ("password changed :)\n");
      return r;
    }
}
