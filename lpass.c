#include <stdio.h>
#include <ldap.h>
#include <lber.h>
#define _XOPEN_SOURCE
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include "lpass.h"
#include <string.h>
#include <stdlib.h>
#include <crypt.h>

#define LDAP_SERVER "127.0.0.1"
#define LDAP_PORT 389
#define ROOTDN "cn=manager,o=VeratNET"
#define ROOTPW "evetidjoka"
#define BASEDN "o=VeratNET"
#define DELIM "}"


static char *lpass_attrs[] = {
  "uid",
  "userPassword",
  "uidNumber",
  "loginShell",
  NULL
};



int
dbg (char *msg)
{
#ifdef DEBUG
  printf ("%s\n", msg);
  return 0;
#endif
  return 0;
}


// UPDATE_LDAP_PASSWORD

int
update_ldap_password (char *luzer1, char *passwd)
{
  LDAPMod **lm = NULL;
  LDAP *ld = NULL;
  int ret;
  char *dn;
  char *pwd;
  char *luzer;
  char *crypted;

  dn = (char *) malloc (200);
  memset (dn, 0, 200);
  luzer = (char *) malloc (12);
  memset (luzer, 0, 12);
  snprintf (luzer, 12, "%s", luzer1);

  sprintf (dn, "uid=%s,Ou=People,%s", luzer, BASEDN);

  if (ld == NULL)
    {
      ld = ldap_init (LDAP_SERVER, LDAP_PORT);
      if (ld == NULL)
	{
	  dbg ("prso ldap_init()\n");
	  return LDAP_PASS_LDAP_CONNECT_ERR;
	}
      ret = ldap_simple_bind_s (ld, ROOTDN, ROOTPW);
      if (ret != LDAP_SUCCESS)
	{
	  dbg ("prso ldap_simple_bind_s()\n");
	  return LDAP_PASS_LDAP_CONNECT_ERR;
	}
    }

  lm = (LDAPMod **) malloc (sizeof (LDAPMod *) * 1);
  if (lm == NULL)
    {
      dbg ("cene da vapli\n");
      return LDAP_PASS_LDAP_CONNECT_ERR;
    }
  lm[0] = (LDAPMod *) malloc (sizeof (LDAPMod));
  memset ((LDAPMod *) lm[0], 0, sizeof (LDAPMod));
  lm[0]->mod_op = LDAP_MOD_REPLACE;
  lm[0]->mod_values = (char **) malloc (sizeof (char *) * 2);
  lm[0]->mod_values[1] = NULL;
  lm[0]->mod_type = strdup ("UserPassword");
  lm[1] = NULL;

  pwd = (char *) malloc (40);
  memset (pwd, 0, 40);
  crypted = crypt (passwd, crypt_make_salt ());
  sprintf (pwd, "{MD5}%s", crypted);

  lm[0]->mod_values[0] = strdup (pwd);
  ret = ldap_modify_s (ld, dn, lm);
  if (ret != LDAP_SUCCESS)
    {
      ldap_perror (ld, "prslo...");
      return LDAP_PASS_LDAP_CONNECT_ERR;
    }
// sve je ok vrati 0;
  return 0;
}



// UPDATE_LDAP_PASSWORD END !!!!!!!!!1



// REMOVE_CRYPT_TAG
char *
remove_crypt_tag (char *passwd)
{
  char *ccc;
  if (passwd == NULL)
    return NULL;
  ccc = (char *) strdup (passwd);
  strtok (ccc, DELIM);
  strcpy (ccc, (char *) strtok (NULL, DELIM));
  return ccc;
}

// REMOVE_CRYPT_TAG END !!!!!!!!!!!


// CRYPT_MAKE_SALT

char *
crypt_make_salt (void)
{
  struct timeval tv;
  static char result[40];

  result[0] = '\0';
  strcpy (result, "$1$");
  gettimeofday (&tv, (struct timezone *) 0);
  strcat (result, (char *) l64a (tv.tv_usec));
  strcat (result, (char *) l64a (tv.tv_sec + getpid () + clock ()));

  if (strlen (result) > 3 + 8)	/* magic+salt */
    result[11] = '\0';

  return result;
}

// CRYPT_MAKE_SALT END !!!!!!!!!!!!!!!!!!!!!!


// CHECK_LDAP_USER

int
check_ldap_user (char *username, char *password)
{
  LDAPMessage *res = NULL, *msg = NULL;
  LDAP *ld = NULL;
  char *basedn;
  char *filter;
  char **podaci;
  char *passwd;
  char *luzer;
  int ret;

  if (ld == NULL)
    {
      ld = ldap_init (LDAP_SERVER, LDAP_PORT);
      if (ld == NULL)
	{
	  dbg ("ldap_init error()\n");
	  return LDAP_PASS_LDAP_CONNECT_ERR;
	}
    }

  ret = ldap_simple_bind_s (ld, ROOTDN, ROOTPW);
  if (ret != LDAP_SUCCESS)
    {
      dbg ("ldap_simple_bind_s err...\n");
      return LDAP_PASS_LDAP_CONNECT_ERR;
    }

  basedn = (char *) malloc (100);
  memset (basedn, 0, 100);
  filter = (char *) malloc (100);
  memset (filter, 0, 100);

  luzer = (char *) malloc (13);
  memset (luzer, 0, 13);
  snprintf (luzer, 12, "%s", username);

  sprintf (basedn, "uid=%s, Ou=People, %s", luzer, BASEDN);
  sprintf (filter, "(uid=%s)", luzer);

  ret = ldap_search_s (ld, basedn, LDAP_SCOPE_SUBTREE,
		       filter, lpass_attrs, 0, &res);
  if (ret != LDAP_SUCCESS)
    {
      dbg ("Ne postoji takav user ...\n");
      return LDAP_PASS_ERROR_NO_SUCH_USER;
    }
  msg = ldap_first_entry (ld, res);
  ret = ldap_count_entries (ld, msg);
  if (ret != 1)
    {
      dbg ("more than one user !?!!??");
      exit (-1);
    }
  podaci = ldap_get_values (ld, msg, "userPassword");

  passwd = (char *) malloc ((strlen (*podaci) + 1));
  if (passwd == NULL)
    {
      dbg (" passwd je null");
      return LDAP_PASS_ATTR_NULL;
    }
  memset ((char *) passwd, 0, (strlen (*podaci) + 1));
  memcpy ((char *) passwd, (char *) (*podaci), strlen (*podaci));

  if (!strcmp
      (crypt (password, remove_crypt_tag (passwd)),
       remove_crypt_tag (passwd)))
    {
      dbg ("pass je tacan\n");
      return LDAP_PASS_OK;
    }
  else
    {
      dbg ("passovi se razlikuju\n");
      return LDAP_PASS_ERROR_PASSWORD_DIFFER;
    }
  return 0;
}
