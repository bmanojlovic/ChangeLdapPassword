#ifndef LPASS_H
#define LPASS_H

#define LDAP_PASS_ERROR_NO_SUCH_USER 2
#define LDAP_PASS_ERROR_PASSWORD_DIFFER 3
#define LDAP_PASS_ERROR_NEW_PASS_SAME_AS_OLD 4
#define LDAP_PASS_LDAP_CONNECT_ERR 5
#define LDAP_PASS_ATTR_NULL 6
#define LDAP_PASS_OK 0

int update_ldap_password (char *luzer, char *password);
char *remove_crypt_tag(char *passwd);
char *crypt_make_salt(void);
int check_ldap_user(char *username, char *password);

#endif // LPASS_H
