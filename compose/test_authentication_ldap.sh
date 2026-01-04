# Tests
ldapsearch -x -H ldap://localhost:389 \
   -D "cn=admin,dc=example,dc=com" \
   -w admin_password \
   -b "dc=example,dc=com" \
   -s base

ldapsearch -x -H ldap://localhost:389 \
   -D "cn=ldap_reader,dc=example,dc=com" \
   -w GoodNewsEveryone \
   -b "ou=people,dc=example,dc=com" \
   "(uid=jdoe)"