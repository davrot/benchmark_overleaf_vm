docker compose down

echo "Check and stop other stray container"
docker stop gitbackup
docker stop oidc
docker stop saml
docker stop ldap
docker stop aiecho


