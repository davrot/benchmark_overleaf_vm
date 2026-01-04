BRANCH="feature-authentication-ldap"
sudo apt install -y ldap-utils
docker stop ldap
sudo rm -rf /workspace/production/ldap/data
sudo rm -rf /workspace/production/ldap/config

rm -rf /workspace/${BRANCH}
git clone -b ${BRANCH} https://github.com/davrot/benchmark_overleaf.git /workspace/${BRANCH}
cd /workspace/${BRANCH}/server-ce
make build-base
make build-community

cd /workspace/production/
sh down.sh

cp /workspace/production/nginx/nginx.conf_main /workspace/production/nginx/nginx.conf
cp /workspace/production/compose.yaml_${BRANCH} /workspace/production/compose.yaml
cp /workspace/production/overleafserver/compose.yaml_${BRANCH} /workspace/production/overleafserver/compose.yaml

sh up.sh

echo "mail: john.doe@example.com"
echo "userPassword: password123"
echo ""
echo "mail: alice.smith@example.com"
echo "userPassword: alicepass"
echo ""
echo "mail: admin2@example.com"
echo "userPassword: adminpass"


