docker compose down

rm -rf /workspace/production/overleafmongo/data_configdb
rm -rf /workspace/production/overleafmongo/data_db
rm -rf /workspace/production/overleafredis/data


cd /workspace/production
sudo ./make_network.sh

sudo sysctl vm.overcommit_memory=1
docker compose up -d

echo "Don't forget to create the admin user again!"