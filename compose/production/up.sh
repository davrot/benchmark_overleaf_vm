docker compose down

cd /workspace/production
sudo ./make_network.sh

sudo sysctl vm.overcommit_memory=1
docker compose up -d
