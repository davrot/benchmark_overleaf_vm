cd /workspace/
rm -rf /workspace/freshcode
git clone https://github.com/davrot/benchmark_overleaf.git freshcode
cd /workspace/feature_references/server-ce
make build-base
make build-community

cd /workspace/production/
sh down.sh

cp /workspace/production/compose.yaml_base /workspace/production/compose.yaml
cp /workspace/production/overleafserver/compose.yaml_base /workspace/production/overleafserver/compose.yaml

sh up.sh


