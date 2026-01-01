cd /workspace/
rm -rf /workspace/feature_references
git clone -b feature_references https://github.com/davrot/benchmark_overleaf.git feature_references
cd /workspace/feature_references/server-ce
make build-base
make build-community

cd /workspace/production/
sh down.sh

cp /workspace/production/compose.yaml_base /workspace/production/compose.yaml
cp /workspace/production/overleafserver/compose.yaml_feature_reference /workspace/production/overleafserver/compose.yaml

sh up.sh
