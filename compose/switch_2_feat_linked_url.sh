BRANCH="feature-linked-url"
rm -rf /workspace/${BRANCH}
git clone -b ${BRANCH} https://github.com/davrot/benchmark_overleaf.git /workspace/${BRANCH}
cd /workspace/${BRANCH}/server-ce
make build-base
make build-community

cd /workspace/production/
sh down.sh

cp /workspace/production/compose.yaml_main /workspace/production/compose.yaml
cp /workspace/production/overleafserver/compose.yaml_${BRANCH} /workspace/production/overleafserver/compose.yaml

sh up.sh
