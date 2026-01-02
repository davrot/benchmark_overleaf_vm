BRANCH="feature_ai_assistant"
rm -rf /workspace/${BRANCH}
git clone -b ${BRANCH} https://github.com/davrot/benchmark_overleaf.git /workspace/${BRANCH}
cd /workspace/${BRANCH}/server-ce
make build-base
make build-community

cd /workspace/production/aiecho
sh build.sh

cd /workspace/production/
sh down.sh

cp /workspace/production/compose.yaml_${BRANCH} /workspace/production/compose.yaml
cp /workspace/production/overleafserver/compose.yaml_${BRANCH} /workspace/production/overleafserver/compose.yaml

sh up.sh
