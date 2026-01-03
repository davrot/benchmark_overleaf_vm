BRANCH="gitbackup"
rm -rf /workspace/${BRANCH}
git clone -b ${BRANCH} https://github.com/davrot/benchmark_overleaf.git /workspace/${BRANCH}
cd /workspace/${BRANCH}/server-ce
make build-base
make build-community
make build-gitbackup

cd /workspace/production/
sh down.sh

cp /workspace/production/nginx/nginx.conf_main /workspace/production/nginx/nginx.conf
cp /workspace/production/compose.yaml_main /workspace/production/compose.yaml
cp /workspace/production/overleafserver/compose.yaml_${BRANCH} /workspace/production/overleafserver/compose.yaml

sh up.sh
