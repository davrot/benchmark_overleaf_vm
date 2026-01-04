BRANCH="feature-template-gallery"
rm -rf /workspace/${BRANCH}

cp /workspace/production/nginx/nginx.conf_main /workspace/production/nginx/nginx.conf
cp /workspace/production/compose.yaml_main /workspace/production/compose.yaml
cp /workspace/production/overleafserver/compose.yaml_main /workspace/production/overleafserver/compose.yaml

