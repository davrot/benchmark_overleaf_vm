BRANCH="feature_admin_extensions"
rm -rf /workspace/${BRANCH}

cp /workspace/production/compose.yaml_main /workspace/production/compose.yaml
cp /workspace/production/overleafserver/compose.yaml_main /workspace/production/overleafserver/compose.yaml

