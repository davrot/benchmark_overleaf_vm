#!/usr/bin/env bash
set -e

chmod 0600 ./cloud-init-key

TARGET_VM="overleaf-production_build"
SSH_PORT="2226" # Use a different port than your other VMs

echo "🚀 Running build commands inside $TARGET_VM..."

# 4. Execute the build commands via SSH
ssh -p $SSH_PORT -i ./cloud-init-key -o StrictHostKeyChecking=no ubuntu@localhost << EOF
  cd /workspace/main/server-ce/
  make build-base 
  make build-community
  docker pull redis:8.4-alpine
  docker pull mongo:8.0
  docker pull nginx:stable-alpine
EOF

echo "Copy compose files into container"
scp -r -P $SSH_PORT -i ./cloud-init-key -o StrictHostKeyChecking=no compose/production ubuntu@localhost:/workspace

echo "Configure the firewall (we need it for the micro-service docker communication) "
ssh -p $SSH_PORT -i ./cloud-init-key -o StrictHostKeyChecking=no ubuntu@localhost "sudo ufw allow $SSH_PORT"
ssh -p $SSH_PORT -i ./cloud-init-key -o StrictHostKeyChecking=no ubuntu@localhost "sudo ufw allow 22"
ssh -p $SSH_PORT -i ./cloud-init-key -o StrictHostKeyChecking=no ubuntu@localhost "sudo ufw enable --force"

echo "Create self signed SSL certs"
ssh -p $SSH_PORT -i ./cloud-init-key -o StrictHostKeyChecking=no ubuntu@localhost << EOF
  mkdir -p /workspace/production/nginx
  cd /workspace/production/nginx
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout key.pem \
    -out ca.pem \
    -subj "/CN=overleaf.local" \
    -addext "subjectAltName = DNS:overleaf.local"
EOF

ssh -p $SSH_PORT -i ./cloud-init-key -o StrictHostKeyChecking=no ubuntu@localhost << EOF
  cd /workspace/production
  chmod +x *.sh
  echo "Prepare the docker network"
  sudo ./make_network.sh
  echo "Configure the /etc/hosts correctly for overleaf.local"
  sudo ./configure_etc_hosts.sh
  echo "Prepare the mailsink"
  mkdir -p /workspace/production/mailsink
  cat /workspace/production/nginx/ca.pem /workspace/production/nginx/key.pem > /workspace/production/mailsink/postfix_cert.pem
EOF


ssh -p $SSH_PORT -i ./cloud-init-key -o StrictHostKeyChecking=no ubuntu@localhost << EOF
  sudo apt update && sudo apt install qemu-guest-agent -y
  sudo systemctl enable --now qemu-guest-agent
EOF

echo "✅ Build complete on $TARGET_VM"
