#!/usr/bin/env bash
set -e

TARGET_VM="overleaf-dev_build"
SSH_PORT="2223" # Use a different port than your other VMs

echo "🚀 Running build commands inside $TARGET_VM..."

# 4. Execute the build commands via SSH
ssh -p $SSH_PORT -i ./cloud-init-key -o StrictHostKeyChecking=no ubuntu@localhost << EOF
  cd /workspace/main/develop && ./bin/build
  docker build texlive -t texlive-full
  cd /workspace/main/services/git-bridge && docker build -t writelatex-git-bridge .
  docker pull 7.4-alpine
  docker pull mongo:8.0
EOF

echo "✅ Build complete on $TARGET_VM"
