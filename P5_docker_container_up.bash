#!/usr/bin/env bash
export SSH_PORT=2226
ssh -p $SSH_PORT -i ./cloud-init-key -o StrictHostKeyChecking=no ubuntu@localhost << EOF
  cd /workspace/production
  ./up.sh
  docker ps
EOF
