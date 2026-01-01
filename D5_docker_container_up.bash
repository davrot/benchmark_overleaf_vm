#!/usr/bin/env bash
export SSH_PORT=2223
ssh -p $SSH_PORT -i ./cloud-init-key -o StrictHostKeyChecking=no ubuntu@localhost << EOF
  cd /workspace/main/develop && ./bin/up
  docker ps
EOF
