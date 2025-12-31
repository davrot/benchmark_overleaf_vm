#!/usr/bin/env bash
export SSH_PORT=2223
echo local http port: 8880 
ssh -p $SSH_PORT -i ./cloud-init-key -o StrictHostKeyChecking=no -L 8880:127.0.0.1:80 ubuntu@localhost
