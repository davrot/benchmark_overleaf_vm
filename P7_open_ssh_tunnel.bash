#!/usr/bin/env bash
export SSH_PORT=2226
echo local http port: 8881
echo EMAIL: llm@lmm.lmm
echo PASSWORD: LLM2LLM2LLM

ssh -p $SSH_PORT -i ./cloud-init-key -o StrictHostKeyChecking=no -L 8881:overleaf.local:443 ubuntu@localhost
