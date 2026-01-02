#!/usr/bin/env bash
export SSH_PORT=2226
echo EMAIL: llm@lmm.lmm
echo PASSWORD: LLM2LLM2LLM
chmod 0600 ./cloud-init-key
scp -r -P $SSH_PORT -i ./cloud-init-key -o StrictHostKeyChecking=no ./compose/* ubuntu@localhost:/workspace

