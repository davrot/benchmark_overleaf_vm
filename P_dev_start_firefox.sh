#!/usr/bin/env bash
export SSH_PORT=2226
echo EMAIL: llm@lmm.lmm
echo PASSWORD: LLM2LLM2LLM
chmod 0600 ./cloud-init-key
ssh -p $SSH_PORT -Y -i ./cloud-init-key -o StrictHostKeyChecking=no ubuntu@localhost "firefox"

