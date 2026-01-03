#!/usr/bin/env bash
export SSH_PORT=2226
echo EMAIL: llm@lmm.lmm
echo PASSWORD: LLM2LLM2LLM
chmod 0600 ./cloud-init-key
ssh -p $SSH_PORT -i ./cloud-init-key -o StrictHostKeyChecking=no ubuntu@localhost "rm -f ~/.Xauthority"
ssh -p $SSH_PORT -i ./cloud-init-key -o StrictHostKeyChecking=no ubuntu@localhost "sudo sed -i 's/#X11UseLocalhost yes/X11UseLocalhost yes/' /etc/ssh/sshd_config"
ssh -p $SSH_PORT -i ./cloud-init-key -o StrictHostKeyChecking=no ubuntu@localhost "sudo systemctl daemon-reload"
ssh -p $SSH_PORT -i ./cloud-init-key -o StrictHostKeyChecking=no ubuntu@localhost "sudo systemctl restart ssh"

ssh -p $SSH_PORT -i ./cloud-init-key -o StrictHostKeyChecking=no ubuntu@localhost << 'EOF'
# 1. Add the Mozilla PPA
sudo add-apt-repository ppa:mozillateam/ppa -y

# 2. Set the Priority (The part you asked for)
echo '
Package: *
Pin: release o=LP-PPA-mozillateam
Pin-Priority: 1001
' | sudo tee /etc/apt/preferences.d/mozilla-firefox

# 3. Ensure unattended upgrades don't switch it back
echo 'Unattended-Upgrade::Allowed-Origins:: "LP-PPA-mozillateam:noble";' | sudo tee /etc/apt/apt.conf.d/51unattended-upgrades-firefox

sudo apt update
sudo apt install -y firefox xauth
EOF


