#!/usr/bin/env bash
export SSH_PORT=2226
ssh -p $SSH_PORT -i ./cloud-init-key -o StrictHostKeyChecking=no ubuntu@localhost << "EOF"

# Use 'cat' with redirection '>' to create the file
cat << 'EOF2' > ./make_overleaf_admin.bash
#!/bin/bash

# 1. Update to HTTPS and your local domain
URL="https://overleaf.local/launchpad"
EMAIL="llm@lmm.lmm"
PASSWORD="LLM2LLM2LLM"
COOKIE_FILE="cookies.txt"

# 2. Get Token and Cookie 
# Added -k to ignore self-signed cert errors
# Added --resolve to map overleaf.local to 127.0.0.1 without needing /etc/hosts inside the script context
CSRF_TOKEN=$(curl -s -k -L --resolve overleaf.local:443:127.0.0.1 -c $COOKIE_FILE $URL | \
    grep -oP 'meta name="ol-csrfToken" content="\K[^"]+')

echo "Found CSRF: $CSRF_TOKEN"

# 3. Post with Referer Header
echo "Registering..."
RESPONSE=$(curl -X POST "$URL/register_admin" \
     -k \
     --resolve overleaf.local:443:127.0.0.1 \
     -b $COOKIE_FILE \
     -e "$URL" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "email=$EMAIL" \
     -d "password=$PASSWORD" \
     -d "_csrf=$CSRF_TOKEN" \
     -s)

echo "Server Response Body: $RESPONSE"
EOF2

# Run the script
bash ./make_overleaf_admin.bash
EOF
