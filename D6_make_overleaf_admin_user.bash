#!/usr/bin/env bash
export SSH_PORT=2223
ssh -p $SSH_PORT -i ./cloud-init-key -o StrictHostKeyChecking=no ubuntu@localhost << "EOF"

# Use 'cat' with redirection '>' to create the file
cat << 'EOF2' > ./make_overleaf_admin.bash
#!/bin/bash

URL="http://127.0.0.1:80/launchpad"
EMAIL="llm@lmm.lmm"
PASSWORD="LLM2LLM2LLM"
COOKIE_FILE="cookies.txt"

# 1. Get Token and Cookie
# Added -L to follow redirects just in case
CSRF_TOKEN=$(curl -s -L -c $COOKIE_FILE $URL | \
    grep -oP 'meta name="ol-csrfToken" content="\K[^"]+')

echo "Found CSRF: $CSRF_TOKEN"

# 2. Post with Referer Header and see the error body
echo "Registering..."
RESPONSE=$(curl -X POST "$URL/register_admin" \
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
