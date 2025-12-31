LINE="127.0.0.1 overleaf.local"
FILE="/etc/hosts"

if ! grep -q "overleaf.local" "$FILE"; then
  echo "Adding overleaf.local to $FILE"
  echo "$LINE" | sudo tee -a "$FILE" > /dev/null
else
  echo "overleaf.local already exists in $FILE, skipping."
fi
