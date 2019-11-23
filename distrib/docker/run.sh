#!/bin/sh

# start in right dir
cd /ircd

# make config file
if [ ! -f "/ircd/ircd.yaml" ]; then
    awk '{gsub(/path: languages/,"path: /ircd-bin/languages")}1' /ircd-bin/oragono.yaml > /tmp/ircd.yaml

    # change default oper passwd
    OPERPASS=$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c20)
    echo "Oper username:password is dan:$OPERPASS"
    ENCRYPTEDPASS=$(echo "$OPERPASS" | /ircd-bin/oragono genpasswd)
    ORIGINALPASS='\$2a\$04\$LiytCxaY0lI.guDj2pBN4eLRD5cdM2OLDwqmGAgB6M2OPirbF5Jcu'

    awk "{gsub(/password: \\\"$ORIGINALPASS\\\"/,\"password: \\\"$ENCRYPTEDPASS\\\"\")}1" /tmp/ircd.yaml > /tmp/ircd2.yaml

    unset OPERPASS
    unset ENCRYPTEDPASS
    unset ORIGINALPASS

    mv /tmp/ircd2.yaml /ircd/ircd.yaml
fi

# make self-signed certs if they don't already exist
/ircd-bin/oragono mkcerts

# run!
exec /ircd-bin/oragono run
