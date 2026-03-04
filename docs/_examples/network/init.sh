#!/usr/bin/env sh

HOSTS="magpie1 magpie2 magpie3"

for magpie in $HOSTS; do
    cookiejar=/tmp/"${magpie}".cookiejar
    curl \
        --cookie-jar "${cookiejar}" \
        -X POST "http://host.docker.internal/${magpie}/signin" \
        -H "Content-Type: application/json" \
        -d '{"user_name": "'${MAGPIE_ADMIN_USER}'", "password": "'${MAGPIE_ADMIN_PASSWORD}'"}'
    for user in test1 test2 test3; do
        curl \
            --cookie "${cookiejar}" \
            -X POST "http://host.docker.internal/${magpie}/users" \
            -d user_name="${user}" \
            -d email="${user}@example.com" \
            -d password='qwertyqwerty!' \
            -d group_name="users"
    done
    for other in $HOSTS; do
        [ "$magpie" = "$other" ] && continue
        curl \
            --cookie "${cookiejar}" \
            -X POST "http://host.docker.internal/${magpie}/network/nodes" \
            -d base_url="http://host.docker.internal/${other}/" \
            -d name="${other}" \
            -d jwks_url="http://host.docker.internal/${other}/network/jwks" \
            -d token_url="http://host.docker.internal/${other}/network/token" \
            -d authorization_url="http://host.docker.internal/${other}/ui/network/authorize" \
            -d redirect_uris="[\"http://host.docker.internal/${other}/network/link\"]"
    done
done
