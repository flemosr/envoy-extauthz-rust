#!/usr/bin/env sh
set -e

# generate envoy.yaml from template and env variables ##########################

envsubst '
    $SERVER_PORT
    $ADMIN_PORT
    $EXT_AUTHZ_SERVER_ADDRESS
    $EXT_AUTHZ_SERVER_PORT
    $NGINX_SERVER_ADDRESS
    $NGINX_SERVER_PORT
' < /etc/envoy/envoy.yaml.template > /etc/envoy/envoy.yaml

chmod go+r /etc/envoy/envoy.yaml

# standard entrypoint ##########################################################

loglevel="${loglevel:-}"
USERID=$(id -u)

# if the first argument look like a parameter (i.e. start with '-'), run Envoy
if [ "${1#-}" != "$1" ]; then
    set -- envoy "$@"
fi

if [ "$1" = 'envoy' ]; then
    # set the log level if the $loglevel variable is set
    if [ -n "$loglevel" ]; then
        set -- "$@" --log-level "$loglevel"
    fi
fi

if [ "$ENVOY_UID" != "0" ] && [ "$USERID" = 0 ]; then
    if [ -n "$ENVOY_UID" ]; then
        usermod -u "$ENVOY_UID" envoy
    fi
    if [ -n "$ENVOY_GID" ]; then
        groupmod -g "$ENVOY_GID" envoy
    fi
    # Ensure the envoy user is able to write to container logs
    chown envoy:envoy /dev/stdout /dev/stderr
    exec su-exec envoy "${@}"
else
    exec "${@}"
fi