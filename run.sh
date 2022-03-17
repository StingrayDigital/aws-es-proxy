#!/bin/sh

set +x

echo "Starting AWS es proxy"

role=''
[[ -z "${AWS_ROLE_ARN}" ]] || role="-assume ${AWS_ROLE_ARN}" || echo "using role ${AWS_ROLE_ARN} for proxy"

set -x
aws-es-proxy -endpoint ${ENDPOINT} ${role} -listen 0.0.0.0:${PORT}