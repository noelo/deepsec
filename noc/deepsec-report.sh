#!/bin/sh -e

if [[ -z "$PROJECT_ID" ]]; then
    echo "Must provide PROJECT_ID in environment" 1>&2
    exit 1
fi

WORK_DIR=${WORK_DIR:-"/work"}

cd "$WORK_DIR"
DEEPSEC_AGENT_DEBUG=1 npm_config_offline=true npx deepsec report --project-id $PROJECT_ID