#!/bin/sh -e
export PI_CODING_AGENT_DIR=/tmp/.pi/agent
cp /home/scan/env/models.json /tmp/.pi/agent/models.json

DEEPSEC_AGENT_DEBUG=1 npm_config_offline=true npx deepsec scan --project-id $PROJECT_ID