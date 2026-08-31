#!/bin/sh -e
WORK_DIR=${WORK_DIR:-"/work"}

if [[ -z "$PROJECT_ID" ]]; then
    echo "Must provide PROJECT_ID in environment" 1>&2
    exit 1
fi

mkdir -p /tmp/.pi/agent
export PI_CODING_AGENT_DIR=/tmp/.pi/agent
cp /home/scan/env/models.json /tmp/.pi/agent/models.json

# Check if the model definitions are present otherwise exit
if [ ! -f "/tmp/.pi/agent/models.json" ]; then
  echo "ERROR - Model definitions not found at /tmp/.pi/agent/models.json"; 
  exit -1; 
fi

# Create the .vercel directory only if it does not exist
if [ ! -d "$WORK_DIR/.vercel/" ]; then
  mkdir -p "$WORK_DIR/.vercel/"
fi

# Create the project.json file only if it does not exist
if [ ! -f "$WORK_DIR/.vercel/project.json" ]; then
  cat > "$WORK_DIR/.vercel/project.json" <<'EOF'
{
  "orgId": "team_dummy",
  "projectId": "prj_dummy"
}
EOF
fi

# OpenShift needs this for some reason
cp -R /home/scan/node_modules "$WORK_DIR"

DEEPSEC_AGENT_DEBUG=1 npm_config_offline=true npx deepsec process  --project-id $PROJECT_ID --model $MODEL_NAME --ai-provider vllm  --ai-api-key-env LLMAPIKEY --ai-base-url $MODEL_BASE_URL --agent pi