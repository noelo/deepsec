#!/bin/sh -e


mkdir -p /tmp/.pi/agent
export PI_CODING_AGENT_DIR=/tmp/.pi/agent
cp /home/scan/env/models.json /tmp/.pi/agent/models.json

export NPM_CONFIG_PREFIX=/work/npm
mkdir -p /work/npm/npm
npm config set cache /work/npm/npm --global
cp -R -p /home/scan/.npm/* /work/npm/npm


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

npm_config_offline=true npx deepsec init --headless --no-tui --force --id $PROJECT_ID --model $MODEL_NAME --model-auth custom --ai-provider vllm  --ai-api-key-env LLMAPIKEY --ai-base-url $MODEL_BASE_URL  --ai-credential-header Authorization:bearer --agent pi  --package-manager npm $WORK_DIR $REPO_DIR