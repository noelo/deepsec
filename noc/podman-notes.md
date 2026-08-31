export VERCEL_OIDC_TOKEN=123123

cat > /work/.vercel/project.json <<'EOF'
{
  "orgId": "team_dummy",
  "projectId": "prj_dummy"
}
EOF


podman run --rm -e DEEPSEC_DEBUG=1 -e LLMAPIKEY=sk-123456 -e PROJECT_ID=fulltest -e MODEL_NAME='vllm/Qwen3.6-35B-A3B' -e MODEL_BASE_URL='https://litemaas.rhoai.rh-exaper-bu.com/v1' -it   -v /home/noelo/dev/deepsec/noc/models.json:/opt/app-root/src/.pi/agent/models.json:ro,Z -v deepsec-work:/work:U -v /home/noelo/dev/visa-vulnerability-agentic-harness:/repo:ro,Z --entrypoint=/bin/bash deepsec-runner

/opt/app-root/src/.pi/agent/models.json


oc create cm model-defn --from-file=models.json
oc create secret generic llm-access --from-env-file=secrets.env.no-commit

oc create secret generic llm-access --from-env-file=openrouter.env.no-commit



oc create deployment deepsec --image=quay.io/noeloc/deepsec-runner:latest --replicas=0
oc set env --from=secret/llm-access deployment/deepsec
oc set volumes deployment deepsec --add --type configmap --mount-path /opt/app-root/src/.pi/agent/models.json --configmap-name= model-defn  --read-only
oc set volume deployment deepsec --add --type=pvc --claim-size=5Gi --claim-mode=ReadWriteOnce --claim-name=work-storage-claim --name=work-data --mount-path=/work



export HOME=/tmp/npm
1000910000@deepsec-78d9d74d48-v7hxl-debug:/home/scan$ npm config set cache /tmp/npm/t  
1000910000@deepsec-78d9d74d48-v7hxl-debug:/home/scan$ mkdir -t /tmp/npm/t

npm_config_offline=false npx deepsec init --headless --no-tui --force --id $PROJECT_ID --model $MODEL_NAME --model-auth custom --ai-provider vllm  --ai-api-key-env LLMAPIKEY --ai-base-url $MODEL_BASE_URL  --ai-credential-header Authorization:bearer --agent pi  --package-manager npm $WORK_DIR $REPO_DIR


export HOME=/work/npm

export NPM_CONFIG_PREFIX=/work/npm
mkdir -p /work/npm/npm
npm config set cache /work/npm/npm --global

export NPM_CONFIG_PREFIX=/work/npm
npm config set cache /home/scan/.npm --global





DEEPSEC_AGENT_DEBUG=1 npm_config_offline=true npx deepsec init --scaffold-only --project-id $PROJECT_ID --model $MODEL_NAME --model-auth custom --ai-provider vllm  --ai-api-key-env LLMAPIKEY --ai-base-url $MODEL_BASE_URL  --ai-credential-header Authorization:bearer --agent pi  --package-manager npm $WORK_DIR $REPO_DIR


DEEPSEC_AGENT_DEBUG=1 npm_config_offline=true npx deepsec init --force --scaffold-only --id $PROJECT_ID --model $MODEL_NAME --model-auth custom --ai-provider vllm  --ai-api-key-env LLMAPIKEY --ai-base-url $MODEL_BASE_URL  --ai-credential-header Authorization:bearer --agent pi  --package-manager npm $WORK_DIR $REPO_DIR





DEEPSEC_AGENT_DEBUG=1 npm_config_offline=true npx deepsec scan --project-id $PROJECT_ID --model $MODEL_NAME --model-auth custom --ai-provider vllm  --ai-api-key-env LLMAPIKEY --ai-base-url $MODEL_BASE_URL  --ai-credential-header Authorization:bearer --agent pi  --package-manager npm $WORK_DIR $REPO_DIR


cd /work
DEEPSEC_AGENT_DEBUG=1 npm_config_offline=true npx deepsec scan --project-id=0 


DEEPSEC_AGENT_DEBUG=1 npm_config_offline=true npx deepsec process --project-id $PROJECT_ID --model $MODEL_NAME --ai-provider vllm  --ai-api-key-env LLMAPIKEY --ai-base-url $MODEL_BASE_URL --agent pi



DEEPSEC_AGENT_DEBUG=1 npm_config_offline=true npx deepsec init --scaffold-only --id $PROJECT_ID --model $MODEL_NAME --model-auth custom --ai-provider vllm  --ai-api-key-env LLMAPIKEY --ai-base-url $MODEL_BASE_URL  --ai-credential-header Authorization:bearer --agent pi  --package-manager npm --force $WORK_DIR $REPO_DIR
34  cd /work
35  DEEPSEC_AGENT_DEBUG=1 npm_config_offline=true npm install
36  DEEPSEC_AGENT_DEBUG=1 npm_config_offline=true npx deepsec scan --project-id=0
38  DEEPSEC_AGENT_DEBUG=1 npm_config_offline=true npx deepsec process --project-id $PROJECT_ID --model $MODEL_NAME --ai-provider vllm  --ai-api-key-env LLMAPIKEY --ai-base-url $MODEL_BASE_URL --agent pi
39  DEEPSEC_AGENT_DEBUG=1 npm_config_offline=true npx deepsec process --project-id $PROJECT_ID --model $MODEL_NAME --ai-provider vllm  --ai-api-key-env LLMAPIKEY --ai-base-url $MODEL_BASE_URL --agent pi
41  DEEPSEC_AGENT_DEBUG=1 npm_config_offline=true npx deepsec report --project-id 0
42  DEEPSEC_AGENT_DEBUG=1 npm_config_offline=true npx deepsec export --project-id 0

export REPO_DIR=/work/repo/deepsec/





DEEPSEC_AGENT_DEBUG=1 npm_config_offline=true  npx deepsec init --plan --output json



