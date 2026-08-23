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
export REPO_DIR=/etc

export NPM_CONFIG_PREFIX=/work/npm
npm config set cache /home/scan/.npm --global
export REPO_DIR=/etc






    1  export NPM_CONFIG_PREFIX=/work/npm
    2  export HOME=/work/npm
    3  mkdir -p /work/npm/cache
    4  npm config set cache /work/npm/cache --globa
    5  npm config set cache /work/npm/cache --global
    6  cd 
    7  ls -altr
    8  cd /home/scan
    9  bash deepsec-setup.sh 
   10  cd /work
   11  ls -altr
   12  export REPO_DIR=/etc
   13  bash deepsec-setup.sh 
   14  cd /home/scan
   15  bash deepsec-setup.sh 
   16  history
   17  cd /work
   18  ls -latr
   19  cat /work/data/0/setup/setup-20260823093256-117.jsonl
   20  cd /home/scan
   21  ls
   22  cat deepsec-setup.sh 
   23  ls -altr
   24  history

 