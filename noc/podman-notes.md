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
oc set volume deployment deepsec --add --type=pvc --claim-size=1Gi --claim-mode=ReadWriteOnce --claim-name=work-storage-claim --name=work-data --mount-path=/work
