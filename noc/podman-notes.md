export VERCEL_OIDC_TOKEN=123123

cat > /work/.vercel/project.json <<'EOF'
{
  "orgId": "team_dummy",
  "projectId": "prj_dummy"
}
EOF


podman run --rm -e DEEPSEC_DEBUG=1 -e LLMAPIKEY=sk-123456 -e PROJECT_ID=fulltest -e MODEL_NAME='vllm/Qwen3.6-35B-A3B' -e MODEL_BASE_URL='https://litemaas.rhoai.rh-exaper-bu.com/v1' -it   -v /home/noelo/dev/deepsec/noc/models.json:/opt/app-root/src/.pi/agent/models.json:ro,Z -v deepsec-work:/work:U -v /home/noelo/dev/visa-vulnerability-agentic-harness:/repo:ro,Z --entrypoint=/bin/bash deepsec-runner

