#!/bin/bash
# Start a vLLM server on LUMI, wait for it, run the model IDB, stop it.
# Submit: sbatch --export=ALL,MODEL_PATH=...,MODEL_NAME=...,OUT=... bench/lumi_idb_full.sbatch
#SBATCH --job-name=mandate-idb-full
#SBATCH --partition=dev-g
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --gres=gpu:4
#SBATCH --time=00:45:00
#SBATCH --output=idb-full-%j.out

set -euo pipefail
module load Local-LAIF lumi-aif-singularity-bindings
SIF=/appl/local/laifs/containers/lumi-multitorch-latest.sif
: "${MODEL_PATH:?set MODEL_PATH}"
: "${MODEL_NAME:?set MODEL_NAME}"
SCENARIOS="${SCENARIOS:-bench/scenarios/model_prompts.jsonl}"
OUT="${OUT:-idb-model-${MODEL_NAME}-${SLURM_JOB_ID}.json}"
cd "$SLURM_SUBMIT_DIR"
LOG="vllm_${MODEL_NAME}_${SLURM_JOB_ID}.log"

singularity exec "$SIF" python3 -m vllm.entrypoints.openai.api_server \
  --host 127.0.0.1 --port 8000 \
  --model "$MODEL_PATH" --served-model-name "$MODEL_NAME" \
  --tensor-parallel-size 4 --max-model-len 32768 \
  --enable-prefix-caching --max-num-seqs 64 >"$LOG" 2>&1 &
VPID=$!
trap 'kill "$VPID" 2>/dev/null || true' EXIT

ready=0
for i in $(seq 1 180); do
  if curl -sf http://127.0.0.1:8000/v1/models >/dev/null; then ready=1; break; fi
  if ! kill -0 "$VPID" 2>/dev/null; then
    echo VLLM_DIED
    tail -60 "$LOG"
    exit 1
  fi
  sleep 5
done
[ "$ready" = 1 ] || { echo VLLM_TIMEOUT; tail -60 "$LOG"; exit 1; }
echo VLLM_READY

SINGULARITYENV_PYTHONPATH="$PWD" singularity exec "$SIF" \
  python3 -m mandate.benchmark --scenarios "$SCENARIOS" \
  --model-url http://127.0.0.1:8000/v1 --model "$MODEL_NAME" --out "$OUT"

echo IDB_MODEL_DONE
