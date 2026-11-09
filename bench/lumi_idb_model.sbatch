#!/bin/bash
# Model-generated Intent Divergence Benchmark on LUMI.
# Start a vLLM OpenAI-compatible server first and export MODEL_URL + MODEL:
#   sbatch -A "$PROJECT" bench/lumi_idb_model.sbatch
#SBATCH --job-name=mandate-idb-model
#SBATCH --partition=dev-g
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --gres=gpu:1
#SBATCH --time=00:30:00
#SBATCH --output=idb-model-%j.out

set -euo pipefail
module load Local-LAIF lumi-aif-singularity-bindings
SIF=/appl/local/laifs/containers/lumi-multitorch-latest.sif
: "${MODEL_URL:?set MODEL_URL to the vLLM OpenAI endpoint}"
: "${MODEL:?set MODEL to the served model name}"
singularity exec "$SIF" bash -lc "
  cd $PWD &&
  python3 -m pip install -q -e . &&
  python3 -m mandate.benchmark \
    --scenarios bench/scenarios/model_prompts.jsonl \
    --model-url \"$MODEL_URL\" --model \"$MODEL\" \
    --out idb-model-report.json
"
