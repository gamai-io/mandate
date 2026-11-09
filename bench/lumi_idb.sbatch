#!/bin/bash
# Intent Divergence Benchmark on LUMI (deterministic gate evaluation).
# Submit with the grant account, e.g.:
#   sbatch -A "$PROJECT" bench/lumi_idb.sbatch
#SBATCH --job-name=mandate-idb
#SBATCH --partition=dev-g
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --gres=gpu:1
#SBATCH --time=00:15:00
#SBATCH --output=idb-%j.out

set -euo pipefail
module load Local-LAIF lumi-aif-singularity-bindings
SIF=/appl/local/laifs/containers/lumi-multitorch-latest.sif
singularity exec "$SIF" bash -lc "
  cd $PWD &&
  python3 -m pip install -q -e . &&
  python3 -m mandate.benchmark --scenarios bench/scenarios/idb_v0.jsonl --out idb-report.json
"
