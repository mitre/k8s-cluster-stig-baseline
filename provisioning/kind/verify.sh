#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SUITE="${1:?usage: $0 <suite>}"
INPUT_FILE="${ROOT_DIR}/kind.${SUITE}.inputs.yml"
KIND_CLUSTER_NAME="k8s-cluster-stig-${SUITE}"
KUBECONFIG_PATH="${ROOT_DIR}/.kitchen/kind/${KIND_CLUSTER_NAME}.kubeconfig"
RESULTS_DIR="${ROOT_DIR}/results"
RESULT_FILE="${RESULTS_DIR}/kind_${SUITE}.json"

[[ -f "${INPUT_FILE}" ]] || { echo "Missing suite inputs: ${INPUT_FILE}" >&2; exit 2; }
[[ -f "${KUBECONFIG_PATH}" ]] || { echo "Cluster kubeconfig not found; run kitchen create ${SUITE} first" >&2; exit 2; }

export KUBECONFIG="${KUBECONFIG_PATH}"
mkdir -p "${RESULTS_DIR}"
kubectl wait --for=condition=Ready nodes --all --timeout=2m

# --no-distinct-exit preserves skipped controls in the report while returning a
# conventional nonzero status for failed assertions, which Kitchen propagates.
bundle exec cinc-auditor exec "${ROOT_DIR}" --target k8s:// --no-distinct-exit \
  --input-file "${INPUT_FILE}" --reporter cli "json:${RESULT_FILE}"
