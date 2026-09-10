#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SUITE="${1:?usage: $0 <suite>}"
KIND_CLUSTER_NAME="k8s-cluster-stig-${SUITE}"
KIND_CONFIG_FILE="${ROOT_DIR}/provisioning/kind/cluster.yaml"
KUBECONFIG_PATH="${ROOT_DIR}/.kitchen/kind/${KIND_CLUSTER_NAME}.kubeconfig"
KIND_NODE_IMAGE="${KIND_NODE_IMAGE:-kindest/node:v1.32.2}"

require_command() {
  command -v "$1" >/dev/null || { echo "Required command not found: $1" >&2; exit 127; }
}

for command_name in kind kubectl; do require_command "${command_name}"; done
[[ -f "${KIND_CONFIG_FILE}" ]] || { echo "Kind config not found: ${KIND_CONFIG_FILE}" >&2; exit 2; }

mkdir -p "$(dirname "${KUBECONFIG_PATH}")"
if ! kind get clusters | grep -Fxq "${KIND_CLUSTER_NAME}"; then
  kind create cluster --name "${KIND_CLUSTER_NAME}" --config "${KIND_CONFIG_FILE}" --image "${KIND_NODE_IMAGE}"
fi

kind export kubeconfig --name "${KIND_CLUSTER_NAME}" --kubeconfig "${KUBECONFIG_PATH}"
export KUBECONFIG="${KUBECONFIG_PATH}"
kubectl wait --for=condition=Ready nodes --all --timeout=2m
kubectl cluster-info
