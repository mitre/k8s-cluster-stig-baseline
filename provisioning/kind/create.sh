#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SUITE="${1:?usage: $0 <suite>}"
KIND_CLUSTER_NAME="k8s-cluster-stig-${SUITE}"
KUBECONFIG_PATH="${ROOT_DIR}/.kitchen/kind/${KIND_CLUSTER_NAME}.kubeconfig"
KIND_NODE_IMAGE="${KIND_NODE_IMAGE:-kindest/node:v1.32.2}"

require_command() {
  command -v "$1" >/dev/null || { echo "Required command not found: $1" >&2; exit 127; }
}

wait_for_cluster() {
  local attempt
  for attempt in $(seq 1 24); do
    if kubectl wait --for=condition=Ready nodes --all --timeout=10s; then
      return 0
    fi
    sleep 5
  done

  echo "Kind cluster did not become Ready within two minutes" >&2
  return 1
}

configure_hardened_control_plane() {
  local node_container manifest_path
  node_container="${KIND_CLUSTER_NAME}-control-plane"
  manifest_path="/etc/kubernetes/manifests/kube-apiserver.yaml"

  docker cp "${POD_SECURITY_CONFIG}" "${node_container}:/etc/kubernetes/pod-security-admission.yaml"
  docker cp "${ENCRYPTION_CONFIG}" "${node_container}:/etc/kubernetes/encryption-provider-config.yaml"

  if ! docker exec "${node_container}" grep -Fq -- '--admission-control-config-file=/etc/kubernetes/pod-security-admission.yaml' "${manifest_path}"; then
    docker exec "${node_container}" sed -i "/^    - kube-apiserver$/a\\    - --admission-control-config-file=/etc/kubernetes/pod-security-admission.yaml" "${manifest_path}"
  fi

  if ! docker exec "${node_container}" grep -Fq -- '--encryption-provider-config=/etc/kubernetes/encryption-provider-config.yaml' "${manifest_path}"; then
    docker exec "${node_container}" sed -i "/^    - kube-apiserver$/a\\    - --encryption-provider-config=/etc/kubernetes/encryption-provider-config.yaml" "${manifest_path}"
  fi

  if ! docker exec "${node_container}" grep -Fq -- 'mountPath: /etc/kubernetes/pod-security-admission.yaml' "${manifest_path}"; then
    docker exec "${node_container}" sed -i "/^    volumeMounts:/a\\    - mountPath: /etc/kubernetes/pod-security-admission.yaml\\n      name: pod-security-admission-config\\n      readOnly: true\\n    - mountPath: /etc/kubernetes/encryption-provider-config.yaml\\n      name: encryption-provider-config\\n      readOnly: true" "${manifest_path}"
  fi

  if ! docker exec "${node_container}" grep -Fq -- 'path: /etc/kubernetes/pod-security-admission.yaml' "${manifest_path}"; then
    docker exec "${node_container}" sed -i "/^  volumes:/a\\  - hostPath:\\n      path: /etc/kubernetes/pod-security-admission.yaml\\n      type: File\\n    name: pod-security-admission-config\\n  - hostPath:\\n      path: /etc/kubernetes/encryption-provider-config.yaml\\n      type: File\\n    name: encryption-provider-config" "${manifest_path}"
  fi
}

for command_name in kind kubectl; do require_command "${command_name}"; done

mkdir -p "$(dirname "${KUBECONFIG_PATH}")"
case "${SUITE}" in
  vanilla)
    KIND_CONFIG_FILE="${ROOT_DIR}/provisioning/kind/cluster.yaml"
    ;;
  hardened)
    require_command openssl
    require_command docker
    HARDENED_FILES_DIR="${ROOT_DIR}/.kitchen/kind/${KIND_CLUSTER_NAME}-files"
    POD_SECURITY_CONFIG="${HARDENED_FILES_DIR}/pod-security-admission.yaml"
    ENCRYPTION_CONFIG="${HARDENED_FILES_DIR}/encryption-provider-config.yaml"
    KIND_CONFIG_FILE="${ROOT_DIR}/provisioning/kind/cluster.yaml"
    mkdir -p "${HARDENED_FILES_DIR}"
    cp "${ROOT_DIR}/provisioning/kind/hardened/pod-security-admission.yaml" "${POD_SECURITY_CONFIG}"
    ENCRYPTION_KEY="$(openssl rand -base64 32 | tr -d '\n')"
    [[ -n "${ENCRYPTION_KEY}" ]] || { echo "Unable to generate the hardened encryption key" >&2; exit 1; }
    sed "s|__ENCRYPTION_KEY__|${ENCRYPTION_KEY}|" \
      "${ROOT_DIR}/provisioning/kind/hardened/encryption-provider-config.yaml.template" > "${ENCRYPTION_CONFIG}"
    ;;
  *)
    echo "Unknown Kind suite: ${SUITE}. Expected vanilla or hardened." >&2
    exit 2
    ;;
esac

[[ -f "${KIND_CONFIG_FILE}" ]] || { echo "Kind config not found: ${KIND_CONFIG_FILE}" >&2; exit 2; }
if ! kind get clusters | grep -Fxq "${KIND_CLUSTER_NAME}"; then
  kind create cluster --name "${KIND_CLUSTER_NAME}" --config "${KIND_CONFIG_FILE}" --image "${KIND_NODE_IMAGE}"
fi

kind export kubeconfig --name "${KIND_CLUSTER_NAME}" --kubeconfig "${KUBECONFIG_PATH}"
export KUBECONFIG="${KUBECONFIG_PATH}"
if [[ "${SUITE}" == 'hardened' ]]; then
  configure_hardened_control_plane
fi
wait_for_cluster
kubectl cluster-info
