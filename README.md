# Kubernetes Cluster STIG Automated Compliance Validation Profile

This InSpec profile evaluates the cluster requirements of the DISA Kubernetes
Security Technical Implementation Guide (STIG), **Version 2 Release 6**. Run it
alongside the [Kubernetes Node profile](https://github.com/mitre/k8s-node-stig-baseline),
which assesses the operating systems of control-plane and worker nodes.

## Requirements and setup

Use an audit runner with Git, Ruby, Bundler, and kubectl. CI uses Ruby 3.1. The
runner needs network access to the Kubernetes API and a kubeconfig with
permission to read the resources assessed across namespaces, including RBAC
objects. Cluster-admin credentials provide that access; a dedicated audit role
can be used if it grants the required reads.

Install the Gemfile dependencies, including Cinc Auditor and the Kubernetes
Train transport:

```sh
bundle install
bundle exec cinc-auditor version
```

Cinc Auditor loads `train-kubernetes` from the bundle; no global plugin
installation or edit to a user plugin file is required. Bundler creates a local
`Gemfile.lock`, which is not tracked by this repository. Keep it when you need
to reproduce a local dependency resolution.

Check the kubeconfig context before scanning. Set `KUBECONFIG` if the file is
not in the default location:

```sh
kubectl config current-context
kubectl get nodes
bundle exec cinc-auditor detect -t k8s://
```

## Profile inputs

[inspec.yml](inspec.yml) declares the inputs. Save a mapping such as the
following to `inputs.yml` and adjust it for the target:

```yaml
# Populate from the applicable organizational authorization; no versions are
# assumed approved by default.
approved_kubernetes_server_versions: []
control_plane_namespace: kube-system
control_plane_static_pod_components:
  - kube-apiserver
  - kube-controller-manager
  - kube-scheduler
```

| Input | Default | Purpose |
|---|---|---|
| `approved_kubernetes_server_versions` | `[]` | Exact API-server `gitVersion` strings authorized by the applicable IAVM, CTO, DTM, or STIG. |
| `control_plane_namespace` | `kube-system` | Namespace exposing the control-plane static Pods. |
| `control_plane_static_pod_components` | `kube-apiserver`, `kube-controller-manager`, `kube-scheduler` | Components assessed for the PodSecurity feature gate before Kubernetes 1.25. |

An empty approved-version list leaves the authorization portion of SV-242443
**Not Reviewed**. Populate it with exact authorized strings, including the `v`
prefix and any distribution suffix. Do not copy the Kind fixture version as an
organizational approval. Client/server version skew still needs separate
verification. Supply all applicable components in the component list; an empty
list is rejected, as are unknown component names and invalid namespaces.

The profile obtains the Kubernetes server version through the API. Managed
control planes may not expose static Pods, in which case their host-local
configuration requires evidence from the provider or another assessment path.

## Run an assessment

Run commands from the profile directory:

```sh
# Run all controls and save results.
bundle exec cinc-auditor exec . -t k8s:// --input-file inputs.yml \
  --show-progress --reporter cli json:results.json

# Run one control.
bundle exec cinc-auditor exec . -t k8s:// --input-file inputs.yml \
  --controls SV-242383 --show-progress
```

Manual-review results are expected where the STIG requires organizational
justification, workload ownership, or interpretation of sensitive information.
The API-only scan delegates host-local portions to node controls SV-254800
(admission policy), SV-274882 (encryption configuration), SV-254801 (kubelet
PodSecurity), and SV-242443 (client/server skew). Run those on each applicable
node and retain both profiles' results: the shared IDs represent complementary
checks. Where managed control planes expose no component Pods or node access,
obtain equivalent provider evidence; unavailable API evidence is Not Reviewed.
A passing profile check or test suite does not complete organizational reviews.

Secret-access evidence includes namespaced and cluster-wide RBAC grants, their
resourceNames restrictions and effective scope, and Secret references in Pods
and workload templates, including dormant Deployments and suspended CronJobs.
Image comparison normalizes Docker Hub aliases and implicit `latest` tags;
explicit digests identify content regardless of tag. Other registry aliases and
tag-only versus digest-only references remain distinct because the scan does
not query registries to prove their equivalence.

## Lint and validate

```sh
bundle exec cinc-auditor vendor . --overwrite
bundle exec rake pre_commit_checks
```

The vendor command replaces `vendor/`. Preserve any SAF delta output stored
there before running it. `pre_commit_checks` runs RuboCop, the regression specs, and Cinc Auditor
profile validation; any failure returns a nonzero status. To run them
individually, use `bundle exec rake lint`, `bundle exec rake spec`, and
`bundle exec rake inspec:check`.
The latter retains its historical task name but invokes Cinc Auditor.

The lint configuration is based on the RHEL 9 sibling profile, targets Ruby
3.1, includes local resource libraries, and excludes vendored dependencies,
generated mapped controls, and Kitchen artifacts. The lint workflow runs on
pull requests and pushes to `main`.

## Test Kitchen Kind suites

Both disposable suites require Docker Desktop (or Docker Engine), `kind`, and
`kubectl` in addition to Ruby and Bundler. Vendor the profile as shown above,
then run:

```sh
KITCHEN_LOCAL_YAML=kitchen.kind.yml bundle exec kitchen test --destroy=always vanilla
KITCHEN_LOCAL_YAML=kitchen.kind.yml bundle exec kitchen test --destroy=always hardened
```

`vanilla` uses the default Kind API server. `hardened` configures Pod Security
Admission, Secrets encryption at rest, and the expected test API-server version.
The setup generates a per-run encryption key and deletes it with the cluster.
These are test fixtures, not a production hardening procedure.

Suite inputs are in `kind.vanilla.inputs.yml` and `kind.hardened.inputs.yml`.
The hardened approved-version entry matches the pinned Kind image and must be
updated when that image's API-server version changes.

Validate saved results with the suite's SAF threshold:

```sh
saf validate threshold -i results/kind_vanilla.json -T kind.vanilla.threshold.yml
saf validate threshold -i results/kind_hardened.json -T kind.hardened.threshold.yml
```

Install the MITRE SAF CLI separately to use those commands.

## View assessment results

Open JSON assessment results in [Heimdall Lite](https://heimdall-lite.mitre.org/)
or upload them to an organizational [Heimdall server](https://github.com/mitre/heimdall2).
