## Kubernetes Cluster STIG Automated Compliance Validation Profile

InSpec profile to validate the secure configuration of a Kubernetes cluster against [DISA's](https://public.cyber.mil/stigs/downloads/) Kubernetes Security Technical Implementation Guide (STIG) Version 2 Release 6.

## Getting Started

It is recommended that Cinc Auditor and this profile be run from a **runner** host, such as a DevOps orchestration server, administrative management system, or developer workstation, against the target Kubernetes API using the [train-kubernetes](https://github.com/inspec/train-kubernetes) transport.

The Kubernetes STIG includes requirements for both the cluster and the nodes that comprise it. This profile contains the cluster checks and is intended to be used with the [Kubernetes Node profile](https://github.com/mitre/k8s-node-stig-baseline).

### Requirements

#### Kubernetes Cluster

- Kubernetes platform deployment
- Access to the Kubernetes API
- Credentials with permission to read the resources evaluated by the profile

#### Required software on the runner

- Git
- Ruby and Bundler
- kubectl

### Set up the runner

Install the profile dependencies, including Cinc Auditor and the Kubernetes transport:

```sh
bundle install
bundle exec cinc-auditor version
```

Cinc Auditor loads `train-kubernetes` from the bundle; no global plugin installation is required.

### Profile input values

Profile inputs and their defaults are defined in [inspec.yml](inspec.yml). To evaluate the Kubernetes server version against versions approved for your environment, create an `inputs.yml` file and populate the approved-version list:

```yaml
approved_kubernetes_server_versions: []
```

Replace the empty list with the exact version or versions authorized by the applicable IAVM, CTO, DTM, or STIG. If the list remains empty, the authorization portion of control SV-242443 is reported as Not Reviewed.

### How to execute this profile

Run these commands from the profile directory.

#### Validate access to the Kubernetes API

```sh
kubectl get nodes
bundle exec cinc-auditor detect -t k8s://
```

#### Execute a single control

```sh
bundle exec cinc-auditor exec . -t k8s:// --input-file inputs.yml \
  --controls SV-242383 --show-progress
```

#### Execute all controls

```sh
bundle exec cinc-auditor exec . -t k8s:// --input-file inputs.yml \
  --show-progress
```

#### Execute all controls and save the results as JSON

```sh
bundle exec cinc-auditor exec . -t k8s:// --input-file inputs.yml \
  --show-progress --reporter cli json:results.json
```

Omit `--input-file inputs.yml` when using the defaults from `inspec.yml`.

## Using Heimdall to view JSON results

The JSON results file can be loaded into [Heimdall Lite](https://heimdall-lite.mitre.org/) for an interactive view or uploaded to a [Heimdall server](https://github.com/mitre/heimdall2) to store and compare multiple profile runs.
