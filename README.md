## Kubernetes Cluster STIG Automated Compliance Validation Profile

InSpec profile to validate the secure configuration of a Kubernetes cluster against [DISA's](https://public.cyber.mil/stigs/downloads/) Kubernetes Secure Technical Implementation Guide (STIG) Version 1 Release 1.

## Getting Started  
It is intended and recommended that Cinc Auditor and this profile be run from a __"runner"__ host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target remotely using the [train-kubernetes plugin](https://github.com/inspec/train-kubernetes) transport (details below).

__For the best security of the runner, always install on the runner the _latest version_ of Cinc Auditor and supporting Ruby language components.__

The bundled dependencies use Cinc Auditor, the community distribution compatible with InSpec profiles.

The Kubernetes STIG includes security requirements for both the Kubernetes cluster itself and the nodes that comprise it. This profile includes the checks for the cluster portion. It is intended  to be used in conjunction with the <b>[Kubernetes Node](https://github.com/mitre/k8s-node-stig-baseline)</b> profile that performs automated compliance checks of the Kubernetes nodes.

## Getting Started

### Requirements

#### Kubernetes Cluster
- Kubernetes Platform deployment
- Access to the Kubernetes Cluster API
- Kubernetes Cluster Admin credentials cached on the runner.


#### Required software on the runner
- git
- Ruby and Bundler

### Setup Environment on the runner
Install the profile's locked testing stack, including Cinc Auditor and the Kubernetes Train transport:

```sh
bundle install
bundle exec cinc-auditor version
```

Cinc Auditor loads `train-kubernetes` from the bundle; no global plugin
installation or edit to a user plugin file is required.
### How to execute this instance  

#### Validate access to Kubernetes API
```sh
kubectl get nodes

# Upon success, validate that Cinc Auditor can reach the cluster API.
bundle exec cinc-auditor detect -t k8s://
```

#### Execute a single Control in the Profile 
**Note**: Replace the profile's directory name - e.g. - `<Profile>` with `.` if currently in the profile's root directory.

```sh
bundle exec cinc-auditor exec <Profile> -t k8s:// --controls=<control_id> <control_id> --show-progress
```

#### Execute a Single Control and save results as JSON 
```sh
bundle exec cinc-auditor exec <Profile> -t k8s:// --controls=<control_id> <control_id> --show-progress --reporter json:results.json
```

#### Execute All Controls in the Profile 
```sh
bundle exec cinc-auditor exec <Profile> -t k8s:// --show-progress
```

#### Execute all the Controls in the Profile and save results as JSON 
```sh
bundle exec cinc-auditor exec <Profile> -t k8s:// --show-progress  --reporter json:results.json
```
## Using Heimdall for Viewing the JSON Results

The JSON results output file can be loaded into __[heimdall-lite](https://heimdall-lite.mitre.org/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __[full heimdall server](https://github.com/mitre/heimdall2)__, allowing for additional functionality such as to store and compare multiple profile runs.
