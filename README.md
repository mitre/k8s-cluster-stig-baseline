## Kubernetes Cluster STIG Automated Compliance Validation Profile

InSpec profile to validate the secure configuration of a Kubernetes cluster against [DISA's](https://iase.disa.mil/stigs/Pages/index.aspx) Kubernetes Secure Technical Implementation Guide (STIG) Version 1 Release 1.

## Getting Started  
It is intended and recommended that InSpec and this profile be run from a __"runner"__ host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target remotely using the [train-kubernetes plugin](https://github.com/inspec/train-kubernetes) transport (details below).

__For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.__

Latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

The Kubernetes STIG includes security requirements for both the Kubernetes cluster itself and the nodes that comprise it. This profile includes the checks for the cluster portion. It is intended  to be used in conjunction with the <b>[Kubernetes Node](https://github.com/mitre/k8s-node-stig-baseline)</b> profile that performs automated compliance checks of the Kubernetes nodes.

## Getting Started

### Requirements

#### Kubernetes Cluster
- Kubernetes Platform deployment
- Access to the Kubernetes Cluster API
- Kubernetes Cluster Admin credentials cached on the runner.


#### Required software on the InSpec Runner
- git
- [InSpec](https://www.chef.io/products/chef-inspec/)

### Setup Environment on the InSpec Runner
#### Install InSpec
Goto https://www.inspec.io/downloads/ and consult the documentation for your Operating System to download and install InSpec.


#### Ensure InSpec version is at least 4.23.10 
```sh
inspec --version
```

#### Install InSpec Kubernetes Train
Kubernetes Train allows InSpec to send request over Kubernetes API to inspect the Kubernetes Cluster.

```sh
# Use one of the two following approaches for installing train-kubernetes.

# if InSpec was installed as a gem, use the system gem binary to install train-kubernetes.
# to check, compare `which inspec` to $GEM_HOME, if they match use
gem install train-kubernetes -v 0.1.6

# if InSpec was installed as a package, use the embedded gem binary to install train-kubernetes.
# to check, compare `which inspec` to $GEM_HOME, if they do not match or if $GEM_HOME is null use
sudo /opt/inspec/embedded/bin/gem install train-kubernetes -v 0.1.6

# Import gem as InSpec plugin
inspec plugin install train-kubernetes

#If it has the version set to "= 0.1.6", modify it to "0.1.6" and save the file.
vi ~/.inspec/plugins.json

# Run the following command to confirm train-kubernetes is installed
inspec plugin list
```
### How to execute this instance  
(See: https://www.inspec.io/docs/reference/cli/)

#### Validate access to Kubernetes API
```sh
kubectl get nodes

# Upon success try the following command to validate InSpec can reach the cluster API
inspec detect -t k8s://
```

#### Execute a single Control in the Profile 
**Note**: Replace the profile's directory name - e.g. - `<Profile>` with `.` if currently in the profile's root directory.

```sh
inspec exec <Profile> -t k8s:// --controls=<control_id> <control_id> --show-progress
```

#### Execute a Single Control and save results as JSON 
```sh
inspec exec <Profile> -t k8s:// --controls=<control_id> <control_id> --show-progress --reporter json:results.json
```

#### Execute All Controls in the Profile 
```sh
inspec exec <Profile> -t k8s:// --show-progress
```

#### Execute all the Controls in the Profile and save results as JSON 
```sh
inspec exec <Profile> -t k8s:// --show-progress  --reporter json:results.json
```
## Using Heimdall for Viewing the JSON Results

The JSON results output file can be loaded into __[heimdall-lite](https://heimdall-lite.mitre.org/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __[full heimdall server](https://github.com/mitre/heimdall2)__, allowing for additional functionality such as to store and compare multiple profile runs.
