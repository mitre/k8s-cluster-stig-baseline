## Kubernetes Cluster STIG Automated Compliance Validation Profile

<b>Kubernetes Cluster</b> STIG Automated Compliance Validation Profile that works with Chef InSpec to perform automated compliance checks of the <b>Kubernetes Cluster</b>. It is to be used in conjunction with the <b>[Kubernetes Node](https://gitlab.dsolab.io/scv-content/inspec/kubernetes/k8s-node-stig-baseline)</b> profile that performs automated compliance checks of the <b>Kubernetes Nodes</b>.

This automated Security Technical Implementation Guide (STIG) validator was developed to reduce the time it takes to perform a security check based upon STIG Guidance from DISA. These check results should provide information needed to receive a secure authority to operate (ATO) certification for the applicable technology.

<b>Kubernetes Cluster Profile</b> uses [Chef InSpec](https://github.com/chef/inspec), which provides an open source compliance, security and policy testing framework that dynamically extracts system configuration information.

## Kubernetes STIG Overview

The <b>Kubernetes</b> STIG (https://public.cyber.mil/stigs/) by the United States Defense Information Systems Agency (DISA) offers a comprehensive compliance guide for the configuration and operation of various technologies.
DISA has created and maintains a set of security guidelines for applications, computer systems or networks connected to the DoD. These guidelines are the primary security standards used by many DoD agencies. In addition to defining security guidelines, the STIG also stipulates how security training should proceed and when security checks should occur. Organizations must stay compliant with these guidelines or they risk having their access to the DoD terminated.

[STIG](https://en.wikipedia.org/wiki/Security_Technical_Implementation_Guide)s are the configuration standards for United States Department of Defense (DoD) Information Assurance (IA) and IA-enabled devices/systems published by the United States Defense Information Systems Agency (DISA). Since 1998, DISA has played a critical role enhancing the security posture of DoD's security systems by providing the STIGs. The STIGs contain technical guidance to "lock down" information systems/software that might otherwise be vulnerable to a malicious computer attack.

The requirements associated with the <b>Kubernetes</b> STIG are derived from the [National Institute of Standards and Technology](https://en.wikipedia.org/wiki/National_Institute_of_Standards_and_Technology) (NIST) [Special Publication (SP) 800-53, Revision 4](https://en.wikipedia.org/wiki/NIST_Special_Publication_800-53) and related documents.

While the Kubernetes STIG automation profile check was developed to provide technical guidance to validate information with security systems such as applications, the guidance applies to all organizations that need to meet internal security as well as compliance standards.

### This STIG Automated Compliance Validation Profile was developed based upon:
- Kubernetes Security Technical Implementation Guide
### Update History 
| Guidance Name  | Guidance Version | Guidance Location                            | Profile Version | Profile Release Date | STIG EOL    | Profile EOL |
|---------------------------------------|------------------|--------------------------------------------|-----------------|----------------------|-------------|-------------|
| Kubernetes STIG  | v1r1 | https://public.cyber.mil/stigs/downloads/  |         1.0.0          |      06/16/2021             | NA | NA |
| Kubernetes STIG  | v1r1 | https://public.cyber.mil/stigs/downloads/  |         1.0.1          |      01/20/2022         | NA | NA |


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

## Check Overview

**Manual Checks**

These checks are not included in the automation process.

| Check Number | Description                                                                                                                                                                                                                                                                                 |
|--------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|V-242410| The Kubernetes API Server must enforce ports, protocols, and services (PPS) that adhere to the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL).|
|V-242411| The Kubernetes Scheduler must enforce ports, protocols, and services (PPS) that adhere to the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL).|
|V-242412| The Kubernetes Controllers must enforce ports, protocols, and services (PPS) that adhere to the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL).|
|V-242413| The Kubernetes etcd must enforce ports, protocols, and services (PPS) that adhere to the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL).|
|V-242417| Kubernetes must separate user functionality.|


**Normal Checks**

These checks will follow the normal automation process and will report accurate STIG compliance PASS/FAIL.

| Check Number | Description                                                                                                                                                                                                               |
|--------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|V-242383| User-managed resources must be created in dedicated namespaces.|
|V-242395| Kubernetes dashboard must not be enabled.|
|V-242414| The Kubernetes cluster must use non-privileged host ports for user  pods.|
|V-242415| Secrets in Kubernetes must not be stored as environment variables.|
|V-242437| Kubernetes must have a pod security policy set.|
|V-242442| Kubernetes must remove old components after updated versions have been installed.|
|V-242443| Kubernetes must contain the latest updates as authorized by IAVMs, CTOs, DTMs, and STIGs.|

## Authors

Defense Information Systems Agency (DISA) https://www.disa.mil/

STIG support by DISA Risk Management Team and Cyber Exchange https://public.cyber.mil/

## Legal Notices

Copyright © 2020 Defense Information Systems Agency (DISA)
