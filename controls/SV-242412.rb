control 'SV-242412' do
  title 'The Kubernetes Controllers must enforce ports, protocols, and services
(PPS) that adhere to the Ports, Protocols, and Services Management Category
Assurance List (PPSM CAL).'
  desc 'Kubernetes Controller ports, protocols, and services must be
controlled and conform to the PPSM CAL. Those PPS that fall outside the PPSM
CAL must be blocked. Instructions on the PPSM can be found in DoD Instruction
8551.01 Policy.'
  desc 'check', 'Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Control Plane. Run the command:
grep kube-conntroller-manager.manifest -I -secure-port

-Review manifest file by executing the following:
VIM <Manifest Name>:
Review  livenessProbe:
HttpGet:
Port:
Review ports:
- containerPort:
       hostPort:
- containerPort:
       hostPort:

Run Command:
kubectl describe services --all-namespaces
Search labels for any controller namespaces.

Any manifest and namespace PPS or services configuration not in compliance with PPSM CAL is a finding.

Review the information systems documentation and interview the team, gain an understanding of the Controller architecture, and determine applicable PPS. Any PPS in the system documentation not in compliance with the CAL PPSM is a finding. Any PPS not set in the system documentation is a finding.

Review findings against the most recent PPSM CAL:
https://cyber.mil/ppsm/cal/

Verify Controller network boundary with the PPS associated with the Controller for Assurance Categories. Any PPS not in compliance with the CAL Assurance Category requirements is a finding.'
  desc 'fix', 'Amend any system documentation requiring revision to comply with the PPSM CAL.

Update Kubernetes Controller manifest and namespace PPS configuration to comply with PPSM CAL.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000142-CTR-000330'
  tag gid: 'V-242412'
  tag rid: 'SV-242412r1043177_rule'
  tag stig_id: 'CNTR-K8-000940'
  tag fix_id: 'F-45645r1007479_fix'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']

  describe "Manually  Kubernetes Controllers must enforces ports, protocols, and services (PPS)
  that adhere to the Ports, Protocols, and Services Management Category Assurance
  List (PPSM CAL)" do
    skip 'PPSM CAL compliance requires review of the approved system architecture and organizational documentation.'
  end
end
