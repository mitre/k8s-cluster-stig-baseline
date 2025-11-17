control 'SV-274884' do
  title 'Kubernetes must limit Secret access on a need-to-know basis.'
  desc 'Kubernetes secrets may store sensitive information such as passwords, tokens, and keys. Access to these secrets should be limited to a need-to-know basis via Kubernetes RBAC.'
  desc 'check', 'Review the Kubernetes accounts and their corresponding roles. 

If any accounts have read (list, watch, get) access to Secrets without a documented organizational requirement, this is a finding. 

Run the below command to list the workload resources for applications deployed to Kubernetes:
kubectl get all -A -o yaml 

If Secrets are attached to applications without a documented requirement, this is a finding.'
  desc 'fix', 'For Kubernetes accounts that have read access to Secrets without a documented requirement, modify the corresponding Role or ClusterRole to remove list, watch, and get privileges for Secrets.'
  impact 0.5
  tag check_id: 'C-78985r1107234_chk'
  tag severity: 'medium'
  tag gid: 'V-274884'
  tag rid: 'SV-274884r1107236_rule'
  tag stig_id: 'CNTR-K8-001163'
  tag gtitle: 'SRG-APP-000429-CTR-001060'
  tag fix_id: 'F-78890r1107235_fix'
  tag 'documentable'
  tag cci: ['CCI-002476']
  tag nist: ['SC-28 (1)']
end
