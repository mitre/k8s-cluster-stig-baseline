control 'SV-274883' do
  title 'Sensitive information must be stored using Kubernetes Secrets or an external Secret store provider.'
  desc 'Sensitive information, such as passwords, keys, and tokens must not be stored in application code.

Kubernetes offers a resource called Secrets that are designed for storing sensitive information for use by applications. Secrets are created and managed separately from application code. Additionally, they can be encrypted at rest and access to the secrets can be controlled via RBAC.'
  desc 'check', 'On the Kubernetes Master node, run the following command:
kubectl get all,cm -A -o yaml 

Manually review the output for sensitive information.

If any sensitive information is found, this is a finding.'
  desc 'fix', 'Any sensitive information found must be stored in an approved external Secret store provider or use Kubernetes Secrets (attached on an as-needed basis to pods).'
  impact 0.7
  tag check_id: 'C-78984r1107237_chk'
  tag severity: 'high'
  tag gid: 'V-274883'
  tag rid: 'SV-274883r1107239_rule'
  tag stig_id: 'CNTR-K8-001161'
  tag gtitle: 'SRG-APP-000171-CTR-000435'
  tag fix_id: 'F-78889r1107238_fix'
  tag 'documentable'
  tag cci: ['CCI-004062']
  tag nist: ['IA-5 (1) (d)']

  describe 'Sensitive information stored in application code and workload configuration' do
    skip 'The STIG requires a semantic review for organization-defined sensitive information; inspect workload manifests and ConfigMaps with the application owner.'
  end
end
