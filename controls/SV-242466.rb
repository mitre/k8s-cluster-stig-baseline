control 'SV-242466' do
  title 'The Kubernetes PKI CRT must have file permissions set to 644 or more restrictive.'
  desc 'The Kubernetes PKI directory contains all certificates (.crt files) supporting secure network communications in the Kubernetes Control Plane. If these files can be modified, data traversing within the architecture components would become unsecure and compromised.'
  desc 'check', %q(Review the permissions of the Kubernetes PKI cert files by using the command:

sudo find /etc/kubernetes/pki/* -name "*.crt" | xargs stat -c '%n %a'

If any of the files have permissions more permissive than "644", this is a finding.)
  desc 'fix', 'Change the ownership of the cert files to "644" by executing the command: 

find /etc/kubernetes/pki -name "*.crt" | xargs chmod 644'
  impact 0.5
  tag check_id: 'C-45741r927138_chk'
  tag severity: 'medium'
  tag gid: 'V-242466'
  tag rid: 'SV-242466r961863_rule'
  tag stig_id: 'CNTR-K8-003330'
  tag gtitle: 'SRG-APP-000516-CTR-001335'
  tag fix_id: 'F-45699r918202_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
