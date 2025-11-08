control 'SV-242459' do
  title 'The Kubernetes etcd must have file permissions set to 644 or more restrictive.'
  desc 'The Kubernetes etcd key-value store provides a way to store data to the Control Plane. If these files can be changed, data to API object and Control Plane would be compromised.'
  desc 'check', 'Review the permissions of the Kubernetes etcd by using the command:

ls -AR /var/lib/etcd/*

If any of the files have permissions more permissive than "644", this is a finding.'
  desc 'fix', 'Change the permissions of the manifest files to "644" by executing the command:

chmod -R 644 /var/lib/etcd/*'
  impact 0.5
  tag check_id: 'C-45734r918198_chk'
  tag severity: 'medium'
  tag gid: 'V-242459'
  tag rid: 'SV-242459r961863_rule'
  tag stig_id: 'CNTR-K8-003260'
  tag gtitle: 'SRG-APP-000516-CTR-001335'
  tag fix_id: 'F-45692r918199_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
