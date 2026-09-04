# encoding: UTF-8

control 'V-242415' do
  title 'Secrets in Kubernetes must not be stored as environment variables.'
  desc  "Secrets, such as passwords, keys, tokens, and certificates should not
be stored as environment variables. These environment variables are accessible
inside Kubernetes by the \"Get Pod\" API call, and by any system, such as CI/CD
pipeline, which has access to the definition file of the container. Secrets
must be mounted from files or stored within password vaults."
  desc  'rationale', ''
  desc  'check', "
    On the Kubernetes Master node, run the following command:

    kubectl get all -o jsonpath='{range .items[?(@..secretKeyRef)]} {.kind}
{.metadata.name} {\"\
    \"}{end}' -A

    If any of the values returned reference environment variables, this is a
finding.
  "
  desc 'fix', "Any secrets stored as environment variables must be moved to
the secret files with the proper protections and enforcements or placed within
a password vault."
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000171-CTR-000435'
  tag gid: 'V-242415'
  tag rid: 'SV-242415r712601_rule'
  tag stig_id: 'CNTR-K8-001160'
  tag fix_id: 'F-45648r712600_fix'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']

  k8sobjects(api: 'v1', type: 'pods').entries.each do |entry|
    describe k8sobject(api: 'v1', type: 'pods', name: entry.name, namespace: entry.namespace) do
      its('k8sobject.spec.to_s') { should_not match 'secretKeyRef' }
    end
  end

  if k8sobjects(api: 'v1', type: 'pods').entries.empty?
    describe 'No pods found in the cluster' do
      skip
    end
  end
end
