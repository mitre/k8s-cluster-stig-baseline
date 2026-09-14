control 'SV-274882' do
  title 'Kubernetes Secrets must be encrypted at rest.'
  desc 'Kubernetes Secrets may store sensitive information such as passwords, tokens, and keys. These values are stored in the etcd database used by Kubernetes unencrypted. To protect these Secrets at rest, these values must be encrypted.'
  desc 'check', %q(Change to the /etc/kubernetes/manifests directory on the Kubernetes Master Node. Run the command:
grep -i encryption-provider-config *

If the setting "encryption-provider-config" is not configured, this is a finding.

If the setting is configured, check the contents of the file specified by its argument.

If the file does not specify the Secret's resource, this is a finding.

If the identity provider is specified as the first provider for the resource, this is also a finding.)
  desc 'fix', %q(Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Master Node.

Set the value of "--encryption-provider-config" to the path to the encryption config.

The encryption config must specify the Secret's resource and provider. Below is an example:
{
  "kind": "EncryptionConfiguration",
  "apiVersion": "apiserver.config.k8s.io/v1",
  "resources": [
    {
      "resources": [
        "secrets"
      ],
      "providers": [
        {
          "aescbc": {
            "keys": [
              {
                "name": "aescbckey",
                "secret": "xxxxxxxxxxxxxxxxxxx"
              }
            ]
          }
        },
        {
          "identity": {}
        }
      ]
    }
  ]
})
  impact 0.7
  tag check_id: 'C-78983r1107240_chk'
  tag severity: 'high'
  tag gid: 'V-274882'
  tag rid: 'SV-274882r1137640_rule'
  tag stig_id: 'CNTR-K8-001162'
  tag gtitle: 'SRG-APP-000033-CTR-000100'
  tag fix_id: 'F-78888r1107241_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  control_plane_namespace = input('control_plane_namespace')
  api_server_pods = k8sobjects(api: 'v1', type: 'pods', namespace: control_plane_namespace).entries.filter_map do |pod|
    item = k8sobject(api: 'v1', type: 'pods', namespace: control_plane_namespace, name: pod.name).item
    component = (item&.metadata&.labels&.to_h || {})['component']
    [pod.name, item] if component == 'kube-apiserver' || pod.name.to_s.start_with?('kube-apiserver-')
  end

  if api_server_pods.empty?
    describe 'API Server encryption provider configuration visibility' do
      skip "No kube-apiserver Pod is visible in input('control_plane_namespace')=#{control_plane_namespace}. Run node control SV-274882 on each control-plane node, or obtain equivalent provider evidence for a managed control plane."
    end
  else
    findings = api_server_pods.filter_map do |pod_name, item|
      flags, error = KubernetesClusterEvidence.component_flags(item, 'kube-apiserver')
      next "#{pod_name}: #{error}" if error

      "#{pod_name}: --encryption-provider-config must name an absolute configuration-file path" unless flags['encryption-provider-config'].to_s.start_with?('/')
    end
    describe 'API Server encryption provider configuration-file arguments' do
      it 'has valid paths on the API Server containers' do
        expect(findings).to be_empty, "Invalid API Server configuration arguments:\n- #{findings.join("\n- ")}"
      end
    end
    describe 'Encryption provider configuration-file contents' do
      skip 'Run node control SV-274882 on every control-plane node to inspect the referenced configuration contents; obtain provider evidence where node access is unavailable.'
    end
  end
end
