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
    api_server = k8sobject(api: 'v1', type: 'pods', namespace: control_plane_namespace, name: pod.name)
    api_server_item = api_server.item
    component = (api_server_item&.metadata&.labels&.to_h || {})['component']
    [pod.name, api_server] if component == 'kube-apiserver' || pod.name.to_s.start_with?('kube-apiserver-')
  end
  encryption_config_findings = []
  encryption_config_findings << "No kube-apiserver static Pod is exposed in #{control_plane_namespace}" if api_server_pods.empty?

  api_server_pods.each do |pod_name, api_server|
    arguments = (api_server.item&.spec&.containers || []).flat_map do |container|
      [container.command, container.args].flatten.compact.map(&:to_s)
    end
    encryption_config_files = arguments.each_with_index.filter_map do |argument, index|
      if argument == '--encryption-provider-config'
        arguments[index + 1]
      elsif argument.start_with?('--encryption-provider-config=')
        argument.split('=', 2).last
      end
    end

    encryption_config_findings << "kube-apiserver Pod #{pod_name} does not set a non-empty --encryption-provider-config" if encryption_config_files.none? { |file_name| !file_name.to_s.strip.empty? }
  end

  describe 'Kubernetes API Server encryption provider configuration-file arguments' do
    subject { encryption_config_findings }
    it { should be_empty }
  end

  describe 'Encryption provider configuration-file contents' do
    skip 'The encryption-provider configuration file is host-local; verify that it encrypts Secrets and does not list identity first with a Control Plane node scan.'
  end
end
