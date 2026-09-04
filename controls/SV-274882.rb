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

  api_server_pods = k8sobjects(api: 'v1', type: 'pods', namespace: 'kube-system').entries.select do |pod|
    pod.labels['component'] == 'kube-apiserver' || pod.name.to_s.start_with?('kube-apiserver-')
  end
  encryption_config_files = api_server_pods.each_with_object([]) do |pod, files|
    api_server = k8sobject(api: 'v1', type: 'pods', namespace: 'kube-system', name: pod.name)
    arguments = (api_server.item&.spec&.containers || []).flat_map do |container|
      [container.command, container.args].flatten.compact.map(&:to_s)
    end
    argument_index = arguments.index do |argument|
      argument == '--encryption-provider-config' || argument.start_with?('--encryption-provider-config=')
    end
    next if argument_index.nil?

    argument = arguments[argument_index]
    files << (argument == '--encryption-provider-config' ? arguments[argument_index + 1] : argument.split('=', 2).last)
  end.compact

  describe 'Kubernetes API Server encryption provider configuration file' do
    subject { encryption_config_files }
    it { should_not be_empty }
    it { should_not include '' }
  end

  describe 'Encryption provider configuration-file contents' do
    skip 'The encryption-provider configuration file is host-local; verify that it encrypts Secrets and does not list identity first with a Control Plane node scan.'
  end
end
