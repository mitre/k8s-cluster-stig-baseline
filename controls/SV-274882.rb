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
  tag check_id: 'C-78983r1107231_chk'
  tag severity: 'high'
  tag gid: 'V-274882'
  tag rid: 'SV-274882r1107233_rule'
  tag stig_id: 'CNTR-K8-001162'
  tag gtitle: 'SRG-APP-000033-CTR-000100'
  tag fix_id: 'F-78888r1107232_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
