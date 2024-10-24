# encoding: UTF-8

control 'V-242383' do
  title 'User-managed resources must be created in dedicated namespaces.'
  desc  "Creating namespaces for user-managed resources is important when
implementing Role-Based Access Controls (RBAC). RBAC allows for the
authorization of users and helps support proper API server permissions
separation and network micro segmentation. If user-managed resources are placed
within the default namespaces, it becomes impossible to implement policies for
RBAC permission, service account usage, network policies, and more."
  desc  'rationale', ''
  desc  'check', "
    To view the available namespaces, run the command:

    kubectl get namespaces

    The default namespaces to be validated are default, kube-public and
kube-node-lease if it is created.

    For the default namespace, execute the commands:

    kubectl config set-context --current --namespace=default
    kubectl get all

    For the kube-public namespace, execute the commands:

    kubectl config set-context --current --namespace=kube-public
    kubectl get all

    For the kube-node-lease namespace, execute the commands:

    kubectl config set-context --current --namespace=kube-node-lease
    kubectl get all

    The only valid return values are the kubernetes service (i.e.,
service/kubernetes) and nothing at all.

    If a return value is returned from the \"kubectl get all\" command and it
is not the kubernetes service (i.e., service/kubernetes), this is a finding.
  "
  desc 'fix', "Move any user-managed resources from the default, kube-public
and kube-node-lease namespaces, to user namespaces."
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000038-CTR-000105'
  tag gid: 'V-242383'
  tag rid: 'SV-242383r712505_rule'
  tag stig_id: 'CNTR-K8-000290'
  tag fix_id: 'F-45616r712504_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  approved_services = input('k8s_approved_services')
  default_namespaces = input('k8s_default_namespaces')

  default_namespaces_with_unapproved_services = default_namespaces.reject { |ns| 
    (k8sobjects(api: 'v1', type: 'services', namespace: ns).entries.map(&:name) - approved_services).empty?
  }

  default_namespaces_with_pods = default_namespaces.select { |ns| 
    k8sobjects(api: 'v1', type: 'pods', namespace: ns).exist?
  }

  describe 'Default namespaces' do
    it 'should only contain approved services or no services' do
      expect(default_namespaces_with_unapproved_services).to all(be_empty), "Failing namespaces:\n\t#{default_namespaces_with_unapproved_services}"
    end
    it 'should have no running pods' do
      expect(default_namespaces_with_pods).to all(be_empty), "Failing namespaces: #{default_namespaces_with_pods}"
    end
  end
end
