control 'SV-242417' do
  title 'Kubernetes must separate user functionality.'
  desc 'Separating user functionality from management functionality is a
requirement for all the components within the Kubernetes Control Plane. Without
the separation, users may have access to management functions that can degrade
the Kubernetes architecture and the services being offered, and can offer a
method to bypass testing and validation of functions before introduced into a
production environment.'
  desc 'check', 'On the Control Plane, run the command:
kubectl get pods --all-namespaces

Review the namespaces and pods that are returned. Kubernetes system namespaces are kube-node-lease, kube-public, and kube-system.

If any user pods are present in the Kubernetes system namespaces, this is a finding.'
  desc 'fix', 'Move any user pods that are present in the Kubernetes system
namespaces to user specific namespaces.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000211-CTR-000530'
  tag gid: 'V-242417'
  tag rid: 'SV-242417r1137643_rule'
  tag stig_id: 'CNTR-K8-001360'
  tag fix_id: 'F-45650r712606_fix'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']

  system_namespaces = %w[kube-node-lease kube-public kube-system]
  pods = k8sobjects(api: 'v1', type: 'pods')
  entries = pods.entries
  pod_evidence = []

  if pods.resource_failed? || pods.resource_skipped?
    pod_evidence << "Pod inventory unavailable: #{pods.resource_exception_message}"
  else
    entries.select { |entry| system_namespaces.include?(entry.namespace) }.each do |entry|
      item = k8sobject(api: 'v1', type: 'pods', name: entry.name, namespace: entry.namespace).item
      if item.nil?
        pod_evidence << "Pod/#{entry.namespace}/#{entry.name}: listed in the inventory, but ownership details could not be retrieved"
        next
      end

      owners = Array(item.metadata&.ownerReferences).map do |owner|
        "#{owner.kind}/#{owner.name}#{owner.controller ? ' (controller)' : ''}"
      end
      owner_summary = owners.empty? ? 'none reported' : owners.join(', ')
      service_account = item.spec&.serviceAccountName || 'not reported'
      node = item.spec&.nodeName || 'not scheduled'
      pod_evidence << "Pod/#{entry.namespace}/#{entry.name}: owners=#{owner_summary}; serviceAccount=#{service_account}; node=#{node}"
    end
  end

  if pod_evidence.empty?
    describe 'Pods requiring ownership review in Kubernetes system namespaces' do
      subject { pod_evidence }
      it { should be_empty }
    end
  else
    describe 'System-namespace Pod ownership and separation of user workloads' do
      skip "Review the following inventory against documented cluster-component ownership. Owner references and service accounts do not establish organizational approval. Move any user workloads to dedicated namespaces.\n- #{pod_evidence.sort.join("\n- ")}"
    end
  end
end
