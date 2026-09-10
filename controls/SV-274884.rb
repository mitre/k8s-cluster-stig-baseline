control 'SV-274884' do
  title 'Kubernetes must limit Secret access on a need-to-know basis.'
  desc 'Kubernetes secrets may store sensitive information such as passwords, tokens, and keys. Access to these secrets should be limited to a need-to-know basis via Kubernetes RBAC.'
  desc 'check', 'Review the Kubernetes accounts and their corresponding roles. 

If any accounts have read (list, watch, get) access to Secrets without a documented organizational requirement, this is a finding. 

Run the below command to list the workload resources for applications deployed to Kubernetes:
kubectl get all -A -o yaml 

If Secrets are attached to applications without a documented requirement, this is a finding.'
  desc 'fix', 'For Kubernetes accounts that have read access to Secrets without a documented requirement, modify the corresponding Role or ClusterRole to remove list, watch, and get privileges for Secrets.'
  impact 0.5
  tag check_id: 'C-78985r1107243_chk'
  tag severity: 'medium'
  tag gid: 'V-274884'
  tag rid: 'SV-274884r1107245_rule'
  tag stig_id: 'CNTR-K8-001163'
  tag gtitle: 'SRG-APP-000429-CTR-001060'
  tag fix_id: 'F-78890r1107244_fix'
  tag 'documentable'
  tag cci: ['CCI-002476']
  tag nist: ['SC-28 (1)']

  secret_read_role = lambda do |role|
    Array(role.rules).any? do |rule|
      rule = rule.to_h
      resources = Array(rule[:resources] || rule['resources'])
      verbs = Array(rule[:verbs] || rule['verbs'])
      (resources.include?('secrets') || resources.include?('*')) && (verbs & %w[get list watch *]).any?
    end
  end

  secret_read_roles = {}
  k8sobjects(api: 'rbac.authorization.k8s.io/v1', type: 'clusterroles').entries.each do |role|
    secret_read_roles["ClusterRole/#{role.name}"] = true if secret_read_role.call(role)
  end
  k8sobjects(api: 'rbac.authorization.k8s.io/v1', type: 'roles').entries.each do |role|
    secret_read_roles["Role/#{role.namespace}/#{role.name}"] = true if secret_read_role.call(role)
  end

  role_reference = lambda do |binding|
    role_ref = binding.roleRef
    next nil if role_ref.nil? || role_ref.kind.to_s.empty? || role_ref.name.to_s.empty?

    if role_ref.kind == 'ClusterRole'
      "ClusterRole/#{role_ref.name}"
    elsif role_ref.kind == 'Role'
      "Role/#{binding.namespace}/#{role_ref.name}"
    end
  end
  binding_subjects = lambda do |binding|
    Array(binding.subjects).map do |subject|
      subject_namespace = subject.namespace.to_s
      subject_namespace = binding.namespace.to_s if subject.kind == 'ServiceAccount' && subject_namespace.empty?
      [subject.kind, subject_namespace, subject.name].compact.map(&:to_s).reject(&:empty?).join('/')
    end
  end
  secret_read_bindings = []
  binding_types = { 'rolebindings' => 'RoleBinding', 'clusterrolebindings' => 'ClusterRoleBinding' }
  binding_types.each do |binding_type, binding_kind|
    k8sobjects(api: 'rbac.authorization.k8s.io/v1', type: binding_type).entries.each do |binding|
      referenced_role = role_reference.call(binding)
      next unless secret_read_roles.key?(referenced_role)

      subjects = binding_subjects.call(binding)
      binding_location = binding_type == 'rolebindings' ? "#{binding.namespace}/#{binding.name}" : binding.name
      secret_read_bindings << "#{binding_kind}/#{binding_location} grants #{referenced_role} to #{subjects.empty? ? 'no subjects' : subjects.join(', ')}"
    end
  end

  workload_secret_references = []
  k8sobjects(api: 'v1', type: 'pods').entries.each do |entry|
    pod = k8sobject(api: 'v1', type: 'pods', name: entry.name, namespace: entry.namespace)
    pod_spec = pod.item&.spec
    containers = [pod_spec&.containers, pod_spec&.initContainers, pod_spec&.ephemeralContainers].flat_map { |group| Array(group) }

    containers.each do |container|
      Array(container.env).each do |environment_variable|
        secret_name = environment_variable.valueFrom&.secretKeyRef&.name
        workload_secret_references << "#{entry.namespace}/#{entry.name} container #{container.name} environment variable #{environment_variable.name} references Secret/#{secret_name}" unless secret_name.to_s.empty?
      end
      Array(container.envFrom).each do |environment_source|
        secret_name = environment_source.secretRef&.name
        workload_secret_references << "#{entry.namespace}/#{entry.name} container #{container.name} envFrom references Secret/#{secret_name}" unless secret_name.to_s.empty?
      end
    end

    Array(pod_spec&.volumes).each do |volume|
      secret_name = volume.secret&.secretName
      workload_secret_references << "#{entry.namespace}/#{entry.name} volume #{volume.name} references Secret/#{secret_name}" unless secret_name.to_s.empty?
      Array(volume.projected&.sources).each do |source|
        secret_name = source.secret&.name
        workload_secret_references << "#{entry.namespace}/#{entry.name} projected volume #{volume.name} references Secret/#{secret_name}" unless secret_name.to_s.empty?
      end
    end

    Array(pod_spec&.imagePullSecrets).each do |secret|
      workload_secret_references << "#{entry.namespace}/#{entry.name} imagePullSecrets references Secret/#{secret.name}" unless secret.name.to_s.empty?
    end
  end

  if secret_read_bindings.empty? && workload_secret_references.empty?
    describe 'Secret-read RBAC bindings and workload Secret references' do
      subject { secret_read_bindings + workload_secret_references }
      it { should be_empty }
    end
  else
    describe 'Need-to-know justification for Secret-read permissions and workload Secret references' do
      binding_candidates = secret_read_bindings.empty? ? 'none' : secret_read_bindings.join("\n- ")
      workload_candidates = workload_secret_references.empty? ? 'none' : workload_secret_references.join("\n- ")
      skip "Verify documented organizational need for the following candidates.\nRBAC bindings:\n- #{binding_candidates}\nWorkload Secret references:\n- #{workload_candidates}"
    end
  end
end
