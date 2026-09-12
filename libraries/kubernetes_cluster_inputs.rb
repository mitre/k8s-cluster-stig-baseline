# Validates tailoring values used to discover and authorize cluster components.
module ::KubernetesClusterInputs
  COMPONENTS = %w[kube-apiserver kube-controller-manager kube-scheduler].freeze

  module_function

  def value(name, value)
    predicate = { 'control_plane_namespace' => :namespace?, 'control_plane_static_pod_components' => :components?, 'approved_kubernetes_server_versions' => :versions? }[name]
    raise ArgumentError, "Invalid input('#{name}'): #{requirement(name)}" if predicate && !public_send(predicate, value)

    value
  end

  def namespace?(value)
    value.is_a?(String) && value.length <= 63 && value.match?(/\A[a-z0-9](?:[-a-z0-9]*[a-z0-9])?\z/)
  end

  def components?(value)
    value.is_a?(Array) && !value.empty? && (value - COMPONENTS).empty?
  end

  def versions?(value)
    value.is_a?(Array) && value.all? { |version| version.is_a?(String) && version.match?(/\Av\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)*\z/) }
  end

  def requirement(name)
    {
      'control_plane_namespace' => 'supply a valid Kubernetes namespace name',
      'control_plane_static_pod_components' => "supply a nonempty array drawn from #{COMPONENTS.join(', ')}",
      'approved_kubernetes_server_versions' => 'supply exact v-prefixed server versions, or [] for manual authorization review'
    }.fetch(name)
  end
end
