require 'kubernetes_arguments'

# Keeps evidence tied to the component container instead of unrelated sidecars.
module ::KubernetesClusterEvidence
  module_function

  def component_flags(item, component)
    containers = matching_containers(item, component)
    return [nil, "Expected exactly one #{component} container"] unless containers.length == 1

    tokens = Array(containers.first.command) + Array(containers.first.args)
    return [nil, 'Component command and args must contain only strings'] unless tokens.all? { |token| token.is_a?(String) }

    [KubernetesArguments.parse(tokens), nil]
  end

  def matching_containers(item, component)
    Array(item&.spec&.containers).select do |container|
      container.name == component || File.basename(Array(container.command).first.to_s) == component
    end
  end

  def default_registry?(parts)
    parts.length == 1 || (!parts.first.match?(/[.:]/) && parts.first != 'localhost')
  end

  def image_identity(image)
    reference, digest = image.split('@', 2)
    last_colon = reference.rindex(':')
    tagged = last_colon && last_colon > (reference.rindex('/') || -1)
    name = tagged ? reference[0...last_colon] : reference
    version = digest || (tagged ? reference[(last_colon + 1)..] : 'latest')
    [canonical_image_name(name), version]
  end

  def canonical_image_name(name)
    parts = name.split('/')
    parts.unshift('docker.io') if default_registry?(parts)
    parts[0] = 'docker.io' if %w[index.docker.io registry-1.docker.io].include?(parts[0])
    parts.insert(1, 'library') if parts[0] == 'docker.io' && parts.length == 2
    parts.join('/')
  end
end
