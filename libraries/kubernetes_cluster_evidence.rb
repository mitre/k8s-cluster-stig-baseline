# Keeps evidence tied to the component container instead of unrelated sidecars.
module ::KubernetesClusterEvidence
  module_function

  def component_flags(item, component)
    containers = matching_containers(item, component)
    return [nil, "Expected exactly one #{component} container"] unless containers.length == 1

    tokens = Array(containers.first.command) + Array(containers.first.args)
    return [nil, 'Component command and args must contain only strings'] unless tokens.all? { |token| token.is_a?(String) }

    [parse_flags(tokens), nil]
  end

  def matching_containers(item, component)
    Array(item&.spec&.containers).select do |container|
      container.name == component || File.basename(Array(container.command).first.to_s) == component
    end
  end

  def parse_flags(tokens)
    tokens.each_with_index.each_with_object({}) do |(token, index), flags|
      next unless token.start_with?('--')

      name, value = token.delete_prefix('--').split('=', 2)
      following = tokens[index + 1]
      value ||= following if following && !following.start_with?('-')
      flags[name] = value || ''
    end
  end
end
