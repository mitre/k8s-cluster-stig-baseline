# Keeps evidence tied to the component container instead of unrelated sidecars.
#
# Records come from k8sobjects#entries. K8s::Resource is a RecursiveOpenStruct and
# build_record_from stores obj.to_h, which is a deep plain Hash with symbol keys,
# so nested values are Hashes and are not method-accessible.
module ::KubernetesClusterEvidence
  module_function

  def all_containers(record)
    %i[containers initContainers ephemeralContainers].flat_map do |group|
      Array(record.dig(:spec, group))
    end
  end

  def api_server_pods(records)
    component_pods(records, 'kube-apiserver')
  end

  def component_pods(records, component)
    records.select do |record|
      (record[:labels] || {})[:component].to_s == component ||
        record[:name].to_s.start_with?("#{component}-")
    end
  end

  def component_flags(record, component)
    containers = matching_containers(record, component)
    return [nil, "Expected exactly one #{component} container"] unless containers.length == 1

    tokens = Array(containers.first[:command]) + Array(containers.first[:args])
    return [nil, 'Component command and args must contain only strings'] unless tokens.all? { |token| token.is_a?(String) }

    [parse_flags(tokens), nil]
  end

  def matching_containers(record, component)
    Array(record.dig(:spec, :containers)).select do |container|
      container[:name] == component || File.basename(Array(container[:command]).first.to_s) == component
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
