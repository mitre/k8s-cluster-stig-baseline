control 'SV-242442' do
  title 'Kubernetes must remove old components after updated versions have been
installed.'
  desc 'Previous versions of Kubernetes components that are not removed after
updates have been installed may be exploited by adversaries by allowing the
vulnerabilities to still exist within the cluster. It is important for
Kubernetes to remove old pods when newer pods are created using new images to
always be at the desired security state.'
  desc 'check', %q(To view all pods and the images used to create the pods, from the Control Plane, run the following command:
kubectl get pods --all-namespaces -o jsonpath="{..image}" | \
tr -s '[[:space:]]' '\n' | \
sort | \
uniq -c

Review the images used for pods running within Kubernetes.

If there are multiple versions of the same image, this is a finding.)
  desc 'fix', 'Remove any old pods that are using older images. On the Control Plane, run the command:
kubectl delete pod podname
(Note: "podname" is the name of the pod to delete.)'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000454-CTR-001110'
  tag gid: 'V-242442'
  tag rid: 'SV-242442r1188293_rule'
  tag stig_id: 'CNTR-K8-002700'
  tag fix_id: 'F-45675r863906_fix'
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']

  images = []
  k8sobjects(api: 'v1', type: 'pods').entries.each do |entry|
    pod = k8sobject(api: 'v1', type: 'pods', name: entry.name, namespace: entry.namespace)
    pod_spec = pod.item&.spec
    containers = [pod_spec&.containers, pod_spec&.initContainers, pod_spec&.ephemeralContainers].flat_map do |container_group|
      Array(container_group)
    end
    images.concat(containers.filter_map(&:image))
  end

  # remove duplicate image references
  images = images.flatten.uniq

  # tally up versions by image name
  image_tally = {}
  images.each do |image|
    image_reference, image_digest = image.split('@', 2)
    last_slash = image_reference.rindex('/')
    last_colon = image_reference.rindex(':')
    has_tag = last_colon && (last_slash.nil? || last_colon > last_slash)
    image_name = has_tag ? image_reference[0...last_colon] : image_reference
    image_version = has_tag ? image_reference[(last_colon + 1)..] : 'latest'
    image_version = "#{image_version}@#{image_digest}" unless image_digest.nil?

    if image_tally[image_name]
      image_tally[image_name] << image_version
    else
      image_tally[image_name] = [ image_version ]
    end
  end

  images_with_multiple_versions = image_tally.filter_map do |image_name, versions|
    "#{image_name}: #{versions.sort.join(', ')}" if versions.length > 1
  end

  describe 'Container images running with multiple versions' do
    it 'should be empty' do
      expect(images_with_multiple_versions).to be_empty, "Container images with multiple running versions:\n\t- #{images_with_multiple_versions.join("\n\t- ")}"
    end
  end
end
