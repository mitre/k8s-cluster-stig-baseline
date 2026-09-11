control 'SV-254800' do
  title 'Kubernetes must have a Pod Security Admission control file configured.'
  desc 'An admission controller intercepts and processes requests to the Kubernetes API prior to persistence of the object, but after the request is authenticated and authorized.

Kubernetes (> v1.23)offers a built-in Pod Security admission controller to enforce the Pod Security Standards. Pod security restrictions are applied at the namespace level when pods are created.

The Kubernetes Pod Security Standards define different isolation levels for Pods. These standards define how to restrict the behavior of pods in a clear, consistent fashion.'
  desc 'check', 'Change to the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Run the command:

"grep -i admission-control-config-file *"

If the setting "--admission-control-config-file" is not configured in the Kubernetes API Server manifest file, this is a finding.

Inspect the .yaml file defined by the --admission-control-config-file. Verify PodSecurity is properly configured.
If least privilege is not represented, this is a finding.'
  desc 'fix', %q(Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane.

Set the value of "--admission-control-config-file" to a valid path for the file.

Create an admission controller config file:
Example File:
```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
- name: PodSecurity
  configuration:
    apiVersion: pod-security.admission.config.k8s.io/v1beta1
    kind: PodSecurityConfiguration
    # Defaults applied when a mode label is not set.
    defaults:
      enforce: "privileged"
      enforce-version: "latest"
    exemptions:
      # Don't forget to exempt namespaces or users that are responsible for deploying
      # cluster components, because they need to run privileged containers
      usernames: ["admin"]
      namespaces: ["kube-system"]

See for more details:
Migrate from PSP to PSA:
https://kubernetes.io/docs/tasks/configure-pod-container/migrate-from-psp/

Best Practice: https://kubernetes.io/docs/concepts/security/pod-security-policy/#recommended-practice.)
  impact 0.7
  tag check_id: 'C-58411r927123_chk'
  tag severity: 'high'
  tag gid: 'V-254800'
  tag rid: 'SV-254800r961359_rule'
  tag stig_id: 'CNTR-K8-002011'
  tag gtitle: 'SRG-APP-000342-CTR-000775'
  tag fix_id: 'F-58357r927124_fix'
  tag 'documentable'
  tag cci: ['CCI-002263']
  tag nist: ['AC-16 a']

  control_plane_namespace = input('control_plane_namespace')
  api_server_pods = k8sobjects(api: 'v1', type: 'pods', namespace: control_plane_namespace).entries.filter_map do |pod|
    api_server = k8sobject(api: 'v1', type: 'pods', namespace: control_plane_namespace, name: pod.name)
    api_server_item = api_server.item
    component = (api_server_item&.metadata&.labels&.to_h || {})['component']
    [pod.name, api_server] if component == 'kube-apiserver' || pod.name.to_s.start_with?('kube-apiserver-')
  end
  admission_config_findings = []
  admission_config_findings << "No kube-apiserver static Pod is exposed in #{control_plane_namespace}" if api_server_pods.empty?

  api_server_pods.each do |pod_name, api_server|
    arguments = (api_server.item&.spec&.containers || []).flat_map do |container|
      [container.command, container.args].flatten.compact.map(&:to_s)
    end
    admission_config_files = arguments.each_with_index.filter_map do |argument, index|
      if argument == '--admission-control-config-file'
        arguments[index + 1]
      elsif argument.start_with?('--admission-control-config-file=')
        argument.split('=', 2).last
      end
    end

    admission_config_findings << "kube-apiserver Pod #{pod_name} does not set a non-empty --admission-control-config-file" if admission_config_files.none? { |file_name| !file_name.to_s.strip.empty? }
  end

  describe 'Kubernetes API Server Pod Security Admission configuration-file arguments' do
    subject { admission_config_findings }
    it { should be_empty }
  end

  describe 'Pod Security Admission configuration-file contents' do
    skip 'The API Server static-Pod configuration file is host-local; verify its PodSecurity settings with a Control Plane node scan.'
  end
end
