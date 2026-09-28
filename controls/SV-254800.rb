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
    item = k8sobject(api: 'v1', type: 'pods', namespace: control_plane_namespace, name: pod.name).item
    component = (item&.metadata&.labels&.to_h || {})['component']
    [pod.name, item] if component == 'kube-apiserver' || pod.name.to_s.start_with?('kube-apiserver-')
  end

  if api_server_pods.empty?
    describe 'API Server Pod Security Admission configuration visibility' do
      skip "No kube-apiserver Pod is visible in input('control_plane_namespace')=#{control_plane_namespace}. Run node control SV-254800 on each control-plane node, or obtain equivalent provider evidence for a managed control plane."
    end
  else
    findings = api_server_pods.filter_map do |pod_name, item|
      flags, error = KubernetesClusterEvidence.component_flags(item, 'kube-apiserver')
      next "#{pod_name}: #{error}" if error

      "#{pod_name}: --admission-control-config-file must name an absolute configuration-file path" unless flags['admission-control-config-file'].to_s.start_with?('/')
    end
    describe 'API Server Pod Security Admission configuration-file arguments' do
      it 'has valid paths on the API Server containers' do
        expect(findings).to be_empty, "Invalid API Server configuration arguments:\n- #{findings.join("\n- ")}"
      end
    end
    describe 'Pod security admission configuration-file contents' do
      skip 'Run node control SV-254800 on every control-plane node to inspect the referenced configuration contents; obtain provider evidence where node access is unavailable.'
    end
  end
end
