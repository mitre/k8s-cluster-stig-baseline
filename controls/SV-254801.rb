require 'kubernetes_cluster_evidence'
require 'kubernetes_cluster_inputs'

control 'SV-254801' do
  title 'Kubernetes must enable PodSecurity admission controller on static pods and Kubelets.'
  desc 'PodSecurity admission controller is a component that validates and enforces security policies for pods running within a Kubernetes cluster. It is responsible for evaluating the security context and configuration of pods against defined policies.

To enable PodSecurity admission controller on Static Pods (kube-apiserver, kube-controller-manager, or kube-schedule), the argument "--feature-gates=PodSecurity=true" must be set.

To enable PodSecurity admission controller on Kubelets, the featureGates PodSecurity=true argument must be set.

(Note: The PodSecurity feature gate is GA as of  v1.25.)'
  desc 'check', %q(On the Control Plane, change to the manifests' directory at /etc/kubernetes/manifests and run the command:
grep -i feature-gates *

For each manifest file, if the "--feature-gates" setting does not exist, does not contain the "--PodSecurity" flag, or sets the flag to "false", this is a finding.

On each Control Plane and Worker Node, run the command:
ps -ef | grep kubelet

If the "--feature-gates" option exists, this is a finding.

Note the path to the config file (identified by --config).

Inspect the content of the config file:
If the "featureGates" setting is not present, does not contain the "PodSecurity" flag, or sets the flag to "false", this is a finding.)
  desc 'fix', %q(On the Control Plane, change to the manifests' directory at /etc/kubernetes/manifests and run the command:
grep -i feature-gates *

Ensure the argument "--feature-gates=PodSecurity=true" is present in each manifest file.

On each Control Plane and Worker Node, run the command:
ps -ef | grep kubelet

Remove the "--feature-gates" option if present.

Note the path to the config file (identified by --config).

Edit the Kubernetes Kubelet config file:
Add a "featureGates" setting if one does not yet exist. Add the feature gate "PodSecurity=true".

Restart the kubelet service using the following command:
systemctl daemon-reload && systemctl restart kubelet)
  impact 0.7
  tag check_id: 'C-58412r918278_chk'
  tag severity: 'high'
  tag gid: 'V-254801'
  tag rid: 'SV-254801r961359_rule'
  tag stig_id: 'CNTR-K8-002001'
  tag gtitle: 'SRG-APP-000342-CTR-000775'
  tag fix_id: 'F-58358r918213_fix'
  tag 'documentable'
  tag cci: ['CCI-002263']
  tag nist: ['AC-16 a']

  control_plane_namespace = KubernetesClusterInputs.value('control_plane_namespace', input('control_plane_namespace'))
  required_components = KubernetesClusterInputs.value('control_plane_static_pod_components', input('control_plane_static_pod_components'))
  minor_version = k8sversion.minor.to_s.to_i
  components = minor_version < 25 ? required_components : ['kube-apiserver']
  pods = k8sobjects(api: 'v1', type: 'pods', namespace: control_plane_namespace).entries

  components.each do |component|
    component_pods = pods.filter_map do |pod|
      item = k8sobject(api: 'v1', type: 'pods', namespace: control_plane_namespace, name: pod.name).item
      label = (item&.metadata&.labels&.to_h || {})['component']
      [pod.name, item] if label == component || pod.name.to_s.start_with?("#{component}-")
    end
    if component_pods.empty?
      describe "#{component} PodSecurity configuration visibility" do
        skip "No #{component} Pod is visible in input('control_plane_namespace')=#{control_plane_namespace}; run node control SV-254801 or obtain equivalent provider evidence."
      end
      next
    end

    findings = component_pods.filter_map do |pod_name, item|
      flags, error = KubernetesClusterEvidence.component_flags(item, component)
      next "#{pod_name}: #{error}" if error

      if minor_version < 25
        gates = flags['feature-gates'].to_s.split(',').map(&:strip)
        "#{pod_name}: PodSecurity must be true" unless gates.include?('PodSecurity=true') && !gates.include?('PodSecurity=false')
      elsif flags.key?('disable-admission-plugins')
        disabled = flags['disable-admission-plugins']
        "#{pod_name}: invalid argument or PodSecurity explicitly disabled" if disabled.to_s.empty? || disabled.split(',').map(&:strip).include?('PodSecurity')
      end
    end
    describe "#{component} enables PodSecurity admission" do
      it 'has no disabled or missing required PodSecurity settings' do
        expect(findings).to be_empty, "PodSecurity findings:\n- #{findings.join("\n- ")}"
      end
    end
  end

  if minor_version < 25
    describe 'Kubelet PodSecurity configuration before Kubernetes 1.25' do
      skip 'Run node control SV-254801 on every control-plane and worker node to check kubelet arguments and featureGates.PodSecurity in its configuration file.'
    end
  end
end
