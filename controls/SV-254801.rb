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

  control_plane_namespace = input('control_plane_namespace')
  required_components = Array(input('control_plane_static_pod_components')).map(&:to_s)
  kubernetes_minor_version = k8sversion.minor.to_s[/\d+/].to_i

  if kubernetes_minor_version >= 25
    # Pod Security Admission is stable and enabled by default in Kubernetes 1.25+.
    # The feature-gate argument is therefore not a compliance signal (and the gate
    # is removed in newer releases). PodSecurity can still be explicitly disabled
    # on kube-apiserver with --disable-admission-plugins.
    api_server_pods = k8sobjects(api: 'v1', type: 'pods', namespace: control_plane_namespace).entries.filter_map do |pod|
      api_server = k8sobject(api: 'v1', type: 'pods', namespace: control_plane_namespace, name: pod.name)
      api_server_item = api_server.item
      component = (api_server_item&.metadata&.labels&.to_h || {})['component']
      [pod.name, api_server] if component == 'kube-apiserver' || pod.name.to_s.start_with?('kube-apiserver-')
    end

    if api_server_pods.empty?
      describe 'Kubernetes API Server PodSecurity admission plugin configuration' do
        skip "No kube-apiserver static Pod is exposed in #{control_plane_namespace}; verify that --disable-admission-plugins does not include PodSecurity with a Control Plane node scan."
      end
    else
      disabled_pod_security_plugins = api_server_pods.filter_map do |pod_name, api_server|
        arguments = (api_server.item&.spec&.containers || []).flat_map do |container|
          [container.command, container.args].flatten.compact.map(&:to_s)
        end
        disabled_plugins = arguments.each_with_index.filter_map do |argument, index|
          if argument == '--disable-admission-plugins'
            arguments[index + 1]
          elsif argument.start_with?('--disable-admission-plugins=')
            argument.split('=', 2).last
          end
        end.flat_map { |plugins| plugins.to_s.split(',') }.map(&:strip)

        pod_name if disabled_plugins.any? { |plugin| plugin.casecmp?('PodSecurity') }
      end

      describe 'Kubernetes API Server does not disable the PodSecurity admission plugin' do
        subject { disabled_pod_security_plugins }
        it('has no API Server static Pods that disable PodSecurity') do
          should be_empty, "API Server static Pods that disable PodSecurity:\n\t- #{disabled_pod_security_plugins.join("\n\t- ")}"
        end
      end
    end
  else
    control_plane_pods = k8sobjects(api: 'v1', type: 'pods', namespace: control_plane_namespace).entries
    feature_gate_findings = required_components.each_with_object([]) do |component, findings|
      component_pods = control_plane_pods.filter_map do |pod|
        component_pod = k8sobject(api: 'v1', type: 'pods', namespace: control_plane_namespace, name: pod.name)
        component_pod_item = component_pod.item
        component_label = (component_pod_item&.metadata&.labels&.to_h || {})['component']
        [pod.name, component_pod] if component_label == component || pod.name.to_s.start_with?("#{component}-")
      end

      if component_pods.empty?
        findings << "#{component} static Pod is not exposed in #{control_plane_namespace}"
        next
      end

      component_pods.each do |pod_name, component_pod|
        arguments = (component_pod.item&.spec&.containers || []).flat_map do |container|
          [container.command, container.args].flatten.compact.map(&:to_s)
        end
        feature_gates = arguments.each_with_index.filter_map do |argument, index|
          if argument == '--feature-gates'
            arguments[index + 1]
          elsif argument.start_with?('--feature-gates=')
            argument.split('=', 2).last
          end
        end
        pod_security_enabled = feature_gates.compact.any? do |feature_gate|
          feature_gate.match?(/PodSecurity\s*=\s*true/i)
        end
        findings << "#{component} Pod #{pod_name} does not set PodSecurity=true" unless pod_security_enabled
      end
    end

    describe 'Control Plane static Pods enable the PodSecurity feature gate before Kubernetes 1.25' do
      subject { feature_gate_findings }
      it('has no static Pods without PodSecurity=true') do
        should be_empty, "Static Pods missing PodSecurity=true:\n\t- #{feature_gate_findings.join("\n\t- ")}"
      end
    end

    describe 'Kubelet PodSecurity feature-gate configuration before Kubernetes 1.25' do
      skip 'Kubelet command-line and configuration-file settings are host-local; evaluate them with the k8s-node profile on every Control Plane and Worker Node.'
    end
  end
end
