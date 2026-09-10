control 'SV-242415' do
  title 'Secrets in Kubernetes must not be stored as environment variables.'
  desc 'Secrets, such as passwords, keys, tokens, and certificates must not be stored as environment variables. These environment variables are accessible inside Kubernetes by the "Get Pod" API call, and by any system, such as CI/CD pipeline, which has access to the definition file of the container. Secrets must be mounted from files or stored within password vaults.'
  desc 'check', 'Follow these steps to check, from the Kubernetes control plane, if secrets are stored as environment variables.

1. Find All Pods Using Secrets in Environment Variables.

To list all pods using secrets as environment variables, execute:

kubectl get pods --all-namespaces -o yaml | grep -A5 "secretKeyRef"

If any of the values returned reference environment variables, this is a finding.

2. Check Environment Variables in a Specific Pod.

To check if a specific pod is using secrets as environment variables, execute:

kubectl get pods -n <namespace>
(Replace <namespace> with the actual namespace, or omit -n <namespace> to check in the default namespace.)
kubectl describe pod <pod-name> -n <namespace> | grep -A5 "Environment:"

If secrets are used, output like the following will be displayed:

Environment:
  SECRET_USERNAME:   <set from secret: my-secret key: username>
  SECRET_PASSWORD:   <set from secret: my-secret key: password>

If the output is similar to this, the pod is using Kubernetes secrets as environment variables, and this is a finding.

3. Check the Pod YAML for Secret Usage.

To check the full YAML definition for environment variables, execute:

kubectl get pod <pod-name> -n <namespace> -o yaml | grep -A5 "env:"

Example output:
yaml
CopyEdit
env:
  - name: SECRET_USERNAME
    valueFrom:
      secretKeyRef:
        name: my-secret
        key: username

This means the pod is pulling the secret named my-secret and setting SECRET_USERNAME from its username key.

If the pod is pulling a secret and setting an environment variable in the "env:", this is a finding.

4. Check Secrets in a Deployment, StatefulSet, or DaemonSet.

If the pod is managed by a Deployment, StatefulSet, or DaemonSet, check their configurations:

kubectl get deployment <deployment-name> -n <namespace> -o yaml | grep -A5 "env:"

or

For all Deployments in all namespaces:

kubectl get deployments --all-namespaces -o yaml | grep -A5 "env:"

If the pod is pulling a secret and setting an environment variable in the "env:", this is a finding.

5. Check Environment Variables Inside a Running Pod.

If needed, check the environment variables inside a running pod:

kubectl exec -it <pod-name> -n <namespace> -- env | grep SECRET

If any of the values returned reference environment variables, this is a finding.'
  desc 'fix', 'Any secrets stored as environment variables must be moved to
the secret files with the proper protections and enforcements or placed within
a password vault.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000171-CTR-000435'
  tag gid: 'V-242415'
  tag rid: 'SV-242415r1069466_rule'
  tag stig_id: 'CNTR-K8-001160'
  tag fix_id: 'F-45648r712600_fix'
  tag cci: ['CCI-000196', 'CCI-004062']
  tag nist: ['IA-5 (1) (c)', 'IA-5 (1) (d)']

  secret_environment_variables = []
  inspect_pod_spec = lambda do |workload, pod_spec|
    containers = [pod_spec&.containers, pod_spec&.initContainers, pod_spec&.ephemeralContainers].flat_map do |container_group|
      Array(container_group)
    end

    containers.each do |container|
      Array(container.env).each do |environment_variable|
        secret_name = environment_variable.valueFrom&.secretKeyRef&.name
        next if secret_name.to_s.empty?

        secret_environment_variables << "#{workload} container #{container.name} environment variable #{environment_variable.name} references Secret/#{secret_name}"
      end

      Array(container.envFrom).each do |environment_source|
        secret_name = environment_source.secretRef&.name
        next if secret_name.to_s.empty?

        secret_environment_variables << "#{workload} container #{container.name} envFrom references Secret/#{secret_name}"
      end
    end
  end

  k8sobjects(api: 'v1', type: 'pods').entries.each do |entry|
    pod = k8sobject(api: 'v1', type: 'pods', name: entry.name, namespace: entry.namespace)
    inspect_pod_spec.call("Pod/#{entry.namespace}/#{entry.name}", pod.item&.spec)
  end

  { 'deployments' => 'Deployment', 'statefulsets' => 'StatefulSet', 'daemonsets' => 'DaemonSet' }.each do |workload_type, workload_kind|
    k8sobjects(api: 'apps/v1', type: workload_type).entries.each do |entry|
      workload = k8sobject(api: 'apps/v1', type: workload_type, name: entry.name, namespace: entry.namespace)
      inspect_pod_spec.call("#{workload_kind}/#{entry.namespace}/#{entry.name}", workload.item&.spec&.template&.spec)
    end
  end

  describe 'Pods that expose Kubernetes Secrets as environment variables' do
    subject { secret_environment_variables }
    it { should be_empty }
  end
end
