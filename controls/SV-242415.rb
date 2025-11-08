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
  desc 'fix', 'Any secrets stored as environment variables must be moved to the secret files with the proper protections and enforcements or placed within a password vault.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000171-CTR-000435'
  tag gid: 'V-242415'
  tag rid: 'SV-242415r1069466_rule'
  tag stig_id: 'CNTR-K8-001160'
  tag fix_id: 'F-45648r712600_fix'
  tag cci: ['CCI-000196', 'CCI-004062']
  tag nist: ['IA-5 (1) (c)', 'IA-5 (1) (d)']

  k8sobjects(api: 'v1', type: 'pods').entries.each do |entry|
    describe k8sobject(api: 'v1', type: 'pods', name: entry.name, namespace: entry.namespace) do
      its('k8sobject.spec.to_s') { should_not match 'secretKeyRef' }
    end
  end

  if k8sobjects(api: 'v1', type: 'pods').entries.empty?
    describe 'No pods found in the cluster' do
      skip
    end
  end
end
