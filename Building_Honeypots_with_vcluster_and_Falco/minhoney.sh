#!/bin/bash
set -x #echo on

################# uninstall everything from helm #################
uninstall_helm_releases() {
  echo -e "\e[92mUninstalling all Helm releases\e[0m\n"
  # List all releases across all namespaces
  RELEASES=$(helm ls --all-namespaces --short)
  if [ -n "$RELEASES" ]; then
    # Uninstall each release by specifying its name and namespace
    echo "$RELEASES" | while read -r release; do
      helm uninstall "$release" --namespace "$(helm ls --all-namespaces | grep "$release" | awk '{print $2}')"
    done
  else
    echo -e "\e[92mNo Helm releases found to uninstall\e[0m\n"
  fi
}

################# delete everything from minikube ################# 
delete_minikube() {
  echo -e "\e[92mDeleting and purging everything in minikube\e[0m\n"
  minikube delete --all --purge
}

################# clean up /tmp #################
clean_tmp() {
  echo -e "\e[92mCleaning up /tmp\e[0m\n"
  find /tmp ! -user root -delete
  sudo rm -rf /tmp/juju*
}

################# fire up minikube #################
start_minikube() {
echo -e "\e[92mStarting Minikube\e[0m\n"
minikube start --vm-driver=docker
minikube addons enable ingress
}

################# install falco #################
install_falco() {
echo -e "\e[92mInstalling Falco\e[0m\n"
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
kubectl create namespace falco

helm install falco falcosecurity/falco --namespace falco \
--set tty=true \
--set falcosidekick.enabled=true \
--set falcosidekick.webui.enabled=true \
--set falcosidekick.config.webhook.address="http://falco-talon:2803"
}

################# update the falco rules #################
update_falco_rules() {
echo -e "\e[92mInstalling Falco rule overrides\e[0m\n"
echo "customRules:" > /tmp/customrules.yaml
echo "  override.yaml: |-" >> /tmp/customrules.yaml
echo "    - rule: Redirect STDOUT/STDIN to Network Connection in Container" >> /tmp/customrules.yaml
echo "      enabled: false" >> /tmp/customrules.yaml

helm upgrade falco falcosecurity/falco --namespace falco --values /tmp/customrules.yaml --reuse-values
kubectl delete pods -n falco -l app.kubernetes.io/name=falco
}

################# install falco-talon #################
install_talon() {
echo -e "\e[92mInstalling Talon\e[0m\n"
git clone https://github.com/Issif/falco-talon.git /tmp/falco-talon

helm install falco-talon /tmp/falco-talon/deployment/helm --namespace falco
}

################# update the talon rules #################
update_talon_rules_and_config() {
echo -e "\e[92mUpdating Talon rules and config\e[0m\n"
echo -e '                                                                                                                                                           ' >> /tmp/falco-talon/deployment/helm/rules.yaml
echo -e '- name: Sensitive file opened                                                                                                                                                             ' >> /tmp/falco-talon/deployment/helm/rules.yaml
echo -e '  match:                                                                                                                                                                                  ' >> /tmp/falco-talon/deployment/helm/rules.yaml
echo -e '    rules:                                                                                                                                                                                ' >> /tmp/falco-talon/deployment/helm/rules.yaml
echo -e '      - "Read sensitive file untrusted"                                                                                                                                                   ' >> /tmp/falco-talon/deployment/helm/rules.yaml
echo -e '  action:                                                                                                                                                                                 ' >> /tmp/falco-talon/deployment/helm/rules.yaml
echo -e '    name: kubernetes:terminate ' >> /tmp/falco-talon/deployment/helm/rules.yaml

# Comment the "- slack" line in values.yaml so we don't get an error in the talon logs later
sed -i 's/^\s*-\s*slack/ # - slack/' /tmp/falco-talon/deployment/helm/values.yaml

helm upgrade falco-talon /tmp/falco-talon/deployment/helm --namespace falco

kubectl delete pods -n falco -l app.kubernetes.io/name=falco-talon
}

################# install vcluster #################
install_vcluster() {
echo -e "\e[92mInstalling vcluster\e[0m\n"
LATEST_TAG=$(curl -s -L -o /dev/null -w %{url_effective} "https://github.com/loft-sh/vcluster/releases/latest" | rev | cut -d'/' -f1 | rev)
URL="https://github.com/loft-sh/vcluster/releases/download/${LATEST_TAG}/vcluster-linux-amd64"
curl -L -o vcluster "$URL" && chmod +x vcluster && sudo mv vcluster /usr/local/bin;

vcluster version
}

################# install ssh server in vcluster #################
install_shh_server() {
echo -e "\e[92mInstalling ssh server\e[0m\n"
kubectl create namespace vcluster

vcluster create ssh -n vcluster

kubectl create namespace ssh

helm repo add securecodebox https://charts.securecodebox.io/

helm repo update

helm install my-dummy-ssh securecodebox/dummy-ssh --version 3.4.0 --namespace ssh \
--set global.service.type="nodePort"

vcluster disconnect
}

################# test everything out #################
trigger_falco() {
echo -e "\e[92mTriggering Falco\e[0m\n"
SSH_SERVICE=$(kubectl get svc -l "vcluster.loft.sh/label-ssh-x-9039c53507=my-dummy-ssh" -n vcluster -o jsonpath="{.items[0].metadata.name}")
POD_NAME=$(kubectl get pod -l "vcluster.loft.sh/label-ssh-x-9039c53507=my-dummy-ssh" -n vcluster -o jsonpath="{.items[0].metadata.name}")

kubectl get pods -n vcluster

sleep 30

kubectl port-forward svc/"$SSH_SERVICE" 5555:22 -n vcluster & 
#PORT_FORWARD_PID=$!

sleep 10

sshpass -p "THEPASSWORDYOUCREATED" ssh -o StrictHostKeyChecking=no -p 5555 root@127.0.0.1 "cat /etc/shadow"
}

################# check the logs #################
check_logs() {
echo -e "\e[92mChecking the logs\e[0m\n"

FALCO_POD=$(kubectl get pods -n falco -l app.kubernetes.io/name=falco -o=jsonpath='{.items[*].metadata.name}')

kubectl logs "$FALCO_POD" -n falco

kubectl get pods -n falco -l app.kubernetes.io/name=falco-talon -o=jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | xargs -I {} kubectl logs {} -n falco

kubectl get pods -n vcluster

kubectl get events -n vcluster | grep my-dummy-ssh
}

main() {
  for arg in "$@"; do
    case $arg in
      --burnit)
        uninstall_helm_releases
        delete_minikube
        clean_tmp
        exit 0
        ;;
      --buildit)
        start_minikube
        install_falco
        update_falco_rules
        install_talon
        update_talon_rules_and_config
        install_vcluster
        install_shh_server
        trigger_falco
        check_logs
        #exit 0
        ;;
      *)
        # Unknown option
        ;;
    esac
  done

  echo -e "\e[92mEverything should be done!\e[0m\n"
  kubectl config view -o jsonpath='{.clusters[].name}{"\n"}'
  kubectl get all --all-namespaces
  kubectl get service
}

main "$@"