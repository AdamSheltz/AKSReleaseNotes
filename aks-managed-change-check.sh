#!/usr/bin/env bash
#
# aks-managed-change-check.sh
#
# Determines whether any AKS-managed component on a specific cluster has changed
# (upgraded, patched, re-imaged, added/removed or reconfigured): control plane,
# node pools / node images, add-ons and the system workloads AKS deploys into
# managed namespaces (kube-system, calico-system, gatekeeper-system, ...).
#
# It combines three independent signals:
#   1. ARM view            Cluster + pool versions, upgrade channels, add-ons,
#                          maintenance configs, and Activity Log operations.
#   2. In-cluster history  ReplicaSet / ControllerRevision history of every managed
#                          workload. Each rollout leaves a timestamped revision, so
#                          upgrades are detectable WITHOUT a prior baseline.
#   3. Snapshot diff       Save a full fingerprint now (--save) and compare later
#                          (--compare / --diff). Catches everything, including changes
#                          older than retained revision history.
#
# Requirements: bash 4+, az CLI (logged in), kubectl, jq. kubelogin for AAD clusters.
#
# Exit codes: 0 = no changes detected, 10 = changes detected, 1 = error.

set -uo pipefail

TOOL_VERSION="2.0.0"
RG=""; CLUSTER=""; SUB=""; SINCE="7d"
SAVE_FILE=""; COMPARE_FILE=""; DIFF_A=""; DIFF_B=""
KCTX=""; USE_ADMIN=false; SKIP_ARM=false; SKIP_K8S=false; SHOW_ALL=false
VERBOSE=false; DESCRIBE=false; FEEDS_FILE=""; LIST_FEEDS=false
NAMESPACES="kube-system,calico-system,tigera-operator,gatekeeper-system,app-routing-system,aks-istio-system,aks-istio-ingress,aks-istio-egress,flux-system,dapr-system"

usage() {
cat <<USAGE
aks-managed-change-check.sh v${TOOL_VERSION}

Detect whether any AKS-managed component on a cluster has been upgraded or changed.

Usage:
  $0 -g <resource-group> -n <cluster> [options]
  $0 --diff <old-snapshot.json> <new-snapshot.json>

Required (live mode):
  -g, --resource-group   Resource group of the AKS cluster
  -n, --name             AKS cluster name

Options:
  -s, --subscription     Subscription ID or name (default: current az context)
      --since <N[d|h|m]> Look-back window for "recent change" detection (default: 7d)
      --save <file>      Save a snapshot (fingerprint) of all managed components
      --compare <file>   Compare current state against a previously saved snapshot
      --diff <a> <b>     Offline: compare two saved snapshots (no cluster access)
      --context <name>   Use an existing kubectl context instead of fetching credentials
      --admin            Fetch admin credentials (az aks get-credentials --admin)
      --namespaces <csv> Managed namespaces to inspect (default: ${NAMESPACES})
      --skip-arm         Skip ARM / Activity Log checks
      --skip-k8s         Skip in-cluster checks (ARM only; works for private clusters)
      --all              Print full revision history, not only changes inside the window
      --verbose          Parsed evidence for only the components flagged as changed
      --describe         --verbose plus raw kubectl describe output and targeted events
      --feeds <file>     Merge a JSON feed catalog with the built-in catalog
      --list-feeds       Print the effective feed catalog and exit (no cluster required)
  -h, --help             Show this help

Examples:
  $0 -g myRG -n myAKS                          # what changed in the last 7 days?
  $0 -g myRG -n myAKS --since 30d --all        # full history, flag last 30 days
  $0 -g myRG -n myAKS --save baseline.json     # take a baseline
  $0 -g myRG -n myAKS --compare baseline.json  # anything changed since the baseline?
  $0 -g myRG -n myAKS --since 7d --verbose     # parsed evidence for flagged components
  $0 -g myRG -n myAKS --since 7d --describe    # parsed evidence + raw describe/events
  $0 -g myRG -n myAKS --feeds extra-feeds.json # merge future components/repositories
  $0 --list-feeds                              # inspect the effective feed catalog
  $0 --diff before.json after.json             # offline comparison

Feed file schema (JSON array; category+component is the merge key):
  [{"category":"Networking","component":"Example","repo":"owner/repo",
    "signals":["workload"],
    "match":{"workload":"example","image":"example"}}]
USAGE
}

# ---------- output helpers ----------
if [[ -t 1 ]]; then B=$'\e[1m'; R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; C=$'\e[36m'; N=$'\e[0m'
else B=""; R=""; G=""; Y=""; C=""; N=""; fi
section() { printf '\n%s== %s ==%s\n' "$B$C" "$1" "$N"; }
info()    { printf '%s\n' "$*"; }
warn()    { printf '%sWARN:%s %s\n' "$Y" "$N" "$*" >&2; }
die()     { printf '%sERROR:%s %s\n' "$R" "$N" "$*" >&2; exit 1; }
tabulate() { if command -v column >/dev/null 2>&1; then column -t -s $'\t'; else cat; fi; }
need()    { command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not found in PATH"; }

FINDINGS=()
finding() { FINDINGS+=("$1"); }

# ---------- argument parsing ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -g|--resource-group) RG="${2:-}"; shift 2 || die "Missing value for option" ;;
    -n|--name)           CLUSTER="${2:-}"; shift 2 || die "Missing value for option" ;;
    -s|--subscription)   SUB="${2:-}"; shift 2 || die "Missing value for option" ;;
    --since)             SINCE="${2:-}"; shift 2 || die "Missing value for option" ;;
    --save)              SAVE_FILE="${2:-}"; shift 2 || die "Missing value for option" ;;
    --compare)           COMPARE_FILE="${2:-}"; shift 2 || die "Missing value for option" ;;
    --diff)              DIFF_A="${2:-}"; DIFF_B="${3:-}"; shift 3 || die "--diff needs two snapshot files" ;;
    --context)           KCTX="${2:-}"; shift 2 || die "Missing value for option" ;;
    --admin)             USE_ADMIN=true; shift ;;
    --namespaces)        NAMESPACES="${2:-}"; shift 2 || die "Missing value for option" ;;
    --skip-arm)          SKIP_ARM=true; shift ;;
    --skip-k8s)          SKIP_K8S=true; shift ;;
    --all)               SHOW_ALL=true; shift ;;
    --verbose)           VERBOSE=true; shift ;;
    --describe)          DESCRIBE=true; VERBOSE=true; shift ;;
    --feeds)             FEEDS_FILE="${2:-}"; shift 2 || die "Missing value for option" ;;
    --list-feeds)        LIST_FEEDS=true; shift ;;
    -h|--help)           usage; exit 0 ;;
    *) usage; die "Unknown argument: $1" ;;
  esac
done

need jq

# ---------- feed catalog ----------
# A feed identifies the upstream/public release source used for correlation. It does
# not assert that an AKS cluster is running the latest upstream release.  "signals"
# describes how this script can observe a component: release context, ARM/control
# plane, node state, or an in-cluster workload. Add future entries with --feeds.
write_default_feeds() {
  cat > "$1" <<'JSON'
[
  {"category":"AKS","component":"AKS release notes","repo":"Azure/AKS","signals":["release"]},
  {"category":"AKS","component":"Node images (AgentBaker)","repo":"Azure/AgentBaker","signals":["node"]},
  {"category":"Storage","component":"Azure Disk CSI","repo":"kubernetes-sigs/azuredisk-csi-driver","signals":["workload","arm:storage.diskCSIDriver"],"match":{"workload":"azuredisk|disk-csi","image":"azuredisk|disk-csi"}},
  {"category":"Storage","component":"Azure Files CSI","repo":"kubernetes-sigs/azurefile-csi-driver","signals":["workload","arm:storage.fileCSIDriver"],"match":{"workload":"azurefile|file-csi","image":"azurefile|file-csi"}},
  {"category":"Storage","component":"Azure Blob CSI","repo":"kubernetes-sigs/blob-csi-driver","signals":["workload","arm:storage.blobCSIDriver"],"match":{"workload":"blob-csi|blobfuse","image":"blob-csi|blobfuse"}},
  {"category":"Storage","component":"Secrets Store CSI","repo":"kubernetes-sigs/secrets-store-csi-driver","signals":["workload"],"match":{"workload":"secrets-store-csi-driver","image":"secrets-store-csi-driver($|[:@/])|/secrets-store-csi-driver"}},
  {"category":"Storage","component":"Key Vault provider","repo":"Azure/secrets-store-csi-driver-provider-azure","signals":["workload"],"match":{"workload":"secrets-store-provider-azure|provider-azure","image":"provider-azure|secrets-store-csi-driver-provider-azure"}},
  {"category":"Storage","component":"CSI external-snapshotter","repo":"kubernetes-csi/external-snapshotter","signals":["workload","arm:storage.snapshotController"],"match":{"workload":"snapshot-controller|csi-snapshotter","image":"snapshot-controller|csi-snapshotter"}},
  {"category":"Networking","component":"Cilium","repo":"cilium/cilium","signals":["workload","arm:network.cilium"],"match":{"workload":"cilium","image":"cilium"}},
  {"category":"Networking","component":"Azure CNI / CNS / NPM","repo":"Azure/azure-container-networking","signals":["workload","arm:network.azureCni"],"match":{"workload":"azure-cni|azure-npm|azure-network|cns","image":"azure-cni|azure-npm|azure-container-networking|/cns"}},
  {"category":"Networking","component":"Calico","repo":"projectcalico/calico","signals":["workload","arm:network.calico"],"match":{"workload":"calico|tigera","image":"calico|tigera"}},
  {"category":"Networking","component":"CoreDNS","repo":"coredns/coredns","signals":["workload"],"match":{"workload":"coredns|kube-dns","image":"coredns"}},
  {"category":"Networking","component":"Konnectivity","repo":"kubernetes-sigs/apiserver-network-proxy","signals":["workload"],"match":{"workload":"konnectivity","image":"konnectivity|apiserver-network-proxy"}},
  {"category":"Networking","component":"ip-masq-agent-v2","repo":"Azure/ip-masq-agent-v2","signals":["workload"],"match":{"workload":"ip-masq-agent","image":"ip-masq-agent"}},
  {"category":"Networking","component":"Retina (ACNS)","repo":"microsoft/retina","signals":["workload"],"match":{"workload":"retina|acns|network-observability","image":"retina|acns|network-observability"}},
  {"category":"Networking","component":"Istio","repo":"istio/istio","signals":["workload","arm:serviceMesh.istio"],"match":{"workload":"istio|asm-","image":"istio|oss/istio"}},
  {"category":"Control plane & add-ons","component":"cloud-provider-azure","repo":"kubernetes-sigs/cloud-provider-azure","signals":["workload"],"match":{"workload":"cloud-node-manager|cloud-controller-manager|azure-cloud","image":"cloud-node-manager|cloud-controller-manager|cloud-provider-azure"}},
  {"category":"Control plane & add-ons","component":"Kubernetes","repo":"kubernetes/kubernetes","signals":["controlPlane","workload"],"match":{"workload":"kube-proxy","image":"kube-proxy"}},
  {"category":"Control plane & add-ons","component":"metrics-server","repo":"kubernetes-sigs/metrics-server","signals":["workload"],"match":{"workload":"metrics-server","image":"metrics-server"}},
  {"category":"Control plane & add-ons","component":"Workload Identity","repo":"Azure/azure-workload-identity","signals":["workload","arm:workloadIdentity"],"match":{"workload":"workload-identity|azure-wi-webhook","image":"workload-identity|azure-wi-webhook"}},
  {"category":"Control plane & add-ons","component":"KEDA","repo":"kedacore/keda","signals":["workload","arm:keda"],"match":{"workload":"keda","image":"keda"}},
  {"category":"Control plane & add-ons","component":"Gatekeeper (Azure Policy)","repo":"open-policy-agent/gatekeeper","signals":["workload","arm:azurePolicy"],"match":{"workload":"gatekeeper|azure-policy","image":"gatekeeper|azure-policy"}}
]
JSON
}

load_feeds() {
  write_default_feeds "$WORK/default-feeds.json"
  if [[ -n "$FEEDS_FILE" ]]; then
    [[ -f "$FEEDS_FILE" ]] || die "Feed catalog not found: $FEEDS_FILE"
    jq -e 'type == "array" and all(.[];
      (.category | type == "string" and length > 0) and
      (.component | type == "string" and length > 0) and
      (.repo | type == "string" and test("^[^/]+/[^/]+$")) and
      ((.signals // ["workload"]) | type == "array") and
      ((.match // {}) | type == "object"))' "$FEEDS_FILE" >/dev/null       || die "Invalid --feeds file. Expected the JSON array schema shown in --help."
    jq -s '
      reduce (.[0] + .[1])[] as $f ({};
        .[($f.category + "|" + $f.component)] =
          ($f | .signals = (.signals // ["workload"]) | .match = (.match // {})))
      | [.[]] | sort_by(.category, .component)'       "$WORK/default-feeds.json" "$FEEDS_FILE" > "$WORK/feeds.json"       || die "Could not merge feed catalog"
  else
    cp "$WORK/default-feeds.json" "$WORK/feeds.json"
  fi
}

# ---------- snapshot diff (shared by --compare and --diff) ----------
# Flattens both snapshots to path=value pairs (arrays kept as one value), ignoring
# metadata, feed-catalog provenance, and the per-node list. Feed additions must not
# look like cluster changes; underlying ARM/workload/node-pool signals are compared.
diff_snapshots() {
  local a="$1" b="$2"
  [[ -f "$a" ]] || die "Snapshot not found: $a"
  [[ -f "$b" ]] || die "Snapshot not found: $b"
  jq -n --slurpfile a "$a" --slurpfile b "$b" '
    def flat:
      [ paths(type != "object") as $p
        | select($p | all(.[]; type == "string"))
        | { key: ($p | join(".")),
            value: (getpath($p) | if type == "array"
                                   then map(if type == "string" then . else tojson end) | join(", ")
                                   else tostring end) } ]
      | from_entries;
    ($a[0] | del(.meta, .nodes, .feedCatalog, .componentInventory) | flat) as $x
    | ($b[0] | del(.meta, .nodes, .feedCatalog, .componentInventory) | flat) as $y
    | ([$x, $y] | map(keys) | add | unique) as $k
    | [ $k[] as $key
        | select($x[$key] != $y[$key])
        | { path: $key,
            change: (if $x[$key] == null then "ADDED" elif $y[$key] == null then "REMOVED" else "CHANGED" end),
            before: ($x[$key] // ""), after: ($y[$key] // "") } ]' > "${WORK}/diff.json" || die "Failed to diff snapshots"

  local n; n=$(jq 'length' "${WORK}/diff.json")
  info "Baseline : $a (captured $(jq -r '.meta.capturedAt // "?"' "$a"))"
  info "Current  : $b (captured $(jq -r '.meta.capturedAt // "?"' "$b"))"
  if [[ "$n" -eq 0 ]]; then
    info "${G}No differences in any tracked managed component.${N}"
  else
    jq -r '.[] |
      if .change == "CHANGED" then "  CHANGED  \(.path)\n           before: \(.before)\n           after : \(.after)"
      elif .change == "ADDED" then "  ADDED    \(.path) = \(.after)"
      else "  REMOVED  \(.path) (was: \(.before))" end' "${WORK}/diff.json"
    finding "Snapshot comparison: ${n} managed-component difference(s) since baseline"
  fi
}

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
load_feeds

if $LIST_FEEDS; then
  section "Effective component feed catalog"
  jq -r '(["CATEGORY","COMPONENT","OWNER/REPO","SIGNALS"] | @tsv),
         (.[] | [.category,.component,.repo,(.signals | join(","))] | @tsv)' "$WORK/feeds.json" | tabulate
  exit 0
fi

if [[ -n "$DIFF_A" ]]; then
  [[ -n "$DIFF_B" ]] || die "--diff needs two snapshot files"
  section "Snapshot diff"
  diff_snapshots "$DIFF_A" "$DIFF_B"
  section "Verdict"
  if [[ ${#FINDINGS[@]} -gt 0 ]]; then info "${R}${B}CHANGES DETECTED${N}"; exit 10; fi
  info "${G}${B}NO CHANGES DETECTED${N}"; exit 0
fi

[[ -n "$RG" && -n "$CLUSTER" ]] || { usage; die "-g and -n are required"; }

# ---------- look-back window ----------
if [[ "$SINCE" =~ ^([0-9]+)([dhm])$ ]]; then
  n="${BASH_REMATCH[1]}"
  case "${BASH_REMATCH[2]}" in d) SECS=$((n*86400));; h) SECS=$((n*3600));; m) SECS=$((n*60));; esac
else
  die "--since must look like 7d, 12h or 90m"
fi
NOW_EPOCH="$(date -u +%s)"
CUTOFF=$((NOW_EPOCH - SECS))
CUTOFF_ISO="$(jq -rn --argjson e "$CUTOFF" '$e | todate')"
# Activity Log retention is 90 days; offset format is ##d##h (minimum 1h)
AL_SECS=$(( SECS > 7776000 ? 7776000 : SECS ))
AL_D=$((AL_SECS/86400)); AL_H=$(((AL_SECS%86400)/3600)); [[ $AL_D -eq 0 && $AL_H -eq 0 ]] && AL_H=1
AL_OFFSET="${AL_D}d${AL_H}h"

SUBARG=(); [[ -n "$SUB" ]] && SUBARG=(--subscription "$SUB")

# Default (empty) data so every later step works even when a source is skipped
echo '{}'          > "$WORK/aks.json"
echo '[]'          > "$WORK/mc.json"
echo '[]'          > "$WORK/activity.json"
echo '{}'          > "$WORK/version.json"
echo '{"items":[]}' > "$WORK/nodes.json"
echo '{"items":[]}' > "$WORK/objs.json"
echo '{"items":[]}' > "$WORK/pods.json"
echo '[]'          > "$WORK/podstate.json"
echo '[]'          > "$WORK/component-inventory.json"

info "${B}AKS managed component change check${N}  v${TOOL_VERSION}"
info "Cluster: ${CLUSTER}   Resource group: ${RG}   Window: last ${SINCE} (since ${CUTOFF_ISO})"

# =====================================================================
# 1. ARM VIEW
# =====================================================================
if ! $SKIP_ARM; then
  need az
  section "1. Azure Resource Manager view"
  az aks show -g "$RG" -n "$CLUSTER" ${SUBARG[@]+"${SUBARG[@]}"} -o json > "$WORK/aks.json" \
    || die "az aks show failed (check login, subscription, RG and cluster name)"
  az aks maintenanceconfiguration list -g "$RG" --cluster-name "$CLUSTER" ${SUBARG[@]+"${SUBARG[@]}"} -o json \
    > "$WORK/mc.json" 2>/dev/null || { echo '[]' > "$WORK/mc.json"; warn "Could not read maintenance configurations"; }

  jq -r '
    "Location / tier       : \(.location) / \(.sku.tier // "n/a")",
    "Provisioning state    : \(.provisioningState)   (power: \(.powerState.code // "n/a"))",
    "Kubernetes version    : target=\(.kubernetesVersion)  current=\(.currentKubernetesVersion // "n/a")",
    "Auto-upgrade channel  : \(.autoUpgradeProfile.upgradeChannel // "none")",
    "Node OS upgrade chan. : \(.autoUpgradeProfile.nodeOsUpgradeChannel // "n/a")",
    "Network               : plugin=\(.networkProfile.networkPlugin // "-") mode=\(.networkProfile.networkPluginMode // "-") dataplane=\(.networkProfile.networkDataplane // "-") policy=\(.networkProfile.networkPolicy // "-")",
    "",
    "Node pools:",
    (.agentPoolProfiles[]? |
      "  \(.name)  k8s=\(.orchestratorVersion) (current \(.currentOrchestratorVersion // "-"))  nodeImage=\(.nodeImageVersion // "-")  os=\(.osSku // .osType)  state=\(.provisioningState)"),
    "",
    "Add-ons enabled:",
    ((.addonProfiles // {}) | to_entries[] | select(.value.enabled == true) | "  \(.key)"),
    (if .serviceMeshProfile.istio.revisions then "  istio (revisions: \(.serviceMeshProfile.istio.revisions | join(", ")))" else empty end),
    (if .ingressProfile.webAppRouting.enabled then "  webAppRouting" else empty end),
    (if .workloadAutoScalerProfile.keda.enabled then "  keda" else empty end),
    (if .workloadAutoScalerProfile.verticalPodAutoscaler.enabled then "  vpa" else empty end),
    (if .azureMonitorProfile.metrics.enabled then "  azureMonitor metrics" else empty end)
  ' "$WORK/aks.json"

  info ""
  info "Maintenance configurations:"
  jq -r 'if length == 0 then "  (none)" else .[] | "  \(.name)" end' "$WORK/mc.json"

  # In-progress / mismatch signals
  while IFS= read -r f; do [[ -n "$f" ]] && finding "$f"; done < <(jq -r '
    (if .provisioningState != "Succeeded" then "Cluster provisioningState is \(.provisioningState) (operation in progress or failed)" else empty end),
    (if (.currentKubernetesVersion // .kubernetesVersion) != .kubernetesVersion
       then "Control plane version mismatch: target \(.kubernetesVersion) vs current \(.currentKubernetesVersion)" else empty end),
    (.agentPoolProfiles[]? |
      (if .provisioningState != "Succeeded" then "Node pool \(.name) provisioningState is \(.provisioningState)" else empty end),
      (if (.currentOrchestratorVersion // .orchestratorVersion) != .orchestratorVersion
         then "Node pool \(.name) version mismatch: target \(.orchestratorVersion) vs current \(.currentOrchestratorVersion)" else empty end))
  ' "$WORK/aks.json")

  section "1b. Activity Log - ContainerService operations on this cluster (last ${AL_OFFSET})"
  az monitor activity-log list -g "$RG" --offset "$AL_OFFSET" --max-events 5000 ${SUBARG[@]+"${SUBARG[@]}"} -o json \
    > "$WORK/activity.json" 2>/dev/null || { echo '[]' > "$WORK/activity.json"; warn "Could not read Activity Log"; }

  CL_LC="$(printf '%s' "$CLUSTER" | tr '[:upper:]' '[:lower:]')"
  jq --arg c "$CL_LC" '
    [ .[]
      | select((.resourceId // "" | ascii_downcase) | test("/providers/microsoft.containerservice/managedclusters/" + $c + "($|/)"))
      | select((.status.value // "") | IN("Succeeded", "Failed", "Canceled"))
      | select((.operationName.value // "") | test("read|listcredential"; "i") | not)
      | { t: .eventTimestamp, op: .operationName.value, st: .status.value,
          caller: (.caller // "-"), res: (.resourceId | split("/") | .[-1]) } ]
    | sort_by(.t)' "$WORK/activity.json" > "$WORK/al.json"
  AL_COUNT="$(jq 'length' "$WORK/al.json")"
  if [[ "$AL_COUNT" -eq 0 ]]; then
    info "  No completed write/upgrade operations found."
  else
    jq -r '.[] | "  \(.t[0:19])Z  \(.st)\t\(.op)\t\(.res)\tcaller=\(.caller)"' "$WORK/al.json"
    finding "Activity Log: ${AL_COUNT} completed ContainerService write/upgrade operation(s) in the last ${AL_OFFSET}"
  fi
  info "  Note: AKS-initiated rollouts of system components do not always surface here; see section 2."
fi

# =====================================================================
# 2. IN-CLUSTER VIEW
# =====================================================================
if ! $SKIP_K8S; then
  need kubectl
  KARGS=()
  if [[ -n "$KCTX" ]]; then
    KARGS=(--context "$KCTX")
  else
    need az
    ADMIN=(); $USE_ADMIN && ADMIN=(--admin)
    az aks get-credentials -g "$RG" -n "$CLUSTER" --file "$WORK/kubeconfig" --overwrite-existing \
      ${ADMIN[@]+"${ADMIN[@]}"} ${SUBARG[@]+"${SUBARG[@]}"} >/dev/null 2>&1 \
      || die "az aks get-credentials failed (private cluster? use --context from a jumpbox, or --skip-k8s)"
    if grep -q kubelogin "$WORK/kubeconfig" 2>/dev/null && command -v kubelogin >/dev/null 2>&1; then
      kubelogin convert-kubeconfig -l azurecli --kubeconfig "$WORK/kubeconfig" >/dev/null 2>&1 || true
    fi
    KARGS=(--kubeconfig "$WORK/kubeconfig")
  fi
  k() { kubectl "${KARGS[@]}" "$@"; }

  catalog_matches() {
    local key="$1" images="$2"
    jq -r --arg key "$key" --arg images "$images" '
      [ .[] as $f
        | select(
            (($f.match.workload // "") as $r | ($r != "" and ($key | test($r; "i")))) or
            (($f.match.image // "") as $r | ($r != "" and ($images | test($r; "i")))))
        | "\($f.category)	\($f.component)	\($f.repo)" ]
      | unique[]?' "$WORK/feeds.json"
  }

  verbose_component_details() {
    local ns="$1" kind="$2" name="$3" change_type="$4"
    local key="$ns/$kind/$name" obj="$WORK/verbose-object.json"
    section "FLAGGED COMPONENT: $key [$change_type]"

    if ! k get "$kind" "$name" -n "$ns" -o json > "$obj" 2>/dev/null; then
      warn "Could not retrieve current object for $key (it may have been removed)"
      return
    fi

    local images
    images="$(jq -r '[((.spec.template.spec.initContainers // []) + (.spec.template.spec.containers // []))[].image] | join(" ")' "$obj")"
    while IFS=$'\t' read -r category component repo; do
      [[ -n "$component" ]] || continue
      info "Feed correlation       : $category / $component -> $repo"
    done < <(catalog_matches "$key" "$images")

    jq -r '
      "Generation             : \(.metadata.generation // "-") (observed \(.status.observedGeneration // "-"))",
      "Replicas               : desired=\(.spec.replicas // "-") updated=\(.status.updatedReplicas // "-") ready=\(.status.readyReplicas // "-") available=\(.status.availableReplicas // "-")",
      "Configured images      : " + ([((.spec.template.spec.initContainers // []) + (.spec.template.spec.containers // []))[] | "\(.name)=\(.image)"] | join(", ")),
      "Conditions             : " + ([(.status.conditions // [])[] | "\(.type)=\(.status):\(.reason // "-")"] | join(", "))' "$obj"

    info ""
    info "Running pod image fingerprints:"
    jq -r --arg key "$key" '
      [ .[] | select(.key == $key) ] as $p
      | if ($p | length) == 0 then "  (no associated running pods found)"
        else $p[] |
          "  \(.pod) (created \(.created // "?"))",
          (.containers[] | "    \(.name): configured=\(.configuredImage // "-") running=\(.runningImage // "-") imageID=\(.imageID // "-") restarts=\(.restartCount // 0) ready=\(.ready // false)")
        end' "$WORK/podstate.json"

    info ""
    info "Retained rollout evidence:"
    jq -r --arg ns "$ns" --arg kind "$kind" --arg name "$name" '
      [ .[] | select(.ns == $ns and .kind == $kind and .name == $name) ]
      | if length == 0 then "  (no retained revision history)"
        else .[] | "  rev \(.rev)  \(.created)  \(.changeType)  " + (.images | join(", "))
        end' "$WORK/history.json"

    if $DESCRIBE; then
      info ""
      info "--- kubectl describe $kind/$name -n $ns ---"
      k describe "$kind" "$name" -n "$ns" 2>&1 | sed 's/^/  /' || warn "describe failed for $key"
      while IFS= read -r pod; do
        [[ -n "$pod" ]] || continue
        info ""
        info "--- kubectl describe pod/$pod -n $ns ---"
        k describe pod "$pod" -n "$ns" 2>&1 | sed 's/^/  /' || warn "describe failed for $ns/Pod/$pod"
        info "--- targeted events for pod/$pod ---"
        k get events -n "$ns" --field-selector "involvedObject.name=$pod" --sort-by='.lastTimestamp' 2>&1 | sed 's/^/  /' || true
      done < <(jq -r --arg key "$key" '.[] | select(.key == $key) | .pod' "$WORK/podstate.json")
      info "--- targeted events for $kind/$name ---"
      k get events -n "$ns" --field-selector "involvedObject.name=$name" --sort-by='.lastTimestamp' 2>&1 | sed 's/^/  /' || true
    fi
  }

  verbose_node_details() {
    local node="$1"
    section "FLAGGED NODE: $node [NODE_CREATED_OR_REIMAGED]"
    k get node "$node" -o json 2>/dev/null | jq -r '
      "Pool                   : \(.metadata.labels["kubernetes.azure.com/agentpool"] // .metadata.labels.agentpool // "-")",
      "Node image             : \(.metadata.labels["kubernetes.azure.com/node-image-version"] // "-")",
      "Kubelet                : \(.status.nodeInfo.kubeletVersion // "-")",
      "Container runtime      : \(.status.nodeInfo.containerRuntimeVersion // "-")",
      "Kernel / OS            : \(.status.nodeInfo.kernelVersion // "-") / \(.status.nodeInfo.osImage // "-")"' || true
    if $DESCRIBE; then
      info "--- kubectl describe node/$node ---"
      k describe node "$node" 2>&1 | sed 's/^/  /' || warn "describe failed for node/$node"
    fi
  }

  verbose_snapshot_differences() {
    [[ -s "$WORK/diff.json" ]] || return
    jq -n -r \
      --slurpfile diff "$WORK/diff.json" --slurpfile objs "$WORK/objs.json" \
      --slurpfile changes "$WORK/changes.json" '
      [ ($changes[0] // [])[] | select(.inWindow) | (.ns + "/" + .kind + "/" + .name) ] as $already
      | [ ($objs[0].items // [])[]
          | select(.kind == "Deployment" or .kind == "DaemonSet" or .kind == "StatefulSet")
          | (.metadata.namespace + "/" + .kind + "/" + .metadata.name) as $key
          | [ $diff[0][] | select(.path | startswith("workloads." + $key + ".")) ] as $direct
          | select(($direct | length) > 0 and ($already | index($key) == null))
          | {key:$key, type:(if any($direct[]; .path | endswith(".runningImageIDs")) then "IMAGE_DIGEST_CHANGE"
                            elif any($direct[]; .path | endswith(".images")) then "IMAGE_CHANGE"
                            else "SNAPSHOT_CHANGE" end)} ]
      | unique_by(.key)[] | [.key,.type] | @tsv' |
    while IFS=$'\t' read -r key change_type; do
      [[ -n "$key" ]] || continue
      IFS='/' read -r ns kind name <<< "$key"
      verbose_component_details "$ns" "$kind" "$name" "$change_type"
    done
  }

  k get --raw /version > "$WORK/version.json" 2>/dev/null || { echo '{}' > "$WORK/version.json"; die "Cannot reach the API server"; }
  k get nodes -o json > "$WORK/nodes.json" 2>/dev/null || { echo '{"items":[]}' > "$WORK/nodes.json"; warn "Cannot list nodes"; }

  EXISTING_NS="$(k get ns -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null)"
  SCANNED=()
  IFS=',' read -r -a NS_LIST <<< "$NAMESPACES"
  for ns in "${NS_LIST[@]}"; do
    grep -qx "$ns" <<< "$EXISTING_NS" || continue
    if k get deployments,replicasets,daemonsets,statefulsets,controllerrevisions -n "$ns" -o json > "$WORK/ns-$ns.json" 2>/dev/null; then
      SCANNED+=("$ns")
      k get pods -n "$ns" -o json > "$WORK/pods-$ns.json" 2>/dev/null         || { echo '{"items":[]}' > "$WORK/pods-$ns.json"; warn "Could not read pods in namespace $ns"; }
    else
      warn "Could not read workloads in namespace $ns"; rm -f "$WORK/ns-$ns.json"
    fi
  done
  if [[ ${#SCANNED[@]} -gt 0 ]]; then
    jq -s '{items: (map(.items) | add // [])}' "$WORK"/ns-*.json > "$WORK/objs.json"
    jq -s '{items: (map(.items) | add // [])}' "$WORK"/pods-*.json > "$WORK/pods.json"
  fi

  section "2. Control plane"
  info "API server version    : $(jq -r '.gitVersion // "unknown"' "$WORK/version.json")  (build date $(jq -r '.buildDate // "?"' "$WORK/version.json"))"
  info "Note: hosted control-plane components (etcd, konnectivity-server, etc.) are not visible from the cluster;"
  info "      the API server gitVersion + ARM currentKubernetesVersion are the observable signals."

  # ---- revision history of managed workloads ----
  jq --argjson cutoff "$CUTOFF" '
    def imgs: ((.initContainers // []) + (.containers // [])) | map("\(.name)=\(.image)") | sort;
    def noimg: (.spec.containers |= ((. // []) | map(del(.image))))
             | (.spec.initContainers |= ((. // []) | map(del(.image))));
    def norm: del(.metadata.labels["pod-template-hash"], .metadata.labels["controller-revision-hash"],
                  .metadata.creationTimestamp, .metadata.annotations["kubectl.kubernetes.io/restartedAt"]);
    .items as $all
    | ( [ $all[] | select(.kind == "ReplicaSet")
          | ((.metadata.ownerReferences // []) | map(select(.kind == "Deployment")) | .[0]) as $o
          | select($o != null)
          | { ns: .metadata.namespace, kind: "Deployment", name: $o.name,
              rev: ((.metadata.annotations["deployment.kubernetes.io/revision"] // "0") | tonumber),
              created: .metadata.creationTimestamp,
              images: ((.spec.template.spec // {}) | imgs),
              tpl: ((.spec.template // {}) | norm | noimg),
              restarted: (.spec.template.metadata.annotations["kubectl.kubernetes.io/restartedAt"] // null) } ]
      + [ $all[] | select(.kind == "ControllerRevision")
          | ((.metadata.ownerReferences // []) | map(select(.kind == "DaemonSet" or .kind == "StatefulSet")) | .[0]) as $o
          | select($o != null)
          | { ns: .metadata.namespace, kind: $o.kind, name: $o.name, rev: .revision,
              created: .metadata.creationTimestamp,
              images: ((.data.spec.template.spec // {}) | imgs),
              tpl: ((.data.spec.template // {}) | norm | noimg),
              restarted: (.data.spec.template.metadata.annotations["kubectl.kubernetes.io/restartedAt"] // null) } ] )
    | group_by([.ns, .kind, .name])
    | map( sort_by(.rev) as $r
        | [ range(0; $r | length) as $i
            | $r[$i] as $cur
            | (if $i > 0 then $r[$i - 1] else null end) as $prev
            | ($cur.created | fromdateiso8601) as $ep
            | { ns: $cur.ns, kind: $cur.kind, name: $cur.name, rev: $cur.rev, created: $cur.created, epoch: $ep,
                inWindow: ($ep >= $cutoff),
                oldestRetained: ($prev == null),
                added:   (if $prev then ($cur.images - $prev.images) else [] end),
                removed: (if $prev then ($prev.images - $cur.images) else [] end),
                configChange: (if $prev then ($cur.tpl != $prev.tpl) else false end),
                restartOnly: (if $prev then (($cur.images == $prev.images) and ($cur.restarted != $prev.restarted)) else false end),
                changeType: (if $prev == null then "NEW_COMPONENT"
                             elif ($cur.images != $prev.images) then "IMAGE_CHANGE"
                             elif (($cur.images == $prev.images) and ($cur.restarted != $prev.restarted)) then "RESTART"
                             elif ($cur.tpl != $prev.tpl) then "POD_TEMPLATE_CHANGE"
                             else "ROLLOUT" end),
                images: $cur.images } ] )
    | add // []' "$WORK/objs.json" > "$WORK/history.json" || die "Failed to analyse revision history"

  # Resolve each Pod through its owner (ReplicaSet -> Deployment, or direct
  # DaemonSet/StatefulSet) and retain exact running image IDs/digests.
  jq -n --slurpfile objs "$WORK/objs.json" --slurpfile pods "$WORK/pods.json" '
    ($objs[0].items // []) as $all
    | (reduce ($all[] | select(.kind == "ReplicaSet")) as $rs ({};
        .[($rs.metadata.namespace + "/" + $rs.metadata.name)] =
          ((($rs.metadata.ownerReferences // []) | map(select(.kind == "Deployment")) | .[0].name) // ""))) as $rsOwner
    | [ ($pods[0].items // [])[]
        | . as $pod
        | (($pod.metadata.ownerReferences // [])[0] // {}) as $o
        | (if $o.kind == "ReplicaSet" then
             {kind:"Deployment", name:($rsOwner[$pod.metadata.namespace + "/" + $o.name] // "")}
           elif ($o.kind == "DaemonSet" or $o.kind == "StatefulSet") then
             {kind:$o.kind, name:$o.name}
           else {kind:"", name:""} end) as $owner
        | select($owner.name != "")
        | { key: ($pod.metadata.namespace + "/" + $owner.kind + "/" + $owner.name),
            ns: $pod.metadata.namespace, kind: $owner.kind, name: $owner.name,
            pod: $pod.metadata.name, created: $pod.metadata.creationTimestamp,
            containers: [ (($pod.spec.initContainers // []) + ($pod.spec.containers // []))[] as $c
              | (($pod.status.initContainerStatuses // []) + ($pod.status.containerStatuses // [])
                 | map(select(.name == $c.name)) | .[0] // {}) as $st
              | {name:$c.name, configuredImage:$c.image, runningImage:($st.image // null),
                 imageID:($st.imageID // null), restartCount:($st.restartCount // 0),
                 ready:($st.ready // false), state:($st.state // {}), lastState:($st.lastState // {})} ] } ]
    | sort_by(.key, .pod)' > "$WORK/podstate.json" || die "Failed to build running Pod image inventory"

  section "3. Managed workloads - last rollout per component (namespaces: ${SCANNED[*]:-none})"
  jq -r '
    group_by([.ns, .kind, .name]) | map(max_by(.rev)) | sort_by(-.epoch)
    | (["LAST ROLLOUT (UTC)", "REV", "WORKLOAD", "IMAGES"] | @tsv),
      (.[] | [ .created, (.rev | tostring), "\(.ns)/\(.kind)/\(.name)",
               (.images | map(sub("^[^=]+="; "") | sub("^.*/"; "")) | join(" ")) ] | @tsv)' \
    "$WORK/history.json" | tabulate | sed 's/^/  /'

  section "4. Managed-component rollouts inside the window (since ${CUTOFF_ISO})"
  jq --argjson all "$SHOW_ALL" '
    [ .[] | select(($all or .inWindow)
                   and ((.oldestRetained | not) or (.rev == 1 and .inWindow))) ] | sort_by(.epoch)' \
    "$WORK/history.json" > "$WORK/changes.json"
  jq -r '
    if length == 0 then "  None." else
    .[] |
      "  \(.created)  \(.ns)/\(.kind)/\(.name)  rev \(.rev)  [\(.changeType)]" + (if .inWindow then "  [IN WINDOW]" else "" end),
      (if .oldestRetained and .rev == 1 then "      NEW component (first revision created in window)" else empty end),
      (.removed[] | "      - \(.)"),
      (.added[]   | "      + \(.)"),
      (if (.added | length) == 0 and (.removed | length) == 0 and (.oldestRetained | not) then
         (if .restartOnly then "      (rollout restart only - no spec change)"
          elif .configChange then "      (pod template changed: args/env/resources/tolerations etc. - images unchanged)"
          else "      (revision bump with no detectable template difference)" end)
       else empty end)
    end' "$WORK/changes.json"
  W_CHANGES="$(jq '[.[] | select(.inWindow and ((.oldestRetained | not) or .rev == 1) and (.restartOnly | not))] | length' "$WORK/history.json")"
  W_IMG="$(jq '[.[] | select(.inWindow and (.oldestRetained | not) and ((.added | length) > 0))] | length' "$WORK/history.json")"
  [[ "$W_CHANGES" -gt 0 ]] && finding "In-cluster: ${W_CHANGES} managed workload rollout(s) in window (${W_IMG} with image/version changes)"
  info "  Note: history depth is limited by revisionHistoryLimit (default 10 for Deployments/DaemonSets)."

  section "5. Nodes"
  jq --argjson cutoff "$CUTOFF" '
    [ .items[] | {
        name: .metadata.name,
        pool: (.metadata.labels["kubernetes.azure.com/agentpool"] // .metadata.labels["agentpool"] // "-"),
        kubelet: .status.nodeInfo.kubeletVersion,
        nodeImage: (.metadata.labels["kubernetes.azure.com/node-image-version"] // "-"),
        kernel: .status.nodeInfo.kernelVersion,
        runtime: .status.nodeInfo.containerRuntimeVersion,
        osImage: .status.nodeInfo.osImage,
        created: .metadata.creationTimestamp,
        inWindow: ((.metadata.creationTimestamp | fromdateiso8601) >= $cutoff) } ] | sort_by(.pool, .name)' \
    "$WORK/nodes.json" > "$WORK/nodelist.json"
  jq -r '(["NODE", "POOL", "KUBELET", "NODE IMAGE", "KERNEL", "RUNTIME", "CREATED (UTC)", ""] | @tsv),
         (.[] | [.name, .pool, .kubelet, .nodeImage, .kernel, .runtime, .created, (if .inWindow then "<- created in window" else "" end)] | @tsv)' \
    "$WORK/nodelist.json" | tabulate | sed 's/^/  /'
  N_NEW="$(jq '[.[] | select(.inWindow)] | length' "$WORK/nodelist.json")"
  [[ "$N_NEW" -gt 0 ]] && finding "Nodes: ${N_NEW} node(s) created in window (upgrade / reimage / node-image upgrade / scale-out)"
  while IFS= read -r f; do [[ -n "$f" ]] && finding "$f"; done < <(jq -r '
    group_by(.pool)[] | . as $p
    | ( [$p[].kubelet] | unique ) as $kv | ( [$p[].nodeImage] | unique ) as $ni | ( [$p[].kernel] | unique ) as $kr
    | (if ($kv | length) > 1 then "Pool \($p[0].pool): mixed kubelet versions \($kv | join(", ")) (upgrade in progress or partial)" else empty end),
      (if ($ni | length) > 1 then "Pool \($p[0].pool): mixed node images \($ni | join(", ")) (node image upgrade in progress or partial)" else empty end),
      (if ($kr | length) > 1 then "Pool \($p[0].pool): mixed kernel versions \($kr | join(", ")) (OS patching / reboot pending on some nodes)" else empty end)
  ' "$WORK/nodelist.json")
fi

# =====================================================================
# 3. FEED-ALIGNED COMPONENT INVENTORY
# =====================================================================
build_component_inventory() {
  jq -n \
    --slurpfile feeds "$WORK/feeds.json" --slurpfile aks "$WORK/aks.json" \
    --slurpfile ver "$WORK/version.json" --slurpfile nodes "$WORK/nodes.json" \
    --slurpfile objs "$WORK/objs.json" --slurpfile podstate "$WORK/podstate.json" '
    def imgs: ((.initContainers // []) + (.containers // [])) | map(.image) | join(" ");
    [ ($objs[0].items // [])[]
      | select(.kind == "Deployment" or .kind == "DaemonSet" or .kind == "StatefulSet")
      | { key:(.metadata.namespace + "/" + .kind + "/" + .metadata.name),
          images:((.spec.template.spec // {}) | imgs) } ] as $workloads
    | ($feeds[0] | map(. as $f
        | [ $workloads[] as $w
            | select(
                (($f.match.workload // "") as $r | ($r != "" and ($w.key | test($r; "i")))) or
                (($f.match.image // "") as $r | ($r != "" and ($w.images | test($r; "i")))))
            | $w ] as $matched
        | ($f.signals // []) as $signals
        | (([ ]
           + (if (($signals | index("release")) != null) and (($aks[0] | length) > 0)
              then ["ARM cluster profile (release correlation only)"] else [] end)
           + (if (($signals | index("node")) != null) and ((($nodes[0].items // []) | length) > 0)
              then ["nodes=" + ((($nodes[0].items // []) | length) | tostring)] else [] end)
           + (if (($signals | index("node")) != null) and ((($nodes[0].items // []) | length) == 0)
                 and ([ $aks[0].agentPoolProfiles[]?.nodeImageVersion | select(. != null and . != "") ] | length) > 0
              then ["ARM nodeImages=" + ([ $aks[0].agentPoolProfiles[]?.nodeImageVersion | select(. != null and . != "") ] | unique | join(","))]
              else [] end)
           + (if (($signals | index("controlPlane")) != null) and (($ver[0].gitVersion // "") != "")
              then ["apiServer=" + $ver[0].gitVersion] else [] end)
           + (if (($signals | index("arm:storage.diskCSIDriver")) != null) and ($aks[0].storageProfile.diskCSIDriver.enabled == true)
              then ["ARM storageProfile.diskCSIDriver enabled"] else [] end)
           + (if (($signals | index("arm:storage.fileCSIDriver")) != null) and ($aks[0].storageProfile.fileCSIDriver.enabled == true)
              then ["ARM storageProfile.fileCSIDriver enabled"] else [] end)
           + (if (($signals | index("arm:storage.blobCSIDriver")) != null) and ($aks[0].storageProfile.blobCSIDriver.enabled == true)
              then ["ARM storageProfile.blobCSIDriver enabled"] else [] end)
           + (if (($signals | index("arm:storage.snapshotController")) != null) and ($aks[0].storageProfile.snapshotController.enabled == true)
              then ["ARM storageProfile.snapshotController enabled"] else [] end)
           + (if (($signals | index("arm:network.cilium")) != null) and (($aks[0].networkProfile.networkDataplane // "") == "cilium")
              then ["ARM networkDataplane=cilium"] else [] end)
           + (if (($signals | index("arm:network.azureCni")) != null) and (($aks[0].networkProfile.networkPlugin // "") == "azure")
              then ["ARM networkPlugin=azure"] else [] end)
           + (if (($signals | index("arm:network.calico")) != null) and (($aks[0].networkProfile.networkPolicy // "") == "calico")
              then ["ARM networkPolicy=calico"] else [] end)
           + (if (($signals | index("arm:serviceMesh.istio")) != null) and ((($aks[0].serviceMeshProfile.istio.revisions // []) | length) > 0)
              then ["ARM serviceMeshProfile.istio enabled"] else [] end)
           + (if (($signals | index("arm:workloadIdentity")) != null)
                 and (($aks[0].oidcIssuerProfile.enabled == true) or ($aks[0].securityProfile.workloadIdentity.enabled == true))
              then ["ARM workload identity/OIDC enabled"] else [] end)
           + (if (($signals | index("arm:keda")) != null) and ($aks[0].workloadAutoScalerProfile.keda.enabled == true)
              then ["ARM workloadAutoScalerProfile.keda enabled"] else [] end)
           + (if (($signals | index("arm:azurePolicy")) != null) and ($aks[0].addonProfiles.azurepolicy.enabled == true)
              then ["ARM addonProfiles.azurepolicy enabled"] else [] end)
           + ($matched | map(.key)))
          | unique) as $evidence
        | {category:$f.category, component:$f.component, repo:$f.repo, signals:$f.signals,
           status:(if (($signals | index("release")) != null) and (($aks[0] | length) > 0) then "CONTEXT"
                   elif ($evidence | length) > 0 then "OBSERVED"
                   else "NOT_OBSERVED" end),
           evidence:$evidence,
           workloads:($matched | map(.key) | unique),
           desiredImages:($matched | map(.images | split(" ")) | add // [] | map(select(. != "")) | unique),
           runningImageIDs:([ ($podstate[0] // [])[] as $p
             | select(($matched | map(.key) | index($p.key)) != null)
             | $p.containers[].imageID | select(. != null and . != "") ] | unique)}))
    | sort_by(.category, .component)' > "$WORK/component-inventory.json" \
    || die "Failed to build feed-aligned component inventory"
}

build_component_inventory
section "6. Feed-aligned component inventory"
info "  Repositories are release-correlation sources; they do not prove that the cluster runs the latest upstream release."
jq -r '(["STATUS","CATEGORY","COMPONENT","OWNER/REPO","EVIDENCE"] | @tsv),
       (.[] | [.status,.category,.component,.repo,
         (if (.evidence | length) == 0 then "not observed (not enabled, not exposed, or no matcher hit)"
          else (.evidence | join(", ")) end)] | @tsv)' "$WORK/component-inventory.json" | tabulate | sed 's/^/  /'

if $VERBOSE && ! $SKIP_K8S; then
  section "7. Verbose evidence for flagged components"
  FLAGGED_COUNT="$(jq '[.[] | select(.inWindow)] | length' "$WORK/changes.json" 2>/dev/null || echo 0)"
  if [[ "$FLAGGED_COUNT" -eq 0 ]]; then
    info "  No in-cluster workload changes were flagged in the selected window."
  else
    while IFS=$'\t' read -r ns kind name change_type; do
      verbose_component_details "$ns" "$kind" "$name" "$change_type"
    done < <(jq -r '[.[] | select(.inWindow)] | group_by([.ns,.kind,.name]) | map(max_by(.epoch))[] | [.ns,.kind,.name,.changeType] | @tsv' "$WORK/changes.json")
  fi
  while IFS= read -r node; do
    [[ -n "$node" ]] && verbose_node_details "$node"
  done < <(jq -r '.[] | select(.inWindow) | .name' "$WORK/nodelist.json" 2>/dev/null)
fi

# =====================================================================
# 4. SNAPSHOT (save / compare)
# =====================================================================
build_snapshot() {
  [[ -f "$WORK/history.json" ]] || echo '[]' > "$WORK/history.json"
  [[ -f "$WORK/nodelist.json" ]] || echo '[]' > "$WORK/nodelist.json"
  jq -n \
    --slurpfile aks "$WORK/aks.json" --slurpfile mc "$WORK/mc.json" --slurpfile ver "$WORK/version.json" \
    --slurpfile objs "$WORK/objs.json" --slurpfile hist "$WORK/history.json" --slurpfile nodes "$WORK/nodelist.json"     --slurpfile podstate "$WORK/podstate.json" --slurpfile feeds "$WORK/feeds.json"     --slurpfile inventory "$WORK/component-inventory.json" \
    --arg cluster "$CLUSTER" --arg rg "$RG" --arg sub "$SUB" --arg tv "$TOOL_VERSION" \
    --argjson skipArm "$SKIP_ARM" --argjson skipK8s "$SKIP_K8S" '
    def imgs: ((.initContainers // []) + (.containers // [])) | map("\(.name)=\(.image)") | sort;
    ($aks[0]) as $a
    | ($hist[0] | group_by([.ns, .kind, .name]) | map({key: "\(.[0].ns)/\(.[0].kind)/\(.[0].name)", value: (map(.rev) | max)}) | from_entries) as $revs
    | {
        meta: { tool: "aks-managed-change-check", toolVersion: $tv, cluster: $cluster, resourceGroup: $rg,
                subscription: ($a.id // "" | split("/") | .[2] // $sub), capturedAt: (now | todate),
                skipArm: $skipArm, skipK8s: $skipK8s },
        arm: (if ($a | length) == 0 then {} else {
          kubernetesVersion: $a.kubernetesVersion,
          currentKubernetesVersion: $a.currentKubernetesVersion,
          provisioningState: $a.provisioningState,
          skuTier: $a.sku.tier,
          supportPlan: $a.supportPlan,
          autoUpgradeProfile: ($a.autoUpgradeProfile // {}),
          agentPools: (($a.agentPoolProfiles // []) | map({key: .name, value: {
              orchestratorVersion, currentOrchestratorVersion, nodeImageVersion, osSku, osType, vmSize,
              mode, provisioningState, maxPods, enableFips: .enableFIPS, kubeletDiskType,
              upgradeSettings: (.upgradeSettings // {}) }}) | from_entries),
          addons: (($a.addonProfiles // {}) | with_entries(.value = (.value.enabled // false))),
          network: ($a.networkProfile // {} | {networkPlugin, networkPluginMode, networkPolicy, networkDataplane, outboundType, loadBalancerSku}),
          serviceMesh: ($a.serviceMeshProfile // {}),
          ingress: ($a.ingressProfile // {}),
          workloadAutoScaler: ($a.workloadAutoScalerProfile // {}),
          azureMonitor: ($a.azureMonitorProfile // {}),
          security: ($a.securityProfile // {} | del(.defender.logAnalyticsWorkspaceResourceId)),
          storage: ($a.storageProfile // {}),
          oidcIssuerEnabled: ($a.oidcIssuerProfile.enabled // false),
          maintenanceConfigurations: ($mc[0] | map(.name) | sort)
        } end),
        controlPlane: { apiServerVersion: ($ver[0].gitVersion // null) },
        feedCatalog: ($feeds[0] | map({category, component, repo, signals})),
        componentInventory: ($inventory[0] | map({key:(.category + "/" + .component), value:{repo,status,evidence,workloads,desiredImages,runningImageIDs}}) | from_entries),
        workloads: ( $objs[0].items
          | map(select(.kind == "Deployment" or .kind == "DaemonSet" or .kind == "StatefulSet"))
          | map("\(.metadata.namespace)/\(.kind)/\(.metadata.name)" as $k
                | {key: $k, value: { images: ((.spec.template.spec // {}) | imgs), revision: ($revs[$k] // null),
                    runningImageIDs:([ ($podstate[0] // [])[] | select(.key == $k) | .containers[].imageID | select(. != null and . != "") ] | unique) }})
          | from_entries ),
        nodePools: ( $nodes[0] | group_by(.pool)
          | map({key: .[0].pool, value: {
              kubeletVersions: ([.[].kubelet] | unique), nodeImages: ([.[].nodeImage] | unique),
              kernels: ([.[].kernel] | unique), runtimes: ([.[].runtime] | unique), osImages: ([.[].osImage] | unique) }})
          | from_entries ),
        nodes: $nodes[0]
      }' > "$WORK/current.json" || die "Failed to build snapshot"
}

if [[ -n "$SAVE_FILE" || -n "$COMPARE_FILE" ]]; then
  build_snapshot
  if [[ -n "$COMPARE_FILE" ]]; then
    section "8. Comparison against baseline snapshot"
    diff_snapshots "$COMPARE_FILE" "$WORK/current.json"
    if $VERBOSE && ! $SKIP_K8S; then
      section "8b. Verbose evidence for snapshot-flagged components"
      verbose_snapshot_differences
    fi
  fi
  if [[ -n "$SAVE_FILE" ]]; then
    cp "$WORK/current.json" "$SAVE_FILE" || die "Could not write $SAVE_FILE"
    info ""
    info "Snapshot saved to ${SAVE_FILE}"
  fi
fi

# =====================================================================
# VERDICT
# =====================================================================
section "Verdict"
if [[ ${#FINDINGS[@]} -gt 0 ]]; then
  info "${R}${B}CHANGES DETECTED${N} on ${CLUSTER}:"
  for f in "${FINDINGS[@]}"; do info "  * $f"; done
  exit 10
else
  info "${G}${B}NO MANAGED-COMPONENT CHANGES DETECTED${N} in the last ${SINCE}"
  info "  (within retained revision history and Activity Log retention; use --save/--compare for a durable before/after check)"
  exit 0
fi
