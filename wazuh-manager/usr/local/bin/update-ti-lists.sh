#!/usr/bin/env bash
set -euo pipefail

[ -f /etc/default/wazuh-ti ] && source /etc/default/wazuh-ti

LISTDIR="/var/ossec/etc/lists"
MAX_SIZE=$((500 * 1024 * 1024))   # 500 MB
PRUNE_BYTES=$((100 * 1024 * 1024)) # 100 MB
OWNER="wazuh:wazuh"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

mkdir -p "$LISTDIR"

log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') $*"
}

need_cmd() { command -v "$1" >/dev/null 2>&1 || { log "Missing required command: $1" >&2; exit 1; }; }
need_cmd curl
need_cmd jq
need_cmd grep
need_cmd sort
need_cmd awk
need_cmd stat
need_cmd tail
need_cmd chown
need_cmd uniq

extract_ips_to_listfile() {
  # $1=url  $2=tag_value  $3=output_filename
  local url="$1" tag="$2" out="$3"
  local tmp="$TMPDIR/$(basename "$out").ips"

  curl -fsSL "$url" \
    | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' \
    | sort -u \
    | grep -vP '(^127\.|^192\.168|^172\.16)' \
    > "$tmp"

  awk -v t="$tag" '{print $1 ":" t}' "$tmp" >> "$LISTDIR/$out"
  chown "$OWNER" "$LISTDIR/$out"
  log "Wrote $LISTDIR/$out ($(wc -l < "$LISTDIR/$out") entries)"
}

########################################
# 1) Threatview Cobalt Strike C2 (TXT)
########################################
curl -fsSL "https://threatview.io/Downloads/High-Confidence-CobaltStrike-C2%20-Feeds.txt" \
  | cut -d"," -f1 \
  | sort -u \
  | grep -vP '(^127\.|^192\.168|^172\.16)' \
  | awk '{print $1":threatview_cobaltstrike_c2"}' \
  >> "$LISTDIR/threatview_cs_c2"
chown "$OWNER" "$LISTDIR/threatview_cs_c2"
log "Wrote $LISTDIR/threatview_cs_c2 ($(wc -l < "$LISTDIR/threatview_cs_c2") entries)"

########################################
# 2) Emerging Threats (Proofpoint ET) blockrules
########################################
# Plain IP list
extract_ips_to_listfile \
  "https://rules.emergingthreats.net/blockrules/compromised-ips.txt" \
  "et_compromised_ips" \
  "et_compromised_ips"

# IPs embedded inside .rules (we just regex out the IPs)
extract_ips_to_listfile \
  "https://rules.emergingthreats.net/blockrules/emerging-ciarmy.rules" \
  "et_ciarmy" \
  "et_ciarmy"

extract_ips_to_listfile \
  "https://rules.emergingthreats.net/blockrules/emerging-drop.rules" \
  "et_drop" \
  "et_drop"

extract_ips_to_listfile \
  "https://rules.emergingthreats.net/blockrules/emerging-tor.rules" \
  "et_tor" \
  "et_tor"

extract_ips_to_listfile \
  "https://rules.emergingthreats.net/blockrules/emerging-dshield.rules" \
  "et_dshield" \
  "et_dshield"

########################################
# 3) ThreatFox (abuse.ch) via API (jq only)
########################################
# Export THREATFOX_AUTH_KEY="..."
: "${THREATFOX_AUTH_KEY:=}"
THREATFOX_DAYS="${THREATFOX_DAYS:-7}"

if [[ -z "$THREATFOX_AUTH_KEY" ]]; then
  log "THREATFOX_AUTH_KEY not set, skipping ThreatFox."
else
  TF_JSON="$TMPDIR/threatfox.json"

  curl -fsSL \
    -H "Auth-Key: $THREATFOX_AUTH_KEY" \
    -X POST "https://threatfox-api.abuse.ch/api/v1/" \
    -d "{\"query\":\"get_iocs\",\"days\":$THREATFOX_DAYS}" \
    > "$TF_JSON"

  # IPs: ioc_type ip or ip:port -> normalize to plain IP as key
  jq -r '
    .data[]? 
    | select(.ioc_type=="ip" or .ioc_type=="ip:port")
    | (.ioc | split(":")[0]) as $ip
    | "\($ip):threatfox_\(.threat_type)_\(.malware)"
  ' "$TF_JSON" \
    | sort -u \
    >> "$LISTDIR/threatfox_ip"
  chown "$OWNER" "$LISTDIR/threatfox_ip"
  log "Wrote $LISTDIR/threatfox_ip ($(wc -l < "$LISTDIR/threatfox_ip") entries)"

  # Domains
  jq -r '
    .data[]?
    | select(.ioc_type=="domain")
    | "\(.ioc):threatfox_\(.threat_type)_\(.malware)"
  ' "$TF_JSON" \
    | sort -u \
    >> "$LISTDIR/threatfox_domain"
  chown "$OWNER" "$LISTDIR/threatfox_domain"
  log "Wrote $LISTDIR/threatfox_domain ($(wc -l < "$LISTDIR/threatfox_domain") entries)"
fi

########################################
# 4) AlienVault - Open Threat Exchange
########################################
# Export OTX_ALIENVAULT_AUTH_KEY="..."
: "${OTX_ALIENVAULT_AUTH_KEY:=}"
OTX_DAYS_DELTA="${OTX_DAYS_DELTA:-3}"

if [[ -z "$OTX_ALIENVAULT_AUTH_KEY" ]]; then
  log "OTX_ALIENVAULT_AUTH_KEY not set, skipping OTX AlienVault."
else
  OTX_JSON="$TMPDIR/otx_subscribed.json"
  OTX_CUTOFF_EPOCH="$(date -u -d "$OTX_DAYS_DELTA days ago" +%s)"

  log "Fetching OTX pulses (local filter: indicators created in last $OTX_DAYS_DELTA days)"

  curl -fsSL \
    -H "X-OTX-API-KEY: $OTX_ALIENVAULT_AUTH_KEY" \
    "https://otx.alienvault.com/api/v1/pulses/subscribed" \
    > "$OTX_JSON"

  size=$(stat -c %s "$OTX_JSON")
  log "Fetched OTX pulse (size=$((size/1024/1024))MB)"

  # IPv4 (filtered by indicator.created)
  jq -r --argjson cutoff "$OTX_CUTOFF_EPOCH" '
    .results[]?.indicators[]?
    | select(.type=="IPv4")
    | select(.created? and ((.created + "Z") | fromdateiso8601) >= $cutoff)
    | .indicator
  ' "$OTX_JSON" \
    | sort -u \
    | grep -vP '(^127\.|^192\.168|^172\.16)' \
    | awk '{print $1":otx_alienvault_ip"}' \
    >> "$LISTDIR/otx_alienvault_ip" || true
  chown "$OWNER" "$LISTDIR/otx_alienvault_ip"
  log "Wrote $LISTDIR/otx_alienvault_ip ($(wc -l < "$LISTDIR/otx_alienvault_ip") entries)"

  # Domains (filtered by indicator.created)
  jq -r --argjson cutoff "$OTX_CUTOFF_EPOCH" '
    .results[]?.indicators[]?
    | select(.type=="domain")
    | select(.created? and ((.created + "Z") | fromdateiso8601) >= $cutoff)
    | .indicator
  ' "$OTX_JSON" \
    | sort -u \
    | awk '{print $1":otx_alienvault_domain"}' \
    >> "$LISTDIR/otx_alienvault_domain" || true
  chown "$OWNER" "$LISTDIR/otx_alienvault_domain"
  log "Wrote $LISTDIR/otx_alienvault_domain ($(wc -l < "$LISTDIR/otx_alienvault_domain") entries)"
fi

########################################
# 5) OpenPhish – public phishing feed
########################################
curl -fsSL "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt" \
| sed -E 's/^[[:space:]]+|[[:space:]]+$//g' \
| grep -Evi '^(#|$)' \
| sed -E 's#^https?://##i; s#/.*##' \
| sed -E 's/^www\.//i' \
| grep -Evi '^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)' \
| sort -u \
| awk -F: '{print $1":openphish"}' \
>> "$LISTDIR/openphish_domain"
chown "$OWNER" "$LISTDIR/openphish_domain"
log "Wrote $LISTDIR/openphish_domain ($(wc -l < "$LISTDIR/openphish_domain") entries)"

########################################
# 6) IPsum – malicious IP reputation
########################################
curl -fsSL "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt" \
| awk '
  /^[0-9]/ { print $1 }
' \
| grep -vP '(^127\.|^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.)' \
| sort -u \
| awk '{print $0":ipsum_bad_ips"}' \
>> "$LISTDIR/ipsum_bad_ips"
chown "$OWNER" "$LISTDIR/ipsum_bad_ips"
log "Wrote $LISTDIR/ipsum_bad_ips ($(wc -l < "$LISTDIR/ipsum_bad_ips") entries)"

########################################
########## DEDUP + CLEANUP #############
########################################
for f in \
  threatfox_ip \
  threatfox_domain \
  threatview_cs_c2 \
  et_compromised_ips \
  et_ciarmy \
  et_drop \
  et_tor \
  et_dshield \
  otx_alienvault_ip \
  otx_alienvault_domain \
  openphish_domain \
  ipsum_bad_ips
do
  file="$LISTDIR/$f"
  [[ -f "$file" ]] || continue

  ########################################################
  # 1) KEY-BASED DEDUP (preserve order)
  ########################################################
  log "Deduplicating $file"
  before=$(wc -l < "$file")
  tmp_dedup="${file}.dedup.$$"

  # ------------------------------------------------------------
  # Key-based deduplication (field before ':') with "new-wins"
  # semantics and stable time order.
  #
  # Implementation details:
  # - We scan the file once, top → bottom (original append order).
  # - For each key:
  #     * store the full line as the "latest value"
  #     * store NR (line number) of its LAST occurrence
  # - At END:
  #     * sort keys by their last occurrence position (NR)
  #     * print lines in that order (oldest last-seen → newest)
  #
  # This preserves temporal meaning, so size-based pruning
  # removes the oldest IOCs first.
  # ------------------------------------------------------------
  gawk -F: '
    NF >= 2 {
      key = $1
      last[key] = $0
      lastpos[key] = NR
    }
    END {
      # Build an index array mapping key -> lastpos[key]
      # Sort keys by lastpos ascending, so oldest last-seen first.
      n = asorti(lastpos, keys, "@val_num_asc")
      for (i = 1; i <= n; i++) {
        k = keys[i]
        print last[k]
      }
    }
  ' "$file" > "$tmp_dedup"

  if [[ ! -s "$tmp_dedup" ]]; then
    log "Dedup produced empty output for $file, skipping dedup+cleanup"
    rm -f "$tmp_dedup"
    continue
  fi

  mv "$tmp_dedup" "$file"
  chown "$OWNER" "$file"

  after=$(wc -l < "$file")
  log "Dedup completed for $file ($after entries, removed $((before - after)))"

  ########################################################
  # 2) SIZE-BASED PRUNE (only if still too large)
  ########################################################
  size=$(stat -c %s "$file")
  if (( size <= MAX_SIZE )); then
    continue
  fi

  log "Pruning $file (size=$((size/1024/1024))MB)"

  # avg size of a line (bytes). Guard against NR==0.
  avg_line_size=$(awk 'NR>0 {s+=length($0)+1} END {print (NR>0 ? int(s/NR) : 0)}' "$file")

  if (( avg_line_size <= 0 )); then
    log "Skip $file: cannot estimate prune size (avg_line_size=$avg_line_size)"
    continue
  fi

  prune_lines=$((PRUNE_BYTES / avg_line_size))
  if (( prune_lines <= 0 )); then
    log "Skip $file: prune_lines=$prune_lines"
    continue
  fi

  tmp_prune="${file}.prune.$$"

  # Keep only lines after the first N lines
  tail -n +"$((prune_lines + 1))" "$file" > "$tmp_prune"

  if [[ ! -s "$tmp_prune" ]]; then
    log "WARNING: prune produced empty output for $file, skipping prune"
    rm -f "$tmp_prune"
    continue
  fi

  mv "$tmp_prune" "$file"
  chown "$OWNER" "$file"

  log "Removed ~$((PRUNE_BYTES/1024/1024))MB from $file (now $(stat -c %s "$file") bytes)"
done

log "Done"
