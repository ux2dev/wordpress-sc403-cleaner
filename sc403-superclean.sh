#!/usr/bin/env bash
# sc403-superclean.sh - enhancement wrapper around wp-sc-account-cleaner-v45.sh
#
# Keeps the proven account cleaner as the engine and adds what SC 4.3.24
# analysis showed it lacks:
#   PRE   1. computes the md5(ABSPATH+role) artifact names for every site, and
#            the two derived browser endpoints (?p=<sw>, ?p=<inst>) and the
#            twelve derived private option keys, and injects the file names
#            (plus extra 4.3.24 markers) into the cleaner's IOC_REGEX -
#            exact, per-account IoCs instead of heuristics
#         2. captures the service-worker evidence from every site database
#            BEFORE the cleaner's strict DB cleanup destroys it: the plaintext
#            sc_sw_last_url / sc_sw_had rows, the implant's own encrypted
#            sw_url row (decoded), and the worker JavaScript it was serving to
#            administrators (sw_cached) - the only record of what ran in their
#            browsers
#   RUN   3. executes the patched fork (root, account-wide, unchanged logic)
#   POST  4. installs 00-sc403-sw-neutralizer.php on every site (browser
#            service-worker revocation), with that site's historical URLs
#            filled in; the current URL it derives for itself
#         5. optional: plants the phase-5 spread vaccine via sc403-vaccinate.sh,
#            which verifies the planted file actually satisfies the implant's
#            own already-infected test
#         6. bundles all evidence into a sha256-manifested tarball
#
# Usage (on the server, as root):
#   ./sc403-superclean.sh CPANEL_USER
#   ./sc403-superclean.sh --build-only --root /home/u/public_html CPANEL_USER
#
# Files expected next to this script:
#   wp-sc-account-cleaner-v45.sh     (the engine - unmodified, required)
#   00-sc403-sw-neutralizer.php      (optional, for step 4)
#   sc403-vaccinate.sh               (optional, for step 5; chmod +x it)

set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BASE="$HERE/wp-sc-account-cleaner-v45.sh"
# v2 of the neutralizer ships as 00-... because MU-plugins load alphabetically
# and it has to win that race against any implant MU-plugin still on disk.
NEUT="$HERE/00-sc403-sw-neutralizer.php"
[ -f "$NEUT" ] || NEUT="$HERE/sc403-sw-neutralizer.php"
NEUT_INSTALL_NAME="00-sc403-sw-neutralizer.php"
VACC="$HERE/sc403-vaccinate.sh"
TS=$(date +%Y%m%d-%H%M%S)

BUILD_ONLY=0; DO_VACCINE=1; DO_NEUT=1; ROOTS=(); CPUSER=""
while [ $# -gt 0 ]; do
  case "$1" in
    --build-only)    BUILD_ONLY=1; shift ;;
    --no-vaccine)    DO_VACCINE=0; shift ;;
    --no-neutralizer) DO_NEUT=0; shift ;;
    --root)          ROOTS+=("${2:?}"); shift 2 ;;
    -h|--help)       sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*)              echo "unknown option: $1" >&2; exit 64 ;;
    *)               CPUSER="$1"; shift ;;
  esac
done
[ -n "$CPUSER" ] || { echo "usage: $0 [options] CPANEL_USER (see --help)"; exit 64; }
[ -f "$BASE" ] || { echo "missing engine: $BASE"; exit 66; }

EVID="$HERE/superclean-$CPUSER-$TS"
mkdir -p "$EVID/build"
LOG="$EVID/superclean.log"
say() { printf '%s\n' "$*" | tee -a "$LOG"; }

md5s() {
  if command -v md5sum >/dev/null 2>&1; then printf '%s' "$1" | md5sum | cut -d' ' -f1
  else printf '%s' "$1" | md5 -q; fi
}

# The implant's two browser-facing endpoints, derived exactly as it derives
# them (core sc_derived_endpoint_id): 91000000 + md5(ABSPATH.'ep'.role)[0:7]
# modulo 8999999. `sw` is the service-worker scriptURL registered in every
# administrator's browser; `inst` is where that worker POSTs C2-supplied
# payloads. These are the identifiers the neutralizer needs and the ones the
# v1 toolkit never computed.
epid() { # $1 = ABSPATH (trailing slash), $2 = role
  local h; h=$(md5s "$1ep$2"); h=${h:0:7}
  printf '%s' $(( 91000000 + 16#$h % 8999999 ))
}

# Private option key: md5(ABSPATH . 93819 . name)[0:12]  (core sc_derived_option_key).
optkey() { md5s "$1""93819""$2" | cut -c1-12; }

# Reverse sc_load_encrypted_option: base64( keybyte . xor(serialize(v), keybyte) ).
decode_priv() {
  if command -v perl >/dev/null 2>&1; then
    perl -MMIME::Base64 -e 'local $/; my $b=decode_base64(<STDIN>); exit 1 if length($b)<2;
      my $k=substr($b,0,1); print join "", map { chr(ord($_)^ord($k)) } split //, substr($b,1);'
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import sys,base64
b=base64.b64decode(sys.stdin.read()); k=b[0]
sys.stdout.write("".join(chr(c^k) for c in b[1:]))'
  else
    cat   # leave it encoded rather than losing it
  fi
}

# --- discover site roots -----------------------------------------------------
if [ ${#ROOTS[@]} -eq 0 ]; then
  UHOME=$(getent passwd "$CPUSER" 2>/dev/null | cut -d: -f6)
  [ -n "${UHOME:-}" ] || UHOME="/home/$CPUSER"
  while IFS= read -r r; do ROOTS+=("$r"); done < <(
    find "$UHOME" -maxdepth 6 -type d -name wp-admin 2>/dev/null | sed 's|/wp-admin$||' | sort -u)
fi
[ ${#ROOTS[@]} -gt 0 ] || { say "no WordPress roots found for $CPUSER"; exit 1; }
say "site roots (${#ROOTS[@]}): ${ROOTS[*]}"

# --- PRE 1: derived names ------------------------------------------------
# Roles recovered from the deobfuscated 4.3.24 core; names are
# substr(md5(ABSPATH.role), 0, n) with ABSPATH ending in '/'.
DERIVED_TSV="$EVID/derived-names.tsv"
EXTRA_NAMES=""
printf 'root\trole\tname\n' > "$DERIVED_TSV"
for root in "${ROOTS[@]}"; do
  A="${root%/}/"
  HTL=$(md5s "${A}htl"  | cut -c1-8);  LDR=$(md5s "${A}ldr"  | cut -c1-8)
  DIRH=$(md5s "${A}dir" | cut -c1-8);  CORE=$(md5s "${A}core" | cut -c1-8)
  ZIP=$(md5s "${A}zip"  | cut -c1-8);  INST=$(md5s "${A}inst" | cut -c1-8)
  OC=$(md5s "${A}oc"    | cut -c1-8);  OWN=$(md5s "${A}own"  | cut -c1-8)
  G=$(md5s "${A}g"      | cut -c1-8);  OPT=$(md5s "${A}opt"  | cut -c1-10)
  EP_SW=$(epid "$A" sw); EP_IN=$(epid "$A" inst)
  for pair in "htl:$HTL" "ldr:$LDR" "dir:$DIRH" "core:$CORE" "zip:$ZIP" \
              "inst:$INST" "oc:$OC" "own:$OWN" "g:$G" "opt:$OPT" \
              "ep_sw:$EP_SW" "ep_inst:$EP_IN"; do
    printf '%s\t%s\t%s\n' "$root" "${pair%%:*}" "${pair#*:}" >> "$DERIVED_TSV"
  done
  for o in sw_url sw_cached sw_config sw_config_sig srv_key page_cached js_cached src bp bu ic errors; do
    printf '%s\topt_%s\t%s\n' "$root" "$o" "$(optkey "$A" "$o")" >> "$DERIVED_TSV"
  done
  EXTRA_NAMES="$EXTRA_NAMES|${HTL}[.]php|[.]${LDR}[.]php|${LDR}[.]php|core_${CORE}[.]php|${ZIP}[.]zip|own_${OWN}[.]php|${INST}[.]php|[.]g[a-z]{0,3}_${G}|${OPT}"
done
say "derived names written: $DERIVED_TSV"

# Extra 4.3.24 markers the engine's list does not yet include.
EXTRA_STATIC='SCSHM1:|SC_WC|sc_reins_|sc_spread_interval|sc_own_manifest|sc_oc_dat_ok|sc_sw_had|sc_sw_last_url|sc_js_printed_ts|sc_last_recovery_check|sc_last_rpc|sc_last_fetch_ts|sc_persist_manifest'
EXTRA="${EXTRA_STATIC}${EXTRA_NAMES}"

# --- build the patched fork ------------------------------------------------
FORK="$EVID/build/wp-sc-account-cleaner-v46-enhanced.sh"
PATCHED=0
: > "$FORK"
while IFS= read -r line; do
  if [[ $line == IOC_REGEX=* && $line == *\' ]]; then
    line="${line%\'}|${EXTRA}'"
    PATCHED=$((PATCHED+1))
  fi
  printf '%s\n' "$line" >> "$FORK"
done < "$BASE"
chmod 700 "$FORK"
if [ "$PATCHED" -ne 2 ]; then
  say "ERROR: expected to patch 2 IOC_REGEX lines, patched $PATCHED - engine layout changed, aborting"
  exit 1
fi
bash -n "$FORK" || { say "ERROR: patched fork failed bash -n"; exit 1; }
say "patched fork built: $FORK (2 IOC_REGEX lines extended)"

# --- PRE 2: capture service-worker evidence BEFORE DB cleanup --------------
SWFILE="$EVID/service-worker-urls.txt"
wpc() { sed -n "s/.*define(\s*['\"]$2['\"]\s*,\s*['\"]\([^'\"]*\)['\"].*/\1/p" "$1" | head -1; }
for root in "${ROOTS[@]}"; do
  cfg="$root/wp-config.php"
  [ -f "$cfg" ] && command -v mysql >/dev/null 2>&1 || continue
  DB=$(wpc "$cfg" DB_NAME); DU=$(wpc "$cfg" DB_USER); DP=$(wpc "$cfg" DB_PASSWORD)
  DH=$(wpc "$cfg" DB_HOST); TP=$(sed -n "s/.*table_prefix\s*=\s*['\"]\([A-Za-z0-9_]*\)['\"].*/\1/p" "$cfg" | head -1)
  [ -n "$DB" ] && [ -n "$TP" ] || continue
  MC=$(umask 077 && mktemp) || continue
  printf '[client]\nuser=%s\npassword=%s\nhost=%s\n' "$DU" "$DP" "${DH:-localhost}" > "$MC"
  q() { mysql --defaults-extra-file="$MC" -N -B "$DB" -e "$1" 2>>"$LOG"; }

  A="${root%/}/"
  SWU=$(q "SELECT option_value FROM ${TP}options WHERE option_name='sc_sw_last_url' LIMIT 1;")
  SWH=$(q "SELECT option_value FROM ${TP}options WHERE option_name='sc_sw_had' LIMIT 1;")

  # The implant also keeps its own encrypted copy under a derived key, and that
  # row survives cases where sc_sw_last_url was never written (the plaintext
  # one is only set once a registration script has actually been emitted).
  # Decode it and treat it as authoritative when the plaintext row is absent.
  SWU_PRIV_RAW=$(q "SELECT option_value FROM ${TP}options WHERE option_name='$(optkey "$A" sw_url)' LIMIT 1;")
  SWU_PRIV=""
  if [ -n "$SWU_PRIV_RAW" ]; then
    # value arrives as a PHP serialized string: s:<len>:"<url>";
    SWU_PRIV=$(printf '%s' "$SWU_PRIV_RAW" | decode_priv | sed -n 's/^s:[0-9]*:"\(.*\)";$/\1/p')
  fi
  [ -n "$SWU" ] || SWU="$SWU_PRIV"

  # The worker JavaScript actually being served to administrators. Keep it:
  # it is the primary evidence of what ran in their browsers, and it is gone
  # the moment the options table is cleaned.
  SWJS_RAW=$(q "SELECT option_value FROM ${TP}options WHERE option_name='$(optkey "$A" sw_cached)' LIMIT 1;")
  if [ -n "$SWJS_RAW" ]; then
    tag=$(printf '%s' "$root" | tr '/' '_')
    printf '%s' "$SWJS_RAW" | decode_priv > "$EVID/sw-cached${tag}.serialized.txt"
    say "captured served service-worker body for $root -> sw-cached${tag}.serialized.txt"
  fi
  rm -f "$MC"

  if [ -n "$SWU" ]; then
    printf '%s\tsite=%s\tdb=%s\tsc_sw_had=%s\tsource=%s\tcaptured=%s\n' \
      "$SWU" "$root" "$DB" "${SWH:-?}" \
      "$([ -n "$SWU_PRIV" ] && [ "$SWU" = "$SWU_PRIV" ] && echo derived-option || echo plaintext-option)" \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$SWFILE"
    say "captured service-worker URL for $root: $SWU"
  else
    # Not a failure. The neutralizer derives the same URL from ABSPATH on its
    # own, so it still works; this row would only add a historical URL from
    # before the site was moved.
    say "no stored service-worker URL for $root - neutralizer will use the derived ?p=$(epid "$A" sw)"
  fi
done
[ -f "$SWFILE" ] || say "no stored service-worker URLs found (the neutralizer derives its own; this is fine)"

# --- RUN the engine ----------------------------------------------------------
if [ "$BUILD_ONLY" -eq 1 ]; then
  say "--build-only: engine not executed. Run later: $FORK $CPUSER"
else
  [ "$(id -u)" -eq 0 ] || { say "engine requires root; rerun as root or use --build-only"; exit 77; }
  say "launching engine: $FORK $CPUSER"
  "$FORK" "$CPUSER"; RC=$?
  say "engine exit code: $RC"
  [ "$RC" -eq 0 ] || say "engine did not verify fully clean - review its report before POST steps"
fi

# --- POST 4: install the service-worker neutralizer --------------------------
if [ "$DO_NEUT" -eq 1 ] && [ -f "$NEUT" ] && [ "$BUILD_ONLY" -eq 0 ]; then
  for root in "${ROOTS[@]}"; do
    mu="$root/wp-content/mu-plugins"; mkdir -p "$mu"

    # Only this site's own historical URLs. The neutralizer derives the current
    # one from ABSPATH by itself; SC403_SW_URLS exists purely to also catch a
    # registration made before the site was moved to a different path.
    URLS=""
    if [ -f "$SWFILE" ]; then
      URLS=$(awk -F'\t' -v r="site=$root" '{for(i=2;i<=NF;i++) if($i==r){print $1; break}}' "$SWFILE" \
             | sort -u | sed "s/.*/        '&',/")
    fi

    awk -v urls="$URLS" '
      { print }
      # v2 anchor (guarded define), then the v1 anchor, for either layout.
      (urls != "") && ($0 ~ /define\(.SC403_SW_URLS., array\($/ || $0 ~ /^const SC403_SW_URLS = array\(/) { print urls }
    ' "$NEUT" > "$mu/$NEUT_INSTALL_NAME"

    chown "$CPUSER": "$mu/$NEUT_INSTALL_NAME" 2>/dev/null
    chmod 0644 "$mu/$NEUT_INSTALL_NAME" 2>/dev/null

    # A v1 copy left in place would double every hook and, worse, would still
    # carry the path-only tombstone match that can hijack the home page.
    if [ -f "$mu/sc403-sw-neutralizer.php" ] && [ "$NEUT_INSTALL_NAME" != "sc403-sw-neutralizer.php" ]; then
      mv -f "$mu/sc403-sw-neutralizer.php" "$EVID/replaced-v1-neutralizer$(printf '%s' "$root" | tr '/' '_').php" 2>/dev/null \
        && say "removed superseded v1 neutralizer from $mu"
    fi

    say "neutralizer installed: $mu/$NEUT_INSTALL_NAME (sw endpoint ?p=$(epid "${root%/}/" sw))"
  done
fi

# --- POST 5: phase-5 vaccine --------------------------------------------------
if [ "$DO_VACCINE" -eq 1 ] && [ "$BUILD_ONLY" -eq 0 ]; then
  if [ -x "$VACC" ]; then
    # Delegate: sc403-vaccinate.sh verifies the planted file actually satisfies
    # the implant's own size+mtime test, which the inline fallback below never
    # checked. --all because these roots have just been cleaned.
    ARGS=(--execute --all)
    for root in "${ROOTS[@]}"; do ARGS+=(--root "$root"); done
    "$VACC" "${ARGS[@]}" 2>&1 | tee -a "$LOG"
    for root in "${ROOTS[@]}"; do
      chown "$CPUSER": "$root/wp-content/mu-plugins/sc403-vaccine.php" 2>/dev/null
    done
  else
    say "note: $VACC not found - using the inline fallback (no verification)"
    for root in "${ROOTS[@]}"; do
      mu="$root/wp-content/mu-plugins"; f="$mu/sc403-vaccine.php"; mkdir -p "$mu"
      if [ ! -f "$f" ]; then
        { printf '<?php // sc403-vaccine: inert decoy; SC 4.x spread skips this site.\n'
          printf '// No executable logic. Remove when the account has one OS user per site.\nreturn;\n/*\n'
          head -c 5200 /dev/urandom | od -An -tx1 | tr -d ' \n'; printf '\n*/\n'; } > "$f"
        now=$(date +%s); wm=$(( now - now % 100000 + 93819 ))
        [ "$wm" -gt "$now" ] && wm=$(( wm - 100000 ))
        perl -e 'utime $ARGV[0], $ARGV[0], $ARGV[1]' "$wm" "$f" 2>/dev/null \
          || touch -d "@$wm" "$f" 2>/dev/null || say "  ! could not watermark $f - vaccine INEFFECTIVE"
        chown "$CPUSER": "$f" 2>/dev/null
        say "vaccine planted: $f"
      fi
    done
  fi
fi

# --- POST 6: evidence bundle ----------------------------------------------
( cd "$EVID" && find . -type f ! -name SHA256SUMS -exec sh -c \
    'sha256sum "$1" 2>/dev/null || shasum -a 256 "$1"' _ {} \; > SHA256SUMS )
tar -czf "$HERE/superclean-$CPUSER-$TS.tar.gz" -C "$HERE" "superclean-$CPUSER-$TS"
say "evidence bundle: $HERE/superclean-$CPUSER-$TS.tar.gz"
say "done."
