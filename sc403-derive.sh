#!/usr/bin/env bash
# sc403-derive.sh - compute every SC 4.3.24 identifier for a site, from ABSPATH.
#
# SC 4.3.24 has no stable file hashes (every write is padded with 4-5.5 MB of
# random hex) and no fixed filenames. What it does have is a naming algorithm,
# and the algorithm takes exactly one input the defender already knows: the
# site's ABSPATH. Everything below is therefore computable offline, before you
# touch the server, and is exact rather than heuristic.
#
# Three families of identifier, all recovered from the deobfuscated core:
#
#   FILES      substr(md5(ABSPATH . role), 0, n)
#              core L278 sc_hidden_core_cache_path() and its siblings
#
#   ENDPOINTS  91000000 + hexdec(md5(ABSPATH . 'ep' . role)[0:7]) % 8999999
#              core L1392 sc_derived_endpoint_id()
#              These are the `?p=<id>` URLs. `sw` serves the malicious service
#              worker JavaScript to admins' browsers; `inst` includes a cached
#              installer for its side effects and then 404s.
#
#   OPTIONS    substr(md5(ABSPATH . '93819' . name), 0, 12)
#              core L1384 sc_derived_option_key(), where 93819 is the same
#              constant used as the timestomp residue (core L271).
#              Values are base64( keybyte . xor(serialize(v), keybyte) ).
#
# ABSPATH is the WordPress root WITH a trailing slash, after backslash
# normalisation - core L1372 sc_normalized_site_root().
#
# Usage:
#   ./sc403-derive.sh /home/user/public_html
#   ./sc403-derive.sh --tsv /home/user/public_html /home/user/site2
#   ./sc403-derive.sh --find /home/user          # derive for every WP root below
#   ./sc403-derive.sh --sql /home/user/public_html   # emit the option SELECTs
#   ./sc403-derive.sh --decode 'BASE64STRING'    # decode one private option
#
# Reads nothing but the paths you give it and does not touch the database.
# --decode is pure arithmetic on stdin-supplied text.
#
# License: GPL-2.0-or-later. No warranty.

set -uo pipefail

MODE=text
ROOTS=()
DECODE=""

usage() { sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --tsv)    MODE=tsv; shift ;;
    --sql)    MODE=sql; shift ;;
    --ioc)    MODE=ioc; shift ;;
    --decode) DECODE="${2:?--decode needs a base64 string}"; shift 2 ;;
    --find)   shift
              base="${1:?--find needs a directory}"; shift
              while IFS= read -r r; do ROOTS+=("$r"); done < <(
                find "$base" -maxdepth 6 -type d -name wp-admin 2>/dev/null \
                  | sed 's|/wp-admin$||' | sort -u)
              ;;
    -h|--help) usage; exit 0 ;;
    -*)       echo "unknown option: $1" >&2; exit 64 ;;
    *)        ROOTS+=("$1"); shift ;;
  esac
done

# ---------------------------------------------------------------------------
# Primitives. md5sum on Linux, md5 -q on macOS/BSD.
# ---------------------------------------------------------------------------
md5s() {
  if command -v md5sum >/dev/null 2>&1; then printf '%s' "$1" | md5sum | cut -d' ' -f1
  elif command -v md5 >/dev/null 2>&1;    then printf '%s' "$1" | md5 -q
  else echo "need md5sum or md5" >&2; exit 70; fi
}

# 91000000 + (top 7 hex nibbles of the digest) % 8999999.
# 0xFFFFFFF is 268435455, so this stays inside a 32-bit signed int and bash
# arithmetic is exact - no bc, no python required.
endpoint_id() { # $1 = ABSPATH (trailing slash), $2 = role
  local h dec
  h=$(md5s "$1ep$2"); h=${h:0:7}
  dec=$((16#$h))
  printf '%s' $(( 91000000 + dec % 8999999 ))
}

option_key() { # $1 = ABSPATH, $2 = option name
  md5s "$1${TIMESTOMP}$2" | cut -c1-12
}

TIMESTOMP=93819   # core L271 sc_timestomp_offset()

# Every private option name reachable from the core's
# sc_get_private_setting()/sc_set_private_setting() call sites.
PRIV_OPTS="sw_url sw_cached sw_config sw_config_sig srv_key page_cached js_cached src issued bp bu ic errors"

# ---------------------------------------------------------------------------
# --decode: reverse sc_load_encrypted_option() (core L1337).
#   base64_decode -> first byte is the XOR key -> XOR the rest -> serialize()
# Pure text transform; nothing is unserialised or executed.
# ---------------------------------------------------------------------------
if [ -n "$DECODE" ]; then
  if command -v perl >/dev/null 2>&1; then
    printf '%s' "$DECODE" | perl -MMIME::Base64 -e '
      local $/; my $b = decode_base64(<STDIN>);
      die "too short\n" if length($b) < 2;
      my $k = substr($b, 0, 1);
      my $o = join "", map { chr(ord($_) ^ ord($k)) } split //, substr($b, 1);
      print $o, "\n";'
  elif command -v python3 >/dev/null 2>&1; then
    printf '%s' "$DECODE" | python3 -c '
import sys, base64
b = base64.b64decode(sys.stdin.read())
k = b[0]
sys.stdout.write("".join(chr(c ^ k) for c in b[1:]) + "\n")'
  else
    echo "need perl or python3 to decode" >&2; exit 70
  fi
  exit 0
fi

[ ${#ROOTS[@]} -gt 0 ] || { usage; exit 64; }

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
[ "$MODE" = tsv ] && printf 'root\tkind\tname\tvalue\n'

for root in "${ROOTS[@]}"; do
  A="${root%/}/"                      # ABSPATH: trailing slash is load-bearing

  HTL=$(md5s "${A}htl"  | cut -c1-8)
  LDR=$(md5s "${A}ldr"  | cut -c1-8)
  DIRH=$(md5s "${A}dir" | cut -c1-8)
  CORE=$(md5s "${A}core"| cut -c1-8)
  ZIP=$(md5s "${A}zip"  | cut -c1-8)
  INST=$(md5s "${A}inst"| cut -c1-8)
  OC=$(md5s "${A}oc"    | cut -c1-8)
  OWN=$(md5s "${A}own"  | cut -c1-8)
  G=$(md5s "${A}g"      | cut -c1-8)
  OPT=$(md5s "${A}opt"  | cut -c1-10)
  WK=$(md5s "${A}wk"    | cut -c1-12)
  JSATTR=$(md5s "${A}js"| cut -c1-6)

  EP_SW=$(endpoint_id "$A" sw)
  EP_IN=$(endpoint_id "$A" inst)

  case "$MODE" in
  tsv)
    for pair in "file:htl:wp-content/${HTL}.php" \
                "file:ldr:wp-content/.${LDR}.php" \
                "file:dir:wp-content/.sc_${DIRH}/" \
                "file:core:wp-content/.sc_${DIRH}/core_${CORE}.php" \
                "file:zip:wp-content/${ZIP}.zip" \
                "file:inst:wp-content/.sc_${DIRH}/${INST}.php" \
                "file:oc:wp-content/.wp-object-cache-${OC}.dat" \
                "file:own:wp-content/.sc_${DIRH}/own_${OWN}.php" \
                "file:g:wp-content/.g_${G}.php" \
                "option:payload:${OPT}" \
                "endpoint:sw:?p=${EP_SW}" \
                "endpoint:inst:?p=${EP_IN}" \
                "token:writeKey:${WK}" \
                "token:jsAttr:data-sc-${JSATTR}"; do
      IFS=: read -r k n v <<<"$pair"
      printf '%s\t%s\t%s\t%s\n' "$root" "$k" "$n" "$v"
    done
    for o in $PRIV_OPTS; do
      printf '%s\toption\t%s\t%s\n' "$root" "$o" "$(option_key "$A" "$o")"
    done
    ;;

  sql)
    cat <<SQL
-- $root  (ABSPATH $A)
-- Run against this site's database with its own table prefix substituted for
-- wp_. Capture this BEFORE any database cleanup: sw_url is what tells the
-- neutralizer exactly which service worker to revoke, and it is the only
-- record of it once the row is gone.
SELECT option_name, option_value FROM wp_options WHERE option_name IN (
$(for o in $PRIV_OPTS; do printf "  '%s',  -- %s\n" "$(option_key "$A" "$o")" "$o"; done | sed '$ s/,  --/   --/')
);
-- plaintext siblings the implant keeps unencrypted:
SELECT option_name, option_value FROM wp_options
 WHERE option_name IN ('sc_sw_last_url','sc_sw_had','sc_sw_ep_hits','sc_sw_ep_last')
    OR option_name LIKE 'sc\\_%';
-- decode an encrypted value with:  ./sc403-derive.sh --decode '<option_value>'
SQL
    ;;

  ioc)
    # One extended-regex alternation, ready to paste into a scanner.
    printf '%s\n' "${HTL}[.]php|[.]${LDR}[.]php|${LDR}[.]php|[.]sc_${DIRH}|core_${CORE}[.]php|${ZIP}[.]zip|own_${OWN}[.]php|${INST}[.]php|[.]g[a-z]{0,3}_${G}|${OC}[.]dat|${OPT}|p=${EP_SW}|p=${EP_IN}|data-sc-${JSATTR}"
    ;;

  *)
    cat <<TXT
$root
  ABSPATH                 $A

  FILES  (all padded; hashes are worthless, names are not)
    visible loader        wp-content/${HTL}.php
    hidden loader         wp-content/.${LDR}.php
    staging dir           wp-content/.sc_${DIRH}/
    canonical core        wp-content/.sc_${DIRH}/core_${CORE}.php
    installer template    wp-content/.sc_${DIRH}/${INST}.php
    state manifest        wp-content/.sc_${DIRH}/own_${OWN}.php
    replica zip           wp-content/${ZIP}.zip
    object-cache replica  wp-content/.wp-object-cache-${OC}.dat[.lkg]
    guard files           wp-content/.g_${G}.php  .gl_/.gm_/.gp_/.gs_/.gv_${G}

  BROWSER ENDPOINTS  (this is what reaches your administrators)
    service worker        ?p=${EP_SW}
                          -> the scriptURL registered in every admin browser
    installer             ?p=${EP_IN}
                          -> where the worker POSTs C2-supplied payloads

  DATABASE
    payload row           ${OPT}
    private options       md5(ABSPATH . 93819 . name)[0:12]
TXT
    for o in $PRIV_OPTS; do printf '      %-14s %s\n' "$o" "$(option_key "$A" "$o")"; done
    printf '      %-14s %s\n' "(empty)" "$(option_key "$A" "")"
    cat <<TXT

  TOKENS
    writeKey              ${WK}
    injected script attr  data-sc-${JSATTR}
    timestomp residue     mtime % 100000 == ${TIMESTOMP}

TXT
    ;;
  esac
done
