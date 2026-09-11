#!/usr/bin/env bash
# sc403-dbdump.sh - pull every SC 4.3.24 artifact out of a WordPress database
# and decode it, so the results can be read as plain text.
#
# ===========================================================================
# WHY THIS EXISTS
# ===========================================================================
# The implant keeps three families of row in wp_options (see the report, §3):
#
#   sc_*                      the obvious ones. Everybody finds these.
#   <10 hex>                  md5(ABSPATH.'opt')[0:10] - base64(gzip(core))
#   <12 hex>                  md5(ABSPATH.'93819'.name)[0:12] - base64(xor(serialize(v)))
#
# The last two do NOT start with sc_, look exactly like WordPress transient
# debris, and hold the most valuable things on the system: the service worker
# URL and the JavaScript it serves, the C2 server key, the browser payload,
# the list of administrators holding live forged sessions, and a hidden
# administrator account with its password.
#
# This script computes all of them from ABSPATH, pulls them, decodes them, and
# writes each one to its own plainly-named file. Nothing is deleted; it only
# reads.
#
# ===========================================================================
# SCOPE - READ THIS
# ===========================================================================
# It touches wp_options and nothing else, except to COUNT rows in usermeta and
# list administrator logins. It never reads post content, never reads
# customer or order data, and never dumps password hashes or email addresses.
#
# That restraint is deliberate. A full WordPress dump from a client's site is
# personal data - users, emails, hashes, and on a WooCommerce site orders and
# addresses. None of it is needed to analyse this malware, and the safest
# place for it is nowhere near your analysis directory. The attacker's own
# infrastructure (C2 hosts, their backdoor account, their payloads) is not
# personal data and is what this collects.
#
# ===========================================================================
# USAGE
# ===========================================================================
#   ./sc403-dbdump.sh /home/wpclient/public_html            # live database
#   ./sc403-dbdump.sh --sql dump.sql /home/wpclient/public_html   # from a dump
#
#   --out DIR     where to write (default ./sc403-db-<user>-<timestamp>)
#
# Live mode reads DB credentials from the site's own wp-config.php, as text -
# never by executing PHP on an infected host. The password goes into a 0600
# temp file that mysql reads via --defaults-extra-file, never onto a command
# line where `ps` would show it, and it is shredded on exit.
#
# License: GPL-2.0-or-later. No warranty.

set -uo pipefail

SQLFILE=""
OUT=""
ROOT=""

usage() { sed -n '2,50p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --sql)  SQLFILE="${2:?--sql needs a path}"; shift 2 ;;
    --out)  OUT="${2:?--out needs a path}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    -*)     echo "unknown option: $1" >&2; exit 64 ;;
    *)      ROOT="${1%/}"; shift ;;
  esac
done
[ -n "$ROOT" ] || { usage; exit 64; }

TS=$(date +%Y%m%d-%H%M%S)
[ -n "$OUT" ] || OUT="./sc403-db-$(basename "$ROOT")-$TS"
mkdir -p "$OUT" || exit 1
LOG="$OUT/dbdump.log"
say() { printf '%s\n' "$*" | tee -a "$LOG"; }

md5s() {
  if command -v md5sum >/dev/null 2>&1; then printf '%s' "$1" | md5sum | cut -d' ' -f1
  elif command -v md5 >/dev/null 2>&1;    then printf '%s' "$1" | md5 -q
  else echo "need md5sum or md5" >&2; exit 70; fi
}

A="$ROOT/"                                   # ABSPATH; trailing slash matters
N_OPT=$(md5s "${A}opt" | cut -c1-10)
say "ABSPATH            $A"
say "payload option     $N_OPT"

# Endpoint IDs. 0xFFFFFFF = 268435455, so bash arithmetic is exact.
epid() { local h; h=$(md5s "$1ep$2"); printf '%s' $(( 91000000 + 16#${h:0:7} % 8999999 )); }
say "service worker     ?p=$(epid "$A" sw)"
say "installer          ?p=$(epid "$A" inst)"

# The thirteen named private options, plus the un-suffixed one.
PRIV="sw_url sw_cached sw_config sw_config_sig srv_key page_cached js_cached \
src issued bp bu ic errors"
declare -a KEYS NAMES
KEYS+=("$(md5s "${A}93819" | cut -c1-12)"); NAMES+=("_version")
for n in $PRIV; do
  KEYS+=("$(md5s "${A}93819${n}" | cut -c1-12)"); NAMES+=("$n")
done

# ---------------------------------------------------------------------------
# Fetch one option value, from a live DB or by carving it out of a .sql dump.
#
# mysqldump writes the options table as one enormous multi-row INSERT, so a
# plain grep returns the whole statement. Split on "),(" first, then match.
# ---------------------------------------------------------------------------
MYCNF=""
cleanup() { [ -n "$MYCNF" ] && rm -f "$MYCNF"; }
trap cleanup EXIT

if [ -z "$SQLFILE" ]; then
  CFG="$ROOT/wp-config.php"
  [ -f "$CFG" ] || { say "no wp-config.php at $CFG"; exit 66; }
  wpc() { sed -n "s/.*define(\s*['\"]$1['\"]\s*,\s*['\"]\([^'\"]*\)['\"].*/\1/p" "$CFG" | head -1; }
  DB=$(wpc DB_NAME); DU=$(wpc DB_USER); DP=$(wpc DB_PASSWORD); DH=$(wpc DB_HOST)
  TP=$(sed -n "s/.*table_prefix\s*=\s*['\"]\([A-Za-z0-9_]*\)['\"].*/\1/p" "$CFG" | head -1)
  [ -n "$DB" ] && [ -n "$TP" ] || { say "could not parse wp-config.php"; exit 66; }
  command -v mysql >/dev/null 2>&1 || { say "mysql client missing; use --sql with a dump instead"; exit 69; }
  MYCNF=$(umask 077 && mktemp) || exit 1
  printf '[client]\nuser=%s\npassword=%s\nhost=%s\n' "$DU" "$DP" "${DH:-localhost}" > "$MYCNF"
  say "database           $DB (prefix $TP)"
  getopt_val() {  # $1 = option_name
    mysql --defaults-extra-file="$MYCNF" -N -B --raw "$DB" \
      -e "SELECT option_value FROM ${TP}options WHERE option_name='$1' LIMIT 1;" 2>>"$LOG"
  }
  list_names() {
    mysql --defaults-extra-file="$MYCNF" -N -B "$DB" \
      -e "SELECT option_name FROM ${TP}options WHERE option_name LIKE 'sc\\_%' OR option_name REGEXP '^[0-9a-f]{10,12}\$';" 2>>"$LOG"
  }
else
  [ -f "$SQLFILE" ] || { say "no such file: $SQLFILE"; exit 66; }
  say "reading from dump  $SQLFILE"
  # Carve one row. Values may contain escaped quotes, so stop at ',' followed
  # by the autoload column - the last quoted field of the tuple.
  getopt_val() {
    sed "s/),(/)\n(/g" "$SQLFILE" \
      | grep -m1 -F "'$1'," \
      | sed "s/.*'$1','//" \
      | sed "s/','\(auto\|yes\|no\|on\|off\)')\?[,;]\?$//"
  }
  list_names() {
    sed "s/),(/)\n(/g" "$SQLFILE" \
      | grep -oE "'(sc_[a-z_0-9]+|[0-9a-f]{10,12})','" \
      | tr -d "'," | sort -u
  }
fi

# ---------------------------------------------------------------------------
# Decoders. Both are pure text transforms; nothing is unserialised or run.
# ---------------------------------------------------------------------------
xor_b64() {   # stdin: base64( keybyte . xor(serialize(v), keybyte) )
  if command -v perl >/dev/null 2>&1; then
    perl -MMIME::Base64 -e 'local $/; my $b=decode_base64(<STDIN>); exit 1 if length($b)<2;
      my $k=substr($b,0,1); print join "", map { chr(ord($_)^ord($k)) } split //, substr($b,1);'
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import sys,base64
b=base64.b64decode(sys.stdin.read()); k=b[0]
sys.stdout.write("".join(chr(c^k) for c in b[1:]))'
  else
    cat
  fi
}

# ---------------------------------------------------------------------------
# 1. The plaintext rows. sc_c2_cache is the live C2 list and needs no decoding.
# ---------------------------------------------------------------------------
say ""
say "=== plaintext sc_* rows ==="
: > "$OUT/plaintext-options.txt"
for n in sc_c2_cache sc_last_c2 sc_last_rpc sc_sw_last_url sc_sw_had \
         sc_initialized sc_seen_ver sc_own_rec sc_own_manifest sc_persist_manifest \
         sc_ini_pending sc_ini_fail sc_ini_dead sc_ht_fail sc_pad_off_ts \
         sc_oc_dat_ok sc_lb_mode sc_last_hb sc_fetch_fails sc_last_fetch_ts \
         sc_last_fetch_fail_ts sc_last_recovery_check sc_last_tmpclean \
         sc_js_printed_ts sc_sw_ep_hits sc_sw_ep_last sc_reins_adv sc_reins_db \
         sc_reins_oc sc_reins_mu sc_reins_th sc_payload_persistent cron; do
  v=$(getopt_val "$n")
  [ -n "$v" ] || continue
  printf '%s\t%s\n' "$n" "$v" >> "$OUT/plaintext-options.txt"
  case "$n" in
    sc_c2_cache|sc_last_c2|sc_last_rpc|sc_sw_last_url|sc_ini_dead|sc_reins_*)
      say "  $n = $(printf '%s' "$v" | tr '\n' ' ' | cut -c1-140)" ;;
  esac
done
say "  -> $OUT/plaintext-options.txt"

# ---------------------------------------------------------------------------
# 2. The derived private options, decoded one file each.
# ---------------------------------------------------------------------------
say ""
say "=== derived private options (md5(ABSPATH.93819.name)[0:12]) ==="
i=0
while [ $i -lt ${#KEYS[@]} ]; do
  k="${KEYS[$i]}"; n="${NAMES[$i]}"; i=$((i+1))
  v=$(getopt_val "$k")
  if [ -z "$v" ]; then say "  $n ($k)  - absent"; continue; fi
  printf '%s' "$v" > "$OUT/raw-$n.b64"
  printf '%s' "$v" | xor_b64 > "$OUT/decoded-$n.txt"
  sz=$(wc -c < "$OUT/decoded-$n.txt" | tr -d ' ')
  say "  $n ($k)  -> decoded-$n.txt  (${sz} bytes)"
done

# ---------------------------------------------------------------------------
# 3. The payload row. base64(gzip(core)) - no XOR on this one.
#    Recovering it and hashing it is the cleanest possible confirmation that
#    you are looking at the same build this analysis describes.
# ---------------------------------------------------------------------------
say ""
say "=== payload row $N_OPT (base64 + gzip) ==="
v=$(getopt_val "$N_OPT")
if [ -n "$v" ]; then
  printf '%s' "$v" > "$OUT/raw-payload.b64"
  if command -v base64 >/dev/null 2>&1; then
    base64 -d < "$OUT/raw-payload.b64" 2>/dev/null > "$OUT/payload.gz" \
      || base64 -D < "$OUT/raw-payload.b64" 2>/dev/null > "$OUT/payload.gz"
    gunzip -c "$OUT/payload.gz" > "$OUT/recovered-core.php" 2>/dev/null
    if [ -s "$OUT/recovered-core.php" ]; then
      H=$( { sha256sum "$OUT/recovered-core.php" 2>/dev/null || shasum -a 256 "$OUT/recovered-core.php"; } | cut -d' ' -f1)
      say "  recovered core     $(wc -c < "$OUT/recovered-core.php" | tr -d ' ') bytes"
      say "  sha256             $H"
      if [ "$H" = "0e0d2a0220a51603af3b2c4a5311514c77d00a5fd0e9f2467bf178d92460fb13" ]; then
        say "  ** MATCHES the published canonical SCV:4.3.24 core **"
      else
        say "  ** does NOT match the published 4.3.24 hash - different build, keep this file **"
      fi
    fi
  fi
else
  say "  absent"
fi

# ---------------------------------------------------------------------------
# 4. What else is hiding. Any 10- or 12-hex option name we did NOT predict
#    means the derivation missed - a moved site, a symlinked docroot, or a
#    build with roles this analysis has not seen. Report, never assume.
# ---------------------------------------------------------------------------
say ""
say "=== unexplained hex-named options (should be empty) ==="
list_names | grep -E '^[0-9a-f]{10,12}$' | sort -u > "$OUT/all-hex-names.txt"
{ printf '%s\n' "$N_OPT"; printf '%s\n' "${KEYS[@]}"; } | sort -u > "$OUT/.predicted"
comm -23 "$OUT/all-hex-names.txt" "$OUT/.predicted" | tee -a "$LOG" | sed 's/^/  /'
rm -f "$OUT/.predicted"

# ---------------------------------------------------------------------------
# 5. Accounts and sessions. Logins and counts only - no hashes, no emails.
# ---------------------------------------------------------------------------
if [ -z "$SQLFILE" ]; then
  say ""
  say "=== administrators (raw SQL; the implant cannot filter this) ==="
  mysql --defaults-extra-file="$MYCNF" -N -B "$DB" -e \
    "SELECT u.user_login, u.user_registered FROM ${TP}users u
     JOIN ${TP}usermeta m ON m.user_id=u.ID
     WHERE m.meta_key='${TP}capabilities' AND m.meta_value LIKE '%administrator%';" 2>>"$LOG" \
    | tee -a "$LOG" | sed 's/^/  /'
  say "  (compare with the Users screen; admin_|adm_|administrator_|backup_ + hex is the implant's)"
  say ""
  say "=== live sessions ==="
  say "  session_tokens rows: $(mysql --defaults-extra-file="$MYCNF" -N -B "$DB" -e \
    "SELECT COUNT(*) FROM ${TP}usermeta WHERE meta_key='session_tokens';" 2>>"$LOG")"
fi

say ""
say "done. everything is under: $OUT"
say ""
say "Start with these:"
say "  plaintext-options.txt   sc_c2_cache is the live C2 host list, in clear"
say "  decoded-sw_url.txt      the service worker URL registered in admin browsers"
say "  decoded-sw_cached.txt   the worker JavaScript actually served to them"
say "  decoded-page_cached.txt the payload run in the admin page context"
say "  decoded-issued.txt      which admins hold live forged sessions, and until when"
say "  decoded-bu.txt / bp     the implant's own hidden administrator account"
