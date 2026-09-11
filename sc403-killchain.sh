#!/usr/bin/env bash
#
# sc403-killchain.sh - ordered eradication of the SC 4.3.24 self-healing
# WordPress implant (aliases seen in the wild: "Elite Module Cue",
# "Trace Scanner Lite", "trace-store-x").
#
# RUN THIS ON THE SERVER, AS root OR AS THE HOSTING ACCOUNT USER.
# Not on your laptop. It expects a Linux host with the sites on disk.
#
#   ./sc403-killchain.sh                      # DRY RUN - prints, changes nothing
#   ./sc403-killchain.sh --execute            # actually do it
#   ./sc403-killchain.sh --execute --no-phase5   # this site only, no sibling sweep
#   ./sc403-killchain.sh --phase5-only        # only find/contain sibling sites
#
# THE ORDER IS THE WHOLE POINT.
#   K0 snapshot -> K1 contain -> K2 restart PHP pool -> K3 sever auto_prepend_file
#   -> K4 files -> K5 database -> K6 rotate -> K7 service worker -> K8 harden
# Deleting files (K4) before restarting the pool (K2) is the single mistake that
# makes this malware look unkillable: the payload lives in System V shared
# memory and in a CLI php daemon, and both rewrite the files you just removed.
#
# License: GPL-2.0-or-later. No warranty. Read it before you run it.

set -uo pipefail
shopt -s nullglob dotglob

VERSION="1.0.0"

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------

EXECUTE=0             # 0 = dry run
SITES=()              # explicit --path targets
DO_PHASE5=1           # sibling-site sweep (lateral spread containment)
PHASE5_ONLY=0
DO_DB=1
VACCINE=0             # plant skip-markers on clean sites
POOL_CMD=""           # explicit service restart command
EVID_DIR=""           # where the evidence snapshot goes
RESET_CRON=0
ASSUME_YES=0

usage() {
  sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'
  cat <<'EOF'
Options:
  --execute           apply changes (default: dry run)
  -p, --path DIR      WordPress root to treat as primary (repeatable;
                      default: auto-discover every root you can read)
  --no-phase5         do NOT sweep sibling sites (single-site mode).
                      WARNING: any infected sibling WILL reinfect this site.
  --phase5-only       only discover + report/clean sibling sites and exit
  --vaccinate         after cleaning, plant an inert marker file that makes
                      the spread routine skip this site permanently
  --no-db             skip database cleanup
  --reset-cron        delete the whole 'cron' option row (WP rebuilds it);
                      removes sc_cron_guard without unserializing PHP data
  --pool-cmd CMD      command that restarts YOUR php workers, e.g.
                      'systemctl restart php8.2-fpm' (root) or left empty
                      for the shared-hosting fallback (killall own procs)
  --evidence DIR      where to write the forensic snapshot (default: ~/sc403-evidence-<ts>)
  --yes               do not ask for confirmation in --execute mode
  -h, --help          this text
EOF
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --execute)      EXECUTE=1; shift ;;
    -p|--path)      SITES+=("${2:?}"); shift 2 ;;
    --no-phase5)    DO_PHASE5=0; shift ;;
    --phase5-only)  PHASE5_ONLY=1; shift ;;
    --vaccinate)    VACCINE=1; shift ;;
    --no-db)        DO_DB=0; shift ;;
    --reset-cron)   RESET_CRON=1; shift ;;
    --pool-cmd)     POOL_CMD="${2:?}"; shift 2 ;;
    --evidence)     EVID_DIR="${2:?}"; shift 2 ;;
    --yes)          ASSUME_YES=1; shift ;;
    -h|--help)      usage ;;
    -v|--version)   echo "sc403-killchain.sh $VERSION"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 64 ;;
  esac
done

# ---------------------------------------------------------------------------
# Output / helpers
# ---------------------------------------------------------------------------

TS=$(date +%Y%m%d-%H%M%S)
[ -n "$EVID_DIR" ] || EVID_DIR="${HOME:-/tmp}/sc403-evidence-$TS"
QUAR="$EVID_DIR/quarantine"
LOG="$EVID_DIR/killchain.log"

say()  { printf '%s\n' "$*" | tee -a "$LOG" 2>/dev/null; }
act()  { # act <description> <command...>  - honours dry run
  local desc="$1"; shift
  if [ "$EXECUTE" -eq 1 ]; then
    say "[DO   ] $desc"
    "$@" 2>>"$LOG" || say "[FAIL ] $desc (see log)"
  else
    say "[dry  ] $desc"
  fi
}
crit() { say "[FOUND] $*"; }
note() { say "[info ] $*"; }
head1(){ say ""; say "===== $* ====="; }

md5_str() {
  if command -v md5sum >/dev/null 2>&1; then printf '%s' "$1" | md5sum | cut -d' ' -f1
  else printf '%s' "$1" | md5 -q; fi
}

# quarantine <file> <site-tag>  - move, never delete; strip write bits
quarantine() {
  local f="$1" tag="$2" dest
  [ -e "$f" ] || return 0
  dest="$QUAR/$tag$(dirname "$f" | tr '/' '_')"
  act "quarantine $f" mkdir -p "$dest"
  act "  -> $dest/" mv -f "$f" "$dest/" 
}

# ---------------------------------------------------------------------------
# Artifact names - all derived from md5(ABSPATH + role). ABSPATH ends in '/'.
# Verified against a live 4.3.24 infection:
#   dir->.sc_XXXXXXXX  core->core_XXXXXXXX.php  g->guard suffix  opt->option(10)
#   htl->visible loader  ldr->hidden loader  zip->replica zip  inst->installer
#   oc->.wp-object-cache-XXXXXXXX.dat  oc_m->OC marker  wk->writeKey  own->manifest
# ---------------------------------------------------------------------------

derive_names() { # $1 = site root (no trailing slash); sets N_* globals
  local A="$1/"
  N_DIR=".sc_$(md5_str "${A}dir"   | cut -c1-8)"
  N_CORE="core_$(md5_str "${A}core" | cut -c1-8).php"
  N_G=$(md5_str "${A}g"    | cut -c1-8)
  N_OPT=$(md5_str "${A}opt"  | cut -c1-10)
  N_HTL="$(md5_str "${A}htl"  | cut -c1-8).php"
  N_LDR="$(md5_str "${A}ldr"  | cut -c1-8).php"
  N_ZIP="$(md5_str "${A}zip"  | cut -c1-8).zip"
  N_INST="$(md5_str "${A}inst" | cut -c1-8)"
  N_OC=$(md5_str "${A}oc"   | cut -c1-8)
  N_OWN="own_$(md5_str "${A}own"  | cut -c1-8).php"
}

# ---------------------------------------------------------------------------
# The SECOND naming family: private wp_options rows.
#
#   substr(md5(ABSPATH . "93819" . <name>), 0, 12)
#
# 93819 is the same constant used as the timestomp residue, reused here as a
# salt. Values are base64( keybyte . xor(serialize(v), keybyte) ).
#
# These rows do NOT begin with "sc_" - they are twelve hex characters and look
# exactly like WordPress transient debris, which is why every cleanup that
# matches on 'sc\_%' leaves them behind. Between them they hold the service
# worker URL and its JavaScript, the C2 server key, the list of administrators
# holding live forged sessions, and a hidden administrator account with its
# password in reversible form.
#
# Observed on a live 4.3.24 infection (/home/wpclient/public_html):
#   3401877c1abe -> s:35:"https://<site>/?p=98376420";   (sw_url)
#   99f0f2a7d756 -> s:24:"administrator_7e1b9c4d02";     (backdoor login)
#   5c9659c9ab74 -> s:24:"3f9a2c7e5d18b0461c7fa93e";     (its password)
#   ebbf87d7bae1 -> s:32:"b7d41e0a62c9f3581ade47c0b2695f3d";
#   4849e89f424c -> 4.3.24|php.euc-eludom-etile          (slug, REVERSED, plaintext)
#
# The empty name is also used, holding the installed version for the boot guard.
# ---------------------------------------------------------------------------

SC_PRIV_OPTS="sw_url sw_cached sw_config sw_config_sig srv_key page_cached \
js_cached src issued bp bu ic errors"

derive_option_keys() { # $1 = site root; sets N_PRIV_KEYS (space separated)
  local A="$1/" n
  N_PRIV_KEYS="$(md5_str "${A}93819" | cut -c1-12)"     # the un-suffixed key
  for n in $SC_PRIV_OPTS; do
    N_PRIV_KEYS="$N_PRIV_KEYS $(md5_str "${A}93819${n}" | cut -c1-12)"
  done
}

# Browser-facing endpoint IDs: 91000000 + hexdec(md5(ABSPATH.'ep'.role)[0:7]) % 8999999
# 0xFFFFFFF is 268435455, so bash arithmetic is exact - no bc needed.
derive_endpoint_ids() { # $1 = site root; sets N_EP_SW / N_EP_INST
  local A="$1/" h
  h=$(md5_str "${A}epsw");   N_EP_SW=$((  91000000 + 16#${h:0:7} % 8999999 ))
  h=$(md5_str "${A}epinst"); N_EP_INST=$((91000000 + 16#${h:0:7} % 8999999 ))
}

# ---------------------------------------------------------------------------
# Site discovery - the SAME roots the malware walks (decoded core L5778),
# so the sweep covers everything its spread routine can reach.
# ---------------------------------------------------------------------------

discover_sites() {
  local roots=() r
  for r in "${SITES[@]}"; do roots+=("$(dirname "$r")"); done
  roots+=("${HOME:-}" /home /var/www /var/www/vhosts /var/www/html /srv/www /srv/users /usr/local/www)
  for r in "${roots[@]}"; do
    [ -n "$r" ] && [ -d "$r" ] && [ -r "$r" ] || continue
    find "$r" -maxdepth 6 -type d -name wp-admin 2>/dev/null | sed 's|/wp-admin$||'
  done | { printf '%s\n' "${SITES[@]:-}"; cat; } | awk 'NF && !x[$0]++'
}

SC_MARKERS='SC_DB_BEGIN|SC_ADV_BEGIN|SC_OC_BEGIN|SC_TH_BEGIN|SC_WC|SCV:[0-9]|SCD1:|SCSHM1:|sc_payload_persistent|sc_cron_fetch|sc_cron_guard|0x3bc5de30'

# is_infected <root> -> 0 when any SC artifact exists (fast structural probe)
is_infected() {
  local root="$1" wc="$1/wp-content" f
  derive_names "$root"
  for f in "$wc/$N_DIR" "$wc/$N_HTL" "$wc/.$N_LDR" "$wc/$N_LDR" \
           "$wc/$N_ZIP" "$wc/.wp-object-cache-$N_OC.dat"; do
    [ -e "$f" ] && return 0
  done
  grep -qs 'auto_prepend_file' "$root/.htaccess" "$root/.user.ini" \
       "$wc/.htaccess" "$wc/.user.ini" 2>/dev/null && return 0
  grep -qsE "$SC_MARKERS" "$wc/db.php" "$wc/advanced-cache.php" \
       "$wc/object-cache.php" 2>/dev/null && return 0
  # MU/plugin bodies: only need the first 4 KB of each candidate
  for f in "$wc"/mu-plugins/*.php "$wc"/plugins/*/*.php; do
    [ "$(basename "$f")" = "sc403-vaccine.php" ] && continue
    head -c 4096 "$f" 2>/dev/null | grep -qE "$SC_MARKERS" && return 0
  done
  return 1
}

# ---------------------------------------------------------------------------
# K0 - SNAPSHOT. Files + DB dump BEFORE any change. Timestamps are forged,
# so this snapshot is your only trustworthy evidence.
# ---------------------------------------------------------------------------

k0_snapshot() { # $1 = site root
  local root="$1" tag; tag=$(basename "$root")
  head1 "K0 snapshot: $root"
  act "mkdir evidence dir $EVID_DIR" mkdir -p "$EVID_DIR" "$QUAR"
  act "tar wp-content metadata + suspect files" \
    tar --ignore-failed-read -czf "$EVID_DIR/files-$tag-$TS.tgz" \
      -C "$(dirname "$root")" \
      "$(basename "$root")/.htaccess" "$(basename "$root")/.user.ini" \
      "$(basename "$root")/wp-config.php" "$(basename "$root")/wp-content"
  if [ "$DO_DB" -eq 1 ] && command -v mysqldump >/dev/null 2>&1 && load_db_creds "$root"; then
    act "mysqldump $DB_NAME" sh -c \
      "mysqldump --defaults-extra-file='$MYCNF' --single-transaction --quick '$DB_NAME' | gzip > '$EVID_DIR/db-$tag-$TS.sql.gz'"
  fi
  # record process + shm state before we destroy it
  { ps aux 2>/dev/null | grep -iE 'php|lsphp' | grep -v grep
    command -v ipcs >/dev/null 2>&1 && ipcs -m; } >> "$EVID_DIR/runtime-$tag-$TS.txt" 2>/dev/null
}

# ---------------------------------------------------------------------------
# K1 - CONTAIN. Serve a static maintenance page so no PHP entry point runs.
# ---------------------------------------------------------------------------

k1_contain() { # $1 = site root
  local root="$1"
  head1 "K1 contain: $root"
  act "write maintenance page" sh -c "printf 'Maintenance in progress.\n' > '$root/.maintenance-sc403.html'"
  act "prepend RewriteRule to .htaccess (all traffic -> static page)" sh -c \
    "printf 'RewriteEngine On\nRewriteCond %%{REQUEST_URI} !maintenance-sc403\nRewriteRule .* /.maintenance-sc403.html [R=503,L]\n' | cat - '$root/.htaccess' 2>/dev/null > '$root/.htaccess.sc403tmp' && mv '$root/.htaccess.sc403tmp' '$root/.htaccess'"
  note "undo later: remove the 3 RewriteRule lines + .maintenance-sc403.html"
}

# ---------------------------------------------------------------------------
# K2 - KILL THE RUNTIME. Pool restart clears: cached .user.ini (300 s TTL),
# OPcache, the SysV shared-memory replica, and the CLI guard daemon.
# DOING THIS BEFORE K4 IS WHAT MAKES THE CLEANUP STICK.
# ---------------------------------------------------------------------------

# Who the malware's processes actually belong to.
#
# This is load-bearing and it is easy to get wrong. The implant's CLI guard
# daemon, its shared-memory segment and the PHP workers all belong to the site's
# OS user - NOT to whoever is running this script. Scoping K2 to `id -un` means
# that running the script as root (which the header invites you to do, and which
# the account-wide wrapper requires) looks for root's php processes, finds none,
# reports success, and leaves the daemon and the shm replica alive. Then K4
# deletes the files and they come straight back. That is the exact failure this
# whole script exists to prevent, so derive the owner from the site itself.
site_owner() { # $1 = site root
  stat -c %U "$1" 2>/dev/null || stat -f %Su "$1" 2>/dev/null
}

k2_kill_runtime() { # $1 = site root
  local root="$1" pid key seg owner me
  head1 "K2 kill runtime"

  me=$(id -un)
  owner=$(site_owner "$root")
  [ -n "$owner" ] || owner="$me"

  if [ "$owner" != "$me" ] && [ "$(id -u)" -ne 0 ]; then
    crit "$root is owned by '$owner' but this script is running as '$me'."
    note "K2 cannot see that user's PHP processes or shared memory, so the guard"
    note "daemon and the SysV replica will survive and rebuild whatever K4 deletes."
    note "Rerun as root, or as '$owner'. Continuing would be worse than stopping."
    return 1
  fi
  [ "$owner" = "$me" ] || note "running as $me; targeting processes owned by $owner"
  # 2a. the guard daemon - its PID is helpfully recorded in .gl_<hash>
  derive_names "$root"
  for f in "$root/wp-content/$N_DIR/.gl_$N_G" "$root"/wp-content/.gl_* "$root"/wp-includes/.gl_*; do
    [ -f "$f" ] || continue
    pid=$(tr -dc '0-9' < "$f")
    [ -n "$pid" ] && act "kill guard daemon PID $pid (from $(basename "$f"))" kill -9 "$pid"
  done
  # 2b. any CLI php owned by us that is NOT a child of cron/sshd - report + kill
  ps -u "$owner" -o pid=,comm=,args= 2>/dev/null | grep -E 'php' | grep -v killchain | \
  while read -r pid comm args; do
    crit "php process: $pid $args"
    act "kill $pid" kill -9 "$pid"
  done
  # 2c. SysV shared memory owned by us (the SCSHM1 replica lives here)
  if command -v ipcs >/dev/null 2>&1; then
    ipcs -m 2>/dev/null | awk -v u="$owner" '$3==u {print $2}' | while read -r seg; do
      crit "shm segment $seg (owned by $owner)"
      act "ipcrm -m $seg" ipcrm -m "$seg"
    done
  fi
  # 2d. restart the pool
  if [ -n "$POOL_CMD" ]; then
    act "pool restart: $POOL_CMD" sh -c "$POOL_CMD"
  else
    act "shared-hosting fallback: kill $owner's lsphp/php-fpm workers" \
      sh -c "pkill -9 -u '$owner' -f 'lsphp|php-fpm|php-cgi' || true"
    note "no --pool-cmd given; if root, prefer: systemctl restart php*-fpm (or lsws)"
  fi
}

# ---------------------------------------------------------------------------
# K3 - SEVER PRE-WORDPRESS EXECUTION. Remove auto_prepend_file everywhere.
# Done AFTER K2 so no worker still holds the cached directive.
# ---------------------------------------------------------------------------

strip_prepend_file() { # $1 = config file
  local f="$1"
  [ -f "$f" ] || return 0
  if grep -qs 'auto_prepend_file' "$f"; then
    crit "auto_prepend_file in $f"
    act "strip auto_prepend_file lines from $f" sh -c \
      "cp -p '$f' '$QUAR/' 2>/dev/null; sed -i.sc403bak -E '/auto_prepend_file/d; /<IfModule (mod_php|litespeed)/d; /^<\/IfModule>$/d' '$f' && rm -f '$f.sc403bak'"
  fi
}

k3_sever_prepend() { # $1 = site root
  local root="$1" d="$1"
  head1 "K3 sever auto_prepend_file: $root"
  while :; do
    for n in .user.ini .htaccess php.ini; do strip_prepend_file "$d/$n"; done
    [ "$d" = "/" ] || [ "$d" = "${HOME:-/}" ] && break
    case "$d" in /home|/var|/srv) break;; esac
    d=$(dirname "$d")
  done
  strip_prepend_file "$root/wp-content/.user.ini"
  strip_prepend_file "$root/wp-content/.htaccess"
}

# ---------------------------------------------------------------------------
# K4 - REMOVE EVERY FILE NODE. Quarantine (never delete) in one pass.
# ---------------------------------------------------------------------------

has_watermark() { # mtime % 100000 == 93819 ?
  local m
  m=$(stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null) || return 1
  [ $((m % 100000)) -eq 93819 ]
}

k4_files() { # $1 = site root
  local root="$1" wc="$1/wp-content" tag f d
  tag=$(basename "$root")
  head1 "K4 file nodes: $root"
  derive_names "$root"

  # 4a. loaders, staging dir, replicas - names computed from ABSPATH
  for f in "$wc/$N_HTL" "$wc/$N_LDR" "$wc/.$N_LDR" "$wc/$N_DIR" "$wc/$N_ZIP" \
           "$wc/.wp-object-cache-$N_OC.dat" "$wc/.wp-object-cache-$N_OC.dat.lkg" \
           "$wc/$N_OWN"; do
    [ -e "$f" ] && { crit "artifact $f"; quarantine "$f" "$tag"; }
  done

  # 4b. guard + stub dotfiles wherever they hide
  for d in "$wc" "$root/wp-includes" "$wc/$N_DIR"; do
    for f in "$d"/.g_*.php "$d"/.gl_* "$d"/.gm_* "$d"/.gp_* "$d"/.gs_* \
             "$d"/.gt_* "$d"/.gv_* "$d"/.gx_* "$d"/.gk_* "$d"/.gsu_* "$d"/.grd_* \
             "$d"/.kk_* "$d"/.rd_* "$d"/.sd_* "$d"/.bt_* "$d"/.sc_* "$d"/.wp-object-cache-*; do
      [ -e "$f" ] && { crit "guard/stub $f"; quarantine "$f" "$tag"; }
    done
  done

  # 4c. drop-ins - only when they carry SC markers (legit ones stay)
  for f in "$wc/db.php" "$wc/advanced-cache.php" "$wc/object-cache.php"; do
    [ -f "$f" ] && grep -qsE "$SC_MARKERS" "$f" && { crit "infected drop-in $f"; quarantine "$f" "$tag"; }
  done

  # 4d. MU-plugins and plugins: markers OR timestomp watermark
  for f in "$wc"/mu-plugins/*.php; do
    [ "$(basename "$f")" = "sc403-vaccine.php" ] && continue
    if head -c 4096 "$f" | grep -qsE "$SC_MARKERS" || has_watermark "$f"; then
      crit "MU-plugin payload $f"; quarantine "$f" "$tag"
    fi
  done
  for d in "$wc"/plugins/*/; do
    f="$d$(basename "$d").php"
    if [ -f "$f" ] && { head -c 4096 "$f" | grep -qsE "$SC_MARKERS" || has_watermark "$f"; }; then
      crit "plugin twin $d"; quarantine "${d%/}" "$tag"
    fi
  done

  # 4e. any other 8-hex .php in wp-content root, PHP inside uploads/
  for f in "$wc"/[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f].php \
           "$wc"/.[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f].php; do
    [ -e "$f" ] && { crit "hex-named loader $f"; quarantine "$f" "$tag"; }
  done
  find "$wc/uploads" -name '*.php' -type f 2>/dev/null | while read -r f; do
    crit "PHP in uploads: $f"; quarantine "$f" "$tag"
  done

  # 4f. theme injection: strip SC_TH_BEGIN..SC_TH_END block from every theme
  for f in "$wc"/themes/*/functions.php; do
    if grep -qs 'SC_TH_' "$f"; then
      crit "theme injection in $f"
      act "strip SC_TH block from $f" sh -c \
        "cp -p '$f' '$QUAR/$tag-$(basename "$(dirname "$f")")-functions.php'; awk '/SC_TH_BEGIN/{skip=1} !skip{print} /SC_TH_END/{skip=0}' '$f' > '$f.sc403tmp' && mv '$f.sc403tmp' '$f'"
    fi
  done

  # 4g. wp-config: remove the SC_WC-tagged WP_CACHE line only
  if grep -qs 'SC_WC' "$root/wp-config.php"; then
    crit "SC_WC define in wp-config.php"
    act "remove SC_WC line from wp-config.php" sh -c \
      "cp -p '$root/wp-config.php' '$QUAR/$tag-wp-config.php'; sed -i.sc403bak '/SC_WC/d' '$root/wp-config.php' && rm -f '$root/wp-config.php.sc403bak'"
  fi
}

# ---------------------------------------------------------------------------
# K5 - DATABASE. Credentials come from each site's wp-config.php, parsed as
# plain text (NEVER by executing PHP while infected). The password never
# appears on a command line or in `ps`: it goes into a 0600 option file
# that mysql reads via --defaults-extra-file, shredded on exit.
# ---------------------------------------------------------------------------

MYCNF=""
cleanup_mycnf() { [ -n "$MYCNF" ] && rm -f "$MYCNF"; }
trap cleanup_mycnf EXIT

wpcfg() { # wpcfg <file> <CONSTANT>
  sed -n "s/.*define(\s*['\"]$2['\"]\s*,\s*['\"]\([^'\"]*\)['\"].*/\1/p" "$1" | head -1
}

load_db_creds() { # $1 = site root; sets DB_* TP MYCNF; returns 1 when unusable
  local cfg="$1/wp-config.php"
  [ -f "$cfg" ] || return 1
  DB_NAME=$(wpcfg "$cfg" DB_NAME);  DB_USER=$(wpcfg "$cfg" DB_USER)
  DB_PASS=$(wpcfg "$cfg" DB_PASSWORD); DB_HOST=$(wpcfg "$cfg" DB_HOST)
  TP=$(sed -n "s/.*table_prefix\s*=\s*['\"]\([A-Za-z0-9_]*\)['\"].*/\1/p" "$cfg" | head -1)
  [ -n "$DB_NAME" ] && [ -n "$DB_USER" ] && [ -n "$TP" ] || return 1
  cleanup_mycnf
  MYCNF=$(umask 077 && mktemp "${TMPDIR:-/tmp}/sc403.XXXXXX") || return 1
  printf '[client]\nuser=%s\npassword=%s\nhost=%s\n' \
    "$DB_USER" "$DB_PASS" "${DB_HOST:-localhost}" > "$MYCNF"
  return 0
}

sql() { mysql --defaults-extra-file="$MYCNF" -N -B "$DB_NAME" -e "$1" 2>>"$LOG"; }

k5_database() { # $1 = site root
  local root="$1" O
  head1 "K5 database: $root"
  command -v mysql >/dev/null 2>&1 || { note "mysql client missing - do K5 via phpMyAdmin (see report)"; return; }
  load_db_creds "$root" || { note "could not parse wp-config.php creds"; return; }
  derive_names "$root"
  derive_option_keys "$root"
  derive_endpoint_ids "$root"
  O="${TP}options"

  note "derived browser endpoints for this site: ?p=$N_EP_SW (service worker), ?p=$N_EP_INST (installer)"
  note "grep these out of your access logs - they identify which admin browsers were hit, and when"

  # -------------------------------------------------------------------------
  # CAPTURE FIRST. Everything below is destroyed by the DELETE further down,
  # and three of these rows are the only forensic record that exists:
  #   sw_url / sw_cached  what was registered and served to your admins
  #   issued              which administrators hold live forged sessions
  #   bu / bp             the implant's own hidden admin account
  # They are NOT named sc_*, so a prefix-only cleanup silently destroys them.
  # -------------------------------------------------------------------------
  PRIV_DUMP="$EVID_DIR/private-options-$(basename "$root").tsv"
  local k v hit=0
  for k in $N_PRIV_KEYS; do
    v=$(sql "SELECT option_value FROM $O WHERE option_name='$k' LIMIT 1;")
    [ -n "$v" ] || continue
    hit=$((hit+1))
    printf '%s\t%s\t%s\n' "$root" "$k" "$v" >> "$PRIV_DUMP"
  done
  if [ "$hit" -gt 0 ]; then
    crit "$hit derived private option(s) captured -> $PRIV_DUMP"
    note "decode each with: ./sc403-derive.sh --decode '<option_value>'"
  fi

  # The plaintext C2 list. No decoding needed - this is the campaign's live
  # infrastructure, and it is the single most useful thing in the database.
  for k in sc_c2_cache sc_last_c2 sc_last_rpc; do
    v=$(sql "SELECT option_value FROM $O WHERE option_name='$k' LIMIT 1;")
    [ -n "$v" ] || continue
    crit "$k: $(printf '%s' "$v" | tr '\n' ' ')"
    printf '%s\t%s\t%s\n' "$root" "$k" "$v" >> "$EVID_DIR/c2-endpoints.txt"
  done

  SW_URL=$(sql "SELECT option_value FROM $O WHERE option_name='sc_sw_last_url' LIMIT 1;")
  if [ -n "$SW_URL" ]; then
    crit "service worker was registered from: $SW_URL"
    printf '%s\tsite=%s\tdb=%s\tsc_sw_had=%s\tcaptured=%s\n' \
      "$SW_URL" "$root" "$DB_NAME" \
      "$(sql "SELECT option_value FROM $O WHERE option_name='sc_sw_had' LIMIT 1;")" \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$EVID_DIR/service-worker-urls.txt"
    note "recorded in $EVID_DIR/service-worker-urls.txt - feed the URL to SC403_SW_URLS in sc403-sw-neutralizer.php"
  else
    note "no sc_sw_last_url row (SW may still exist; neutralizer heuristics cover it)"
  fi

  # Build the IN() list of derived private keys once, quoted for SQL.
  local PRIV_IN="" k
  for k in $N_PRIV_KEYS; do PRIV_IN="$PRIV_IN,'$k'"; done
  PRIV_IN="${PRIV_IN#,}"

  # One predicate, reused for the report and the delete so they can never
  # drift apart. Three families:
  #   sc_* options + their transients   - the obvious ones
  #   $N_OPT                            - md5(ABSPATH.'opt')[0:10], base64(gzip(core))
  #   $PRIV_IN                          - md5(ABSPATH.'93819'.name)[0:12], the ones
  #                                       everybody misses
  local WHERE="option_name LIKE 'sc\\_%' \
OR option_name LIKE '\\_transient\\_sc\\_%' \
OR option_name LIKE '\\_transient\\_timeout\\_sc\\_%' \
OR option_name='$N_OPT' \
OR option_name IN ($PRIV_IN)"

  note "malware rows currently in $DB_NAME.$O:"
  sql "SELECT option_name FROM $O WHERE $WHERE;" | sed 's/^/         /' | tee -a "$LOG"

  if [ "$EXECUTE" -eq 1 ]; then
    say "[DO   ] delete sc_* options + transients, the '$N_OPT' payload row, and $(set -- $N_PRIV_KEYS; echo $#) derived private keys"
    sql "DELETE FROM $O WHERE $WHERE;"
  else
    say "[dry  ] would DELETE those rows"
  fi

  # A derived key is 12 hex chars and autoload='off'. If any 12-hex row with a
  # base64-looking value is still here, the site's ABSPATH is not what we think
  # it is (symlinked docroot, moved site) and the derivation missed. Report it
  # rather than deleting on a guess - a 12-hex option name is not by itself
  # proof of anything, and some plugins do use hashed keys.
  note "residual 12-hex option rows (verify by hand; empty is what you want):"
  sql "SELECT option_name FROM $O WHERE option_name REGEXP '^[0-9a-f]{12}$' AND LENGTH(option_value) > 16;" \
    | sed 's/^/         /' | tee -a "$LOG"

  # active_plugins: after K4 the file is gone; WordPress drops the stale
  # entry automatically. Report it so you can verify.
  note "active_plugins (verify no unknown slug remains):"
  sql "SELECT option_value FROM $O WHERE option_name='active_plugins';" | sed 's/^/         /' | tee -a "$LOG"

  # Cron. Two of the four implant hooks are named sc_cron_guard / sc_cron_fetch.
  # The other two are per-build random strings - on the sample account they were
  # 'zvdcgmrr7smxjwpo_ky' and 'e1pw88l550vjcok7s5pcd', both on the hourly
  # schedule, and both rebuild the implant. There is no pattern to match them on,
  # so dropping the whole cron row is the only reliable removal. WordPress and
  # every plugin re-register their own jobs on the next request.
  note "cron hooks currently scheduled (anything you cannot attribute to an installed plugin is hostile):"
  sql "SELECT option_value FROM $O WHERE option_name='cron';" \
    | tr '{' '\n' | grep -oE 's:[0-9]+:\\?"[A-Za-z0-9_]{6,}\\?"' | sed 's/.*"\(.*\)"/\1/' \
    | sort -u | sed 's/^/         /' | tee -a "$LOG"
  if [ "$RESET_CRON" -eq 1 ]; then
    act "drop the cron row (the ONLY way to clear the randomly-named hourly hooks; WP rebuilds it)" \
      mysql --defaults-extra-file="$MYCNF" "$DB_NAME" -e "DELETE FROM $O WHERE option_name='cron';"
  else
    note "NOT cleared. Two implant cron hooks have random per-build names and cannot be matched -"
    note "rerun with --reset-cron to drop the whole cron row, or the hourly rebuild survives."
  fi

  # hidden administrators: raw SQL the implant cannot filter
  note "ALL administrators per raw SQL - compare with wp-admin Users screen:"
  sql "SELECT u.ID,u.user_login,u.user_registered FROM ${TP}users u JOIN ${TP}usermeta m ON m.user_id=u.ID WHERE m.meta_key='${TP}capabilities' AND m.meta_value LIKE '%administrator%';" | sed 's/^/         /' | tee -a "$LOG"
  note "logins matching (admin_|adm_|administrator_|backup_)+hex are the implant's - delete them in wp-admin AFTER cleanup"
  if [ -f "$PRIV_DUMP" ]; then
    note "the exact login is also in $PRIV_DUMP - decode the rows and look for one that"
    note "deserialises to administrator_<hex>; the row next to it is that account's password."
  fi
  # Session tokens: WP auth cookies survive a password change, so the forged
  # 14-day sessions outlive K6 unless the tokens go too. Salt rotation also
  # kills them, but do both - it costs nothing.
  note "session_tokens rows (every one of these is a live login, forged or real):"
  sql "SELECT COUNT(*) FROM ${TP}usermeta WHERE meta_key='session_tokens';" | sed 's/^/         /' | tee -a "$LOG"
  if [ "$EXECUTE" -eq 1 ]; then
    say "[DO   ] delete all session_tokens (everyone gets logged out; forged sessions die with them)"
    sql "DELETE FROM ${TP}usermeta WHERE meta_key='session_tokens';"
  else
    say "[dry  ] would DELETE all session_tokens"
  fi
  cleanup_mycnf
}

# ---------------------------------------------------------------------------
# PHASE-5 ELIMINATION. The spread routine skips any site whose mu-plugins/
# plugins hold a PHP file >= 5000 bytes with mtime%100000==93819 (decoded
# core L302 + L5859). We turn that against it: an inert, documented vaccine
# file makes clean sites look "already owned" so neighbours never write here.
# ---------------------------------------------------------------------------

vaccinate() { # $1 = site root
  local root="$1" mu="$1/wp-content/mu-plugins" f wm now
  f="$mu/sc403-vaccine.php"
  [ -f "$f" ] && { note "vaccine already present: $f"; return; }
  act "mkdir $mu" mkdir -p "$mu"
  if [ "$EXECUTE" -eq 1 ]; then
    { printf '<?php // sc403-vaccine: inert decoy; SC 4.x spread skips this site.\n'
      printf '// No executable logic. Delete once the whole account is clean.\nreturn;\n/*\n'
      head -c 5200 /dev/urandom | od -An -tx1 | tr -d ' \n'
      printf '\n*/\n'; } > "$f"
    now=$(date +%s); wm=$(( now - now % 100000 + 93819 ))
    touch -d "@$wm" "$f" 2>/dev/null || touch -t "$(date -r "$wm" +%Y%m%d%H%M.%S)" "$f"
    say "[DO   ] vaccine planted: $f (>=5 KB, watermarked mtime)"
  else
    say "[dry  ] would plant vaccine $f"
  fi
}

verify_site() {
  if is_infected "$1"; then crit "RESIDUE REMAINS at $1 - investigate $LOG"; return 1
  else say "[clean] $1 shows no SC 4.x artifacts"; fi
}

clean_site() { # the ordered chain for one root
  local root="$1"
  k0_snapshot "$root"
  k1_contain  "$root"
  # If K2 could not do its job, everything after it is actively harmful: K4
  # deletes files while the guard daemon and the shared-memory replica are still
  # running, which is the sequence that makes this malware look unkillable.
  # Stop on this site rather than produce a cleanup that undoes itself.
  if ! k2_kill_runtime "$root"; then
    crit "K2 did not complete for $root - skipping K3-K5 for this site."
    note "Nothing was deleted here. Fix the condition K2 reported and rerun."
    return 1
  fi
  k3_sever_prepend "$root"
  k4_files "$root"
  [ "$DO_DB" -eq 1 ] && k5_database "$root"
  [ "$VACCINE" -eq 1 ] && vaccinate "$root"
}

# ---------------------------------------------------------------------------
# K6-K8 - steps a script cannot safely do for you.
# ---------------------------------------------------------------------------

k678_guidance() {
  head1 "K6-K8 manual steps (REQUIRED)"
  cat <<'EOF' | tee -a "$LOG"
  K6 ROTATE (stolen in plaintext - assume ALL compromised):
     DB password (panel + wp-config.php); all 8 salts/keys in wp-config.php
     (invalidates the forged 14-day cookies); every WP admin password;
     hosting panel + FTP/SSH credentials.
  K7 BROWSERS: every admin unregisters service workers for the site
     (chrome://serviceworker-internals or Safari develop menu) BEFORE the
     first post-cleanup login.
  K8 HARDEN: one OS user per site (breaks cross-site spread for good);
     pool-level: disable_functions=shmop_open,shmop_write,ftok,popen,proc_open
     forbid .htaccess/.user.ini auto_prepend_file at vhost level;
     wp-content + wp-config.php not writable by the PHP user.
EOF
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

mkdir -p "$EVID_DIR" "$QUAR" 2>/dev/null
say "sc403-killchain $VERSION  mode=$([ "$EXECUTE" -eq 1 ] && echo EXECUTE || echo DRY-RUN)  phase5=$DO_PHASE5  evidence=$EVID_DIR"

if [ "$EXECUTE" -eq 1 ] && [ "$ASSUME_YES" -ne 1 ]; then
  printf 'This will modify sites on this machine. Type YES to continue: '
  read -r ok; [ "$ok" = "YES" ] || { echo aborted; exit 1; }
fi

head1 "discovery"
ALL_SITES=()
while IFS= read -r s; do ALL_SITES+=("$s"); done < <(discover_sites)
INFECTED=()
for s in "${ALL_SITES[@]}"; do
  if is_infected "$s"; then crit "INFECTED: $s"; INFECTED+=("$s")
  else note "clean:    $s"; fi
done
[ ${#ALL_SITES[@]} -eq 0 ] && { say "no WordPress roots found - use --path"; exit 1; }

if [ "$PHASE5_ONLY" -eq 1 ]; then
  head1 "phase5-only: sibling containment"
  for s in "${INFECTED[@]}"; do clean_site "$s"; done
  if [ "$VACCINE" -eq 1 ]; then
    for s in "${ALL_SITES[@]}"; do is_infected "$s" || vaccinate "$s"; done
  fi
  for s in "${INFECTED[@]}"; do verify_site "$s"; done
  exit 0
fi

TARGETS=("${INFECTED[@]}")
if [ "$DO_PHASE5" -eq 0 ]; then
  [ ${#SITES[@]} -gt 0 ] && TARGETS=("${SITES[@]}")
  say ""
  say "*** --no-phase5: cleaning ONLY: ${TARGETS[*]:-none}"
  say "*** Any infected sibling site WILL reinfect within ~17h. Rerun without"
  say "*** --no-phase5, or --vaccinate this site, as soon as you can."
fi

for s in "${TARGETS[@]}"; do clean_site "$s"; done
if [ "$VACCINE" -eq 1 ] && [ "$DO_PHASE5" -eq 1 ]; then
  for s in "${ALL_SITES[@]}"; do is_infected "$s" || vaccinate "$s"; done
fi

head1 "verification rescan"
RC=0
for s in "${TARGETS[@]}"; do verify_site "$s" || RC=2; done
k678_guidance
say ""
say "done. evidence + quarantine + log: $EVID_DIR"
exit "$RC"
