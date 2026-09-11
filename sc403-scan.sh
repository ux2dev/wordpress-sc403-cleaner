#!/usr/bin/env bash
#
# sc403-scan.sh -- read-only detector for the "SC 4.x" self-healing WordPress malware
#                  (SC 4.0.3, August 2026 -> SCV:4.3.24, September 2026)
#
# This script NEVER deletes, moves, quarantines or modifies anything. It reads and
# reports. That is deliberate: SC 4.x keeps redundant copies of itself in PHP
# startup config, MU-plugins, WordPress drop-ins, theme code, ZIP archives, the
# options table, System V shared memory and administrator browsers. Removing one
# node while the others are live invites an immediate rebuild, so eradication has
# to be one coordinated pass by a human -- see README.md.
#
# What changed in 4.3.24, and why this version of the scanner exists:
#
#   * Every write is padded with megabytes of random hex, so FILE HASHES ARE
#     DEAD as indicators. No two installations share one. Names survive.
#   * There are three families of derived name, not one. Files, `?p=` HTTP
#     endpoints, and database option keys. All three come from ABSPATH, which
#     means a defender can compute every one of them in advance -- offline,
#     before touching the server. That is what this script does.
#   * The database keys do not start with `sc_`. A cleanup that greps for
#     `sc\_%` destroys the two most valuable rows on the system and misses the
#     rest.
#
# Usage:
#   ./sc403-scan.sh                     # auto-discover every WordPress root you can read
#   ./sc403-scan.sh -p /var/www/site    # scan specific roots (repeatable)
#   ./sc403-scan.sh --no-db             # skip the WP-CLI database checks
#   ./sc403-scan.sh --names-only        # just print the derived names, scan nothing
#   ./sc403-scan.sh --logs /var/log/nginx  # also grep these access logs for ?p= hits
#
# Exit codes:  0 = nothing found   1 = warnings only   2 = critical findings
#
# Repo:    https://github.com/ux2dev/wordpress-sc403-cleaner
# License: GPL-2.0-or-later
#
set -uo pipefail

VERSION="2.0.0"

# ---------------------------------------------------------------------------
# Indicators. Keep in sync with iocs.csv.
# ---------------------------------------------------------------------------

# Markers implemented directly in recovered SC 4.x code. A hit is decisive.
STRONG_MARKERS=(
    'SC_ADV_BEGIN'
    'SC_ADV_END'
    'SC_DB_BEGIN'
    'SC_DB_END'
    'SC_TH_BEGIN'
    'SC_TH_END'
    'SC_CORE_BOOT_VER'
    'sc_boot_ver'
    'sc_payload_persistent'
    'sc_persist_manifest'
    'sc_cron_fetch'
    'sc_last_recovery_check'
    'sc_last_rpc'
    'sc_last_fetch_ts'
    'sc_own_manifest'
    'sc_c2_cache'
    'sc_sw_last_url'
    '0x3bc5de30'
)

# Version strings. 4.3.24 stamps its own build into every file it writes.
VERSION_MARKERS=(
    '/* SCV:'
    'SCV:4.3.24'
    'SC_ADV_BEGIN:'
    'SC_DB_BEGIN:'
)

# Behaviour shared with other malware families, or occasionally legitimate.
# A hit is a lead, not a verdict.
WEAK_MARKERS=(
    'auto_prepend_file'
    'eth_call'
    'Service-Worker-Allowed'
    'shmop_open'
    'ftok('
    'pre_user_query'
    'wp_mail_from'
)

# Ethereum contracts used as the dead-drop C2 resolver.
CONTRACTS=(
    '0x9A4752cAA1C15868487A0ACb691F81bfA901E063'
    '0x839d1cE5c3F259e8d3D17114d7186EDabdbeA94b'
    '0x6d2c5435EF70196740a48904B69377935D50abBB'
)

# C2 hosts recovered from a live 4.3.24 infection (sc_c2_cache / sc_last_c2).
# These rotate. Treat a hit as decisive, a miss as meaningless.
C2_HOSTS=(
    'basic-junior.com'
    'railroad-boot.com'
    'great-basic.com'
    'root-cherry.com'
    '0xrpc.io'
)

# SHA-256 of artefacts recovered in the August 2026 (4.0.3) analysis.
# 4.3.24 pads every file it writes, so these match ONLY older builds. Kept
# because a hit is still a free, decisive answer.
KNOWN_HASHES=(
    '8284d68274c0475118732110680e38d9da27b4173997c0db0d9f6e5283109554:core payload (trace-scanner-lite.php alias)'
    '5e0634b36af4fab6931e3efc120e5baee1953f32f14a516cbc4c927786d4309c:hidden loader'
    '96d36f0432295b0a833e6d835c8f3100f900ace2f08f0584ea0d2a83e7df8b82:visible loader wrapper'
    '1bd222238cd2679cd8dcdd8e1d391339ae07f009b67277929951d18d75d55cf0:advanced-cache.php implant'
    'a3c6fcd1df2c1fec977427f056aa45852f7ae7a9f63ff79813057e451eeed6c3:db.php implant'
    'b516bd7eb514b80555fc3a04ac30405e52f128c6d08da3baf03e74f1ad2fe1fb:infected theme functions.php'
    'ac7c266d12c6d3d979594b4d74c545ecf2546ac704f2ac07bde1276010747c0d:.user.ini'
    '7bafee00a010ed3db3521a89e8f5d50d2f677204c56995e99c7603768a9f0bd2:service-worker template'
)

# Hidden-administrator username pattern used by the implant.
ADMIN_PATTERN='^(admin_|adm_|administrator_|backup_)[0-9a-f]{6,10}$'

# Shared "timestomp" watermark: mtime %% 100000 == 93819. The same constant is
# the salt in the option-key derivation, which is why one number gives you both.
WATERMARK=93819

# Padding band: 4.3.24 inflates each file to 5.5-7.0 MB with random hex
# comments. Anything in wp-content over this that is not a legitimate asset is
# worth an immediate look.
PAD_FLOOR=4000000

# The private option slot names, verbatim from the core's own call sites.
# Fourteen, counting the empty-string slot.
PRIV_OPTS="sw_url sw_cached sw_config sw_config_sig srv_key page_cached js_cached src issued bp bu ic errors"

# Plaintext state rows. Not encoded, not hidden, and the fastest confirmation
# you will get from a database you cannot run WP-CLI against.
PLAIN_OPTS="sc_initialized sc_persist_manifest sc_payload_persistent sc_last_recovery_check \
sc_last_rpc sc_last_fetch_ts sc_last_c2 sc_c2_cache sc_own_rec sc_own_manifest sc_sw_had \
sc_sw_last_url sc_ini_fail sc_ini_dead sc_fetch_fails sc_pad_off_ts sc_reins_adv sc_reins_db"

# Shared-hosting roots the malware itself walks when looking for sibling sites.
SPREAD_ROOTS=(/home /var/www /var/www/vhosts /srv/www /srv/users)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------

SITES=()
LOGDIRS=()
DEPTH=6
DO_DB=1
DO_HASH=1
NAMES_ONLY=0
QUIET=0

usage() {
    sed -n '2,/^set -/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        -p|--path)  SITES+=("${2:-}");   shift 2 ;;
        -d|--depth) DEPTH="${2:-6}";     shift 2 ;;
        --logs)     LOGDIRS+=("${2:-}"); shift 2 ;;
        --no-db)    DO_DB=0;     shift ;;
        --no-hash)  DO_HASH=0;   shift ;;
        --names-only) NAMES_ONLY=1; DO_DB=0; shift ;;
        -q|--quiet) QUIET=1;     shift ;;
        -h|--help)  usage ;;
        -v|--version) echo "sc403-scan.sh $VERSION"; exit 0 ;;
        *) echo "unknown option: $1 (try --help)" >&2; exit 64 ;;
    esac
done

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    R=$'\033[31m'; Y=$'\033[33m'; G=$'\033[32m'; B=$'\033[34m'; D=$'\033[2m'; N=$'\033[0m'
else
    R=''; Y=''; G=''; B=''; D=''; N=''
fi

CRIT_N=0; WARN_N=0; INFO_N=0

crit() { CRIT_N=$((CRIT_N+1)); printf '%s  [CRITICAL]%s %s\n' "$R" "$N" "$*"; }
warn() { WARN_N=$((WARN_N+1)); printf '%s  [WARNING ]%s %s\n' "$Y" "$N" "$*"; }
info() { INFO_N=$((INFO_N+1)); printf '%s  [INFO    ]%s %s\n' "$B" "$N" "$*"; }
okay() { [ "$QUIET" -eq 1 ] || printf '%s  [ok      ]%s %s\n' "$G" "$N" "$*"; }
note() { [ "$QUIET" -eq 1 ] || printf '%s            %s%s\n' "$D" "$*" "$N"; }
head1() { printf '\n%s== %s ==%s\n' "$B" "$*" "$N"; }
head2() { [ "$QUIET" -eq 1 ] || printf '\n%s-- %s%s\n' "$D" "$*" "$N"; }

# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------

md5_str() {
    if   command -v md5sum >/dev/null 2>&1; then printf '%s' "$1" | md5sum | cut -d' ' -f1
    elif command -v md5    >/dev/null 2>&1; then printf '%s' "$1" | md5 -q
    elif command -v openssl >/dev/null 2>&1; then printf '%s' "$1" | openssl md5 | awk '{print $NF}'
    fi
}

sha256_file() {
    if   command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" 2>/dev/null | cut -d' ' -f1
    elif command -v shasum    >/dev/null 2>&1; then shasum -a 256 "$1" 2>/dev/null | cut -d' ' -f1
    elif command -v openssl   >/dev/null 2>&1; then openssl dgst -sha256 "$1" 2>/dev/null | awk '{print $NF}'
    fi
}

file_size() { wc -c < "$1" 2>/dev/null | tr -d ' '; }

# True when the file contains a base64-ish run of at least $2 characters.
# Implemented in awk because BSD grep rejects interval repetitions above 255.
has_long_b64() {
    awk -v min="$2" '
        {
            line = $0
            while (match(line, /[A-Za-z0-9+\/=]+/)) {
                if (RLENGTH >= min) { found = 1; exit }
                line = substr(line, RSTART + RLENGTH)
            }
        }
        END { exit !found }
    ' "$1" 2>/dev/null
}

# Emit "<mtime-epoch> <path>" for every *.php below a directory.
php_mtimes() {
    if find "$1" -maxdepth 0 -printf '' >/dev/null 2>&1; then
        find "$1" -type f -name '*.php' -printf '%Ts %p\n' 2>/dev/null
    else
        find "$1" -type f -name '*.php' -print0 2>/dev/null | while IFS= read -r -d '' f; do
            m=$(stat -c %Y "$f" 2>/dev/null || stat -f %m "$f" 2>/dev/null)
            [ -n "$m" ] && printf '%s %s\n' "$m" "$f"
        done
    fi
}

# ---------------------------------------------------------------------------
# The three derivations. Everything below is arithmetic on ABSPATH -- no
# network, no database, no guessing. See README "Names, not hashes".
#
#   FILES      substr(md5(ABSPATH . role), 0, n)
#   ENDPOINTS  91000000 + hexdec(md5(ABSPATH . 'ep' . role)[0:7]) % 8999999
#   OPTIONS    substr(md5(ABSPATH . '93819' . name), 0, 12)
#
# ABSPATH is the WordPress root WITH a trailing slash, backslashes normalised.
# ---------------------------------------------------------------------------

endpoint_id() { # $1 = ABSPATH, $2 = role
    local h dec
    h=$(md5_str "$1ep$2"); h=${h:0:7}
    dec=$((16#$h))
    printf '%s' $(( 91000000 + dec % 8999999 ))
}

option_key() { # $1 = ABSPATH, $2 = slot name
    md5_str "$1$WATERMARK$2" | cut -c1-12
}

# Fills the D_* globals for one site.
derive_names() {
    local a="$1"
    D_HTL=$(md5_str "${a}htl"  | cut -c1-8)
    D_LDR=$(md5_str "${a}ldr"  | cut -c1-8)
    D_DIR=$(md5_str "${a}dir"  | cut -c1-8)
    D_CORE=$(md5_str "${a}core"| cut -c1-8)
    D_ZIP=$(md5_str "${a}zip"  | cut -c1-8)
    D_INST=$(md5_str "${a}inst"| cut -c1-8)
    D_OC=$(md5_str "${a}oc"    | cut -c1-8)
    D_OWN=$(md5_str "${a}own"  | cut -c1-8)
    D_G=$(md5_str "${a}g"      | cut -c1-8)
    D_OPT=$(md5_str "${a}opt"  | cut -c1-10)
    D_WK=$(md5_str "${a}wk"    | cut -c1-12)
    D_JS=$(md5_str "${a}js"    | cut -c1-6)
    D_EP_SW=$(endpoint_id "$a" sw)
    D_EP_IN=$(endpoint_id "$a" inst)
}

print_names() {
    local site="$1" a="$2" o
    cat <<TXT
$site
  ABSPATH                 $a

  FILES  (all padded to 5.5-7.0 MB; hashes are worthless, names are not)
    visible loader        wp-content/${D_HTL}.php
    hidden loader         wp-content/.${D_LDR}.php
    staging dir           wp-content/.sc_${D_DIR}/
    canonical core        wp-content/.sc_${D_DIR}/core_${D_CORE}.php
    installer template    wp-content/.sc_${D_DIR}/${D_INST}.php
    state manifest        wp-content/.sc_${D_DIR}/own_${D_OWN}.php
    replica zip           wp-content/${D_ZIP}.zip
    object-cache replica  wp-content/.wp-object-cache-${D_OC}.dat[.lkg]
    guard files           wp-content/.g_${D_G}.php  .gl_/.gm_/.gp_/.gs_/.gv_${D_G}

  BROWSER ENDPOINTS  (this is the half that reaches your administrators)
    service worker        ?p=${D_EP_SW}
    installer             ?p=${D_EP_IN}

  DATABASE
    payload row           ${D_OPT}
    private options       md5(ABSPATH . ${WATERMARK} . name)[0:12]
TXT
    for o in $PRIV_OPTS; do printf '      %-14s %s\n' "$o" "$(option_key "$a" "$o")"; done
    printf '      %-14s %s\n' "(empty)" "$(option_key "$a" "")"
    cat <<TXT

  TOKENS
    writeKey              ${D_WK}
    injected script attr  data-sc-${D_JS}
    timestomp residue     mtime % 100000 == ${WATERMARK}

TXT
}

# ---------------------------------------------------------------------------
# Site discovery
# ---------------------------------------------------------------------------

discover_sites() {
    local roots=() r
    if [ "$(id -u)" -eq 0 ]; then
        for r in "${SPREAD_ROOTS[@]}"; do [ -d "$r" ] && roots+=("$r"); done
    fi
    [ -d "${HOME:-}" ] && roots+=("$HOME")
    [ "${#roots[@]}" -eq 0 ] && roots+=(".")

    for r in "${roots[@]}"; do
        find "$r" -maxdepth "$DEPTH" -type f -path '*/wp-includes/version.php' -print 2>/dev/null
    done | while IFS= read -r v; do
        dirname "$(dirname "$v")"
    done | sort -u
}

# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

# 1. auto_prepend_file in .user.ini / .htaccess, from the site root upwards.
check_prepend() {
    local site="$1" dir="$site" f found=0
    local stop="${HOME:-/}"
    head2 "PHP startup configuration (auto_prepend_file)"

    while :; do
        for f in "$dir/.user.ini" "$dir/.htaccess" "$dir/php.ini"; do
            [ -f "$f" ] || continue
            if grep -qs 'auto_prepend_file' "$f"; then
                crit "auto_prepend_file directive in $f"
                note "$(grep -ns 'auto_prepend_file' "$f" | head -3)"
                found=1
            fi
        done
        [ "$dir" = "/" ] && break
        [ "$dir" = "$stop" ] && break
        dir="$(dirname "$dir")"
        case "$dir" in /home|/var|/srv|/) break ;; esac
    done

    for f in "$site/wp-content/.user.ini" "$site/wp-content/.htaccess"; do
        [ -f "$f" ] || continue
        if grep -qs 'auto_prepend_file' "$f"; then
            crit "auto_prepend_file directive in $f"; found=1
        fi
    done

    # 4.3.24 also flips WP_CACHE on from wp-config.php so the drop-in loads.
    if [ -f "$site/wp-config.php" ] && grep -qs 'SC_WC' "$site/wp-config.php"; then
        crit "wp-config.php carries the SC_WC marker (WP_CACHE forced on to load advanced-cache.php)"
        found=1
    fi

    [ "$found" -eq 0 ] && okay "no auto_prepend_file directives found"
    if [ "$found" -eq 1 ]; then
        note "PHP caches per-directory INI for user_ini.cache_ttl (default 300s);"
        note "removing the file does not stop workers that already read it."
    fi
}

# 2. Content and version markers anywhere under the site.
check_markers() {
    local site="$1" m hits args=()
    head2 "Content markers"

    for m in "${STRONG_MARKERS[@]}"; do args+=(-e "$m"); done
    hits=$(grep -rlI --include='*.php' --include='*.js' --include='*.ini' \
                 -F "${args[@]}" "$site" 2>/dev/null | head -50)
    if [ -n "$hits" ]; then
        while IFS= read -r f; do crit "SC 4.x marker in $f"; done <<< "$hits"
    else
        okay "no SC 4.x markers"
    fi

    args=()
    for m in "${VERSION_MARKERS[@]}"; do args+=(-e "$m"); done
    hits=$(grep -rlI --include='*.php' -F "${args[@]}" "$site/wp-content" 2>/dev/null | head -20)
    [ -n "$hits" ] && while IFS= read -r f; do
        crit "SC version stamp in $f -- $(grep -ohsE 'SC(V|_[A-Z]+_BEGIN):[0-9a-zA-Z.:]+' "$f" 2>/dev/null | head -1)"
    done <<< "$hits"

    args=()
    for m in "${CONTRACTS[@]}"; do args+=(-e "$m"); done
    hits=$(grep -rlI --include='*.php' --include='*.js' -F "${args[@]}" "$site" 2>/dev/null | head -20)
    [ -n "$hits" ] && while IFS= read -r f; do crit "C2 contract address in $f"; done <<< "$hits"

    args=()
    for m in "${C2_HOSTS[@]}"; do args+=(-e "$m"); done
    hits=$(grep -rlI --include='*.php' --include='*.js' -F "${args[@]}" "$site" 2>/dev/null | head -20)
    [ -n "$hits" ] && while IFS= read -r f; do crit "known SC 4.3.24 C2 host referenced in $f"; done <<< "$hits"

    args=()
    for m in "${WEAK_MARKERS[@]}"; do args+=(-e "$m"); done
    hits=$(grep -rlI --include='*.php' -F "${args[@]}" "$site/wp-content" 2>/dev/null | head -30)
    if [ -n "$hits" ]; then
        while IFS= read -r f; do warn "suspicious API in $f (verify by hand)"; done <<< "$hits"
    fi
}

# 3. MU-plugins. Size, the twin-copy signature, and the padding band.
check_mu_plugins() {
    local site="$1" mu="$site/wp-content/mu-plugins" f base sz
    head2 "Must-use plugins"

    if [ ! -d "$mu" ]; then okay "no mu-plugins directory"; return; fi

    local any=0
    while IFS= read -r f; do
        any=1
        base="$(basename "$f" .php)"
        sz="$(file_size "$f")"
        if   [ "${sz:-0}" -gt "$PAD_FLOOR" ]; then
            crit "MU-plugin ${sz}B is inside the SC 4.3.24 padding band: $f"
            note "4.3.24 pads every file it writes to 5.5-7.0 MB with random hex comments."
        elif [ "${sz:-0}" -gt 1048576 ]; then crit "MU-plugin ${sz}B is implausibly large: $f"
        elif [ "${sz:-0}" -gt 102400  ]; then warn "MU-plugin ${sz}B is unusually large: $f"
        else info "MU-plugin ${sz}B: $f"
        fi
        # The defining SC 4.x layout: identical basename as MU-plugin AND as a
        # normal plugin, so either replica can restore the other.
        if [ -f "$site/wp-content/plugins/$base/$base.php" ]; then
            crit "twin copy: $base exists as both MU-plugin and ordinary plugin"
        fi
        if [ ! -w "$f" ]; then warn "MU-plugin is not writable (0444 is an SC 4.x trait): $f"; fi
    done < <(find "$mu" -maxdepth 2 -type f -name '*.php' 2>/dev/null)

    [ "$any" -eq 0 ] && okay "mu-plugins directory is empty"
}

# 4. Drop-ins. The filenames are legitimate; the contents are what matter.
check_dropins() {
    local site="$1" f name any=0
    head2 "WordPress drop-ins"

    for name in db.php advanced-cache.php object-cache.php; do
        f="$site/wp-content/$name"
        [ -f "$f" ] || continue
        any=1
        if grep -qsF -e 'SC_DB_BEGIN' -e 'SC_ADV_BEGIN' -e 'sc_payload_persistent' -e '/* SCV:' "$f"; then
            crit "drop-in carries an SC 4.x implant: $f"
        else
            info "drop-in present ($(file_size "$f")B): $f -- confirm it belongs to a caching/DB plugin you installed"
        fi
        if has_long_b64 "$f" 4000; then
            crit "drop-in contains a >4000-char base64 run (embedded payload): $f"
        fi
        # db.php is backdated to 2020 by the timestomp routine. A drop-in older
        # than the WordPress install under it is not a drop-in you installed.
        if [ "$name" = "db.php" ] && [ "$f" -ot "$site/wp-includes/version.php" ]; then
            warn "db.php is older than wp-includes/version.php -- consistent with SC backdating"
        fi
    done
    [ "$any" -eq 0 ] && okay "no db.php / advanced-cache.php / object-cache.php drop-ins"
}

# 5. Names the malware derives from ABSPATH. Site-specific, near-zero FP rate.
check_derived_names() {
    local site="$1" a="$2" f found=0
    head2 "Site-specific artefact names derived from ABSPATH"

    note "files: htl=$D_HTL ldr=$D_LDR dir=$D_DIR core=$D_CORE zip=$D_ZIP inst=$D_INST oc=$D_OC own=$D_OWN g=$D_G"
    note "endpoints: ?p=$D_EP_SW (service worker)  ?p=$D_EP_IN (installer)"
    note "payload option: $D_OPT   writeKey: $D_WK   script attr: data-sc-$D_JS"

    for f in "$site/wp-content/${D_HTL}.php" \
             "$site/wp-content/.${D_LDR}.php" \
             "$site/wp-content/.sc_${D_DIR}/core_${D_CORE}.php" \
             "$site/wp-content/.sc_${D_DIR}/${D_INST}.php" \
             "$site/wp-content/.sc_${D_DIR}/own_${D_OWN}.php" \
             "$site/wp-content/${D_ZIP}.zip" \
             "$site/wp-content/.wp-object-cache-${D_OC}.dat" \
             "$site/wp-content/.wp-object-cache-${D_OC}.dat.lkg" \
             "$site/wp-content/.g_${D_G}.php" \
             "$site/wp-content/.gl_${D_G}" "$site/wp-content/.gm_${D_G}" \
             "$site/wp-content/.gp_${D_G}" "$site/wp-content/.gs_${D_G}" \
             "$site/wp-content/.gv_${D_G}"; do
        [ -e "$f" ] && { crit "predicted SC artefact exists: $f"; found=1; }
    done

    # The staging directory moves between builds; the name does not.
    while IFS= read -r f; do
        crit "predicted staging directory exists: $f"; found=1
    done < <(find "$site" -maxdepth 4 -type d -name ".sc_${D_DIR}" 2>/dev/null)

    while IFS= read -r f; do
        crit "predicted SC archive exists: $f"; found=1
    done < <(find "$site" -maxdepth 4 -name "${D_ZIP}.zip" 2>/dev/null)

    if grep -rqsF "data-sc-${D_JS}" "$site/wp-content" 2>/dev/null; then
        crit "predicted injected script attribute data-sc-${D_JS} present under wp-content"; found=1
    fi

    [ "$found" -eq 0 ] && okay "none of the predicted artefact names exist on disk"
}

# 6. Hidden loaders and guard stubs.
check_hidden_loaders() {
    local site="$1" f any=0
    head2 "Hidden loaders and guard stubs"

    while IFS= read -r f; do
        crit "guard stub: $f"; any=1
    done < <(find "$site" -type f \( -name '.g_*.php' -o -name '.gl_*' -o -name '.gm_*' \
                  -o -name '.gp_*' -o -name '.gs_*' -o -name '.gv_*' \) 2>/dev/null | head -20)

    while IFS= read -r f; do
        warn "hex-named PHP file (validate contents, do not delete on sight): $f"; any=1
    done < <(find "$site/wp-content" -maxdepth 2 -type f \
                  \( -name '.[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f].php' \
                  -o -name '[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f].php' \) \
                  2>/dev/null | head -20)

    while IFS= read -r f; do
        warn "hidden SC-style staging directory: $f"; any=1
    done < <(find "$site/wp-content" -maxdepth 2 -type d -name '.sc_*' 2>/dev/null | head -10)

    while IFS= read -r f; do
        warn "PHP file in an upload/cache directory: $f"; any=1
    done < <(find "$site/wp-content/uploads" "$site/wp-content/cache" \
                  -type f -name '*.php' 2>/dev/null | head -20)

    [ "$any" -eq 0 ] && okay "no guard stubs or stray hex-named PHP files"
}

# 7. The padding band. Independent of every name and every hash.
check_padding() {
    local site="$1" any=0 line sz f
    head2 "Padded PHP (SC 4.3.24 inflates every file it writes)"
    while IFS= read -r f; do
        sz="$(file_size "$f")"
        crit "PHP file of ${sz}B under wp-content: $f"
        any=1
    done < <(find "$site/wp-content" -type f -name '*.php' -size +3900k 2>/dev/null | head -20)
    if [ "$any" -eq 1 ]; then
        note "Legitimate PHP is essentially never megabytes. Open one and look at the"
        note "tail: a wall of /*<hex>*/ comments is the padding routine."
    else
        okay "no multi-megabyte PHP files under wp-content"
    fi
}

# 8. ZIP backups seeded around the tree.
check_archives() {
    local site="$1" f any=0
    head2 "Archive backups"
    while IFS= read -r f; do
        warn "archive inside wp-content (SC seeds ZIP replicas here): $f"; any=1
    done < <(find "$site/wp-content" -maxdepth 4 -type f -name '*.zip' 2>/dev/null | head -20)
    [ "$any" -eq 0 ] && okay "no archives under wp-content"
}

# 9. The shared timestomp watermark.
check_timestomp() {
    local site="$1" any=0 f
    head2 "Timestamp watermark (mtime mod 100000 == $WATERMARK)"
    while IFS= read -r f; do
        crit "watermarked mtime: $f"; any=1
    done < <(php_mtimes "$site/wp-content" | awk -v w="$WATERMARK" '$1 % 100000 == w {sub(/^[0-9]+ /,""); print}' | head -20)
    if [ "$any" -eq 0 ]; then
        okay "no watermarked timestamps"
    else
        note "The implant also uses this watermark as its own 'already infected' test,"
        note "so a watermarked file in mu-plugins/ or plugins/ is either the malware"
        note "or a deliberate decoy someone planted. Read it before you judge it."
    fi
}

# 10. Known-bad file hashes. Legacy builds only -- see the note above.
check_hashes() {
    local site="$1" f h entry hash label any=0
    [ "$DO_HASH" -eq 1 ] || return
    head2 "Known SHA-256 artefacts (4.0.3-era builds only)"
    while IFS= read -r f; do
        h="$(sha256_file "$f")"
        [ -n "$h" ] || continue
        for entry in "${KNOWN_HASHES[@]}"; do
            hash="${entry%%:*}"; label="${entry#*:}"
            if [ "$h" = "$hash" ]; then crit "exact match ($label): $f"; any=1; fi
        done
    done < <(find "$site/wp-content" -maxdepth 3 -type f \( -name '*.php' -o -name '*.ini' \) -size +1k -size -2000k 2>/dev/null | head -400)
    if [ "$any" -eq 0 ]; then
        okay "no known-bad hashes among scanned files"
        note "Expected on 4.3.24: it pads every write, so no two infections share a hash."
    fi
}

# 11. Theme injection.
check_theme_injection() {
    local site="$1" f any=0
    head2 "Theme injection"
    while IFS= read -r f; do
        if grep -qsF -e 'SC_TH_BEGIN' "$f"; then
            crit "SC_TH_BEGIN block appended to $f"; any=1
        elif has_long_b64 "$f" 4000; then
            crit "long base64 run in $f (embedded payload)"; any=1
        fi
    done < <(find "$site/wp-content/themes" -maxdepth 3 -name 'functions.php' 2>/dev/null)
    [ "$any" -eq 0 ] && okay "no theme injection markers (active and inactive themes checked)"
}

# 12. Access logs. The endpoints are eight-digit post IDs that cannot exist.
check_logs() {
    local site="$1" d f hits any=0 seen=""
    head2 "Access logs (?p=$D_EP_SW / ?p=$D_EP_IN)"

    local dirs=() cand
    for cand in ${LOGDIRS[@]+"${LOGDIRS[@]}"} "$site/logs" "$site/../logs" "$site/../../logs" \
                /var/log/nginx /var/log/apache2 /var/log/httpd; do
        [ -d "$cand" ] || continue
        cand="$(cd "$cand" 2>/dev/null && pwd -P)" || continue
        case " $seen " in *" $cand "*) continue ;; esac
        seen="$seen $cand"
        dirs+=("$cand")
    done
    if [ "${#dirs[@]}" -eq 0 ]; then
        note "no readable log directory found -- pass one with --logs /path"
        return
    fi

    local hitfiles=""
    for d in "${dirs[@]}"; do
        hits=$(grep -rlsE "[?&]p=(${D_EP_SW}|${D_EP_IN})" "$d" 2>/dev/null | head -10)
        [ -n "$hits" ] || continue
        while IFS= read -r f; do
            [ -n "$f" ] || continue
            hitfiles="$hitfiles $f"
            crit "SC endpoint requested, recorded in $f ($(grep -csE "[?&]p=(${D_EP_SW}|${D_EP_IN})" "$f" 2>/dev/null) line(s))"
            note "$(grep -hsE "[?&]p=(${D_EP_SW}|${D_EP_IN})" "$f" 2>/dev/null | head -1 | cut -c1-160)"
            any=1
        done <<< "$hits"
    done

    # Generic form, for an archived log from a site whose ABSPATH you no longer
    # know. Eight-digit post IDs starting with 9 do not occur naturally.
    for d in "${dirs[@]}"; do
        hits=$(grep -rlsE '[?&]p=9[0-9]{7}' "$d" 2>/dev/null | head -5)
        [ -n "$hits" ] || continue
        while IFS= read -r f; do
            [ -n "$f" ] || continue
            case " $hitfiles " in *" $f "*) continue ;; esac
            warn "request to ?p=9XXXXXXX (an impossible post ID) in $f"
            any=1
        done <<< "$hits"
    done

    if [ "$any" -eq 0 ]; then
        okay "no requests to the derived endpoints in the logs checked"
    else
        note "Each hit is a browser that fetched the worker. Those client IPs are"
        note "your list of administrators whose browsers need cleaning."
    fi
}

# 13. Database, via WP-CLI. Read-only queries only.
check_database() {
    local site="$1" a="$2" wp out prefix o keylist=""
    [ "$DO_DB" -eq 1 ] || return
    head2 "Database (WP-CLI)"

    if ! command -v wp >/dev/null 2>&1; then
        note "wp-cli not found -- skipping database checks."
        note "Run ./sc403-derive.sh --sql '$site' for the SQL to paste into phpMyAdmin."
        return
    fi
    wp="wp --path=$site --skip-plugins --skip-themes --quiet"

    if ! $wp option get siteurl >/dev/null 2>&1; then
        note "wp-cli cannot bootstrap this site -- skipping database checks"
        return
    fi
    prefix=$($wp db prefix 2>/dev/null | tr -d '\r\n')

    # 13a. Plaintext state rows.
    out=$($wp db query "SELECT option_name, LENGTH(option_value) AS bytes
                        FROM \`${prefix}options\`
                        WHERE option_name LIKE 'sc\\_%'
                           OR option_name LIKE '\\_transient%sc\\_%'
                        ORDER BY bytes DESC;" --skip-column-names 2>/dev/null)
    if [ -n "$out" ]; then
        while IFS= read -r line; do crit "SC option/transient: $line"; done <<< "$out"
        note "sc_c2_cache and sc_last_c2 hold the live C2 URLs in CLEARTEXT."
        note "Read them and keep them before anything is deleted."
    else
        okay "no sc_* options or transients"
    fi

    # 13b. The ten-hex payload row.
    out=$($wp option get "$D_OPT" 2>/dev/null | head -c 40)
    [ -n "$out" ] && crit "predicted payload option '$D_OPT' exists (base64 of a gzipped payload)"

    # 13c. The fourteen derived private options. These do NOT start with sc_,
    # which is why prefix-based cleanups miss them and prefix-based deletes
    # destroy the evidence in sw_cached and issued.
    for o in $PRIV_OPTS ""; do
        keylist="$keylist,'$(option_key "$a" "$o")'"
    done
    keylist="${keylist#,}"
    out=$($wp db query "SELECT option_name, LENGTH(option_value) AS bytes
                        FROM \`${prefix}options\`
                        WHERE option_name IN ($keylist);" --skip-column-names 2>/dev/null)
    if [ -n "$out" ]; then
        while IFS= read -r line; do crit "derived private option present: $line"; done <<< "$out"
        note "Decode one with: ./sc403-derive.sh --decode '<option_value>'"
        note "sw_url names the worker in your admins' browsers; issued lists the"
        note "administrators currently holding forged 14-day sessions."
    else
        okay "none of the fourteen derived option keys are present"
    fi

    # 13d. Orphans: derived-shaped rows that do NOT belong to this ABSPATH.
    # Every name comes from the install path, so a site that was moved or
    # copied while infected leaves its old rows behind -- including a worker
    # URL still registered in somebody's browser at an id nobody can derive.
    out=$($wp db query "SELECT option_name, LENGTH(option_value) AS bytes
                        FROM \`${prefix}options\`
                        WHERE CHAR_LENGTH(option_name) = 12
                          AND option_name REGEXP '^[0-9a-f]{12}$'
                          AND option_name NOT IN ($keylist)
                        LIMIT 20;" --skip-column-names 2>/dev/null)
    if [ -n "$out" ]; then
        while IFS= read -r line; do
            warn "12-hex option row that this ABSPATH does not predict: $line"
        done <<< "$out"
        note "Either the site was moved/copied while infected (old rows orphaned),"
        note "or another plugin uses generated names. Decode one to find out --"
        note "if it decodes to PHP-serialised data under the SC codec, it is SC's."
    else
        okay "no unexplained 12-hex option rows"
    fi

    # 13e. Oversized options.
    out=$($wp db query "SELECT option_name, LENGTH(option_value) AS bytes
                        FROM \`${prefix}options\`
                        WHERE LENGTH(option_value) > 50000
                        ORDER BY bytes DESC LIMIT 10;" --skip-column-names 2>/dev/null)
    [ -n "$out" ] && while IFS= read -r line; do
        info "large option (validate ownership before touching): $line"
    done <<< "$out"

    # 13f. Scheduled recovery. The hook names rotate; the cron array is the
    # authority, and a corrupted cron array is itself an indicator.
    if $wp cron event list --fields=hook --format=csv 2>/dev/null | grep -qi 'sc_cron_fetch'; then
        crit "scheduled event sc_cron_fetch is registered"
    else
        okay "sc_cron_fetch not scheduled"
    fi
    out=$($wp cron event list --fields=hook --format=csv 2>/dev/null \
          | grep -Ei '^[a-z0-9_]{12,}$' | grep -viE 'wp_|action_scheduler|akismet|jetpack' | head -5)
    [ -n "$out" ] && while IFS= read -r line; do
        warn "cron hook with a generated-looking name: $line"
    done <<< "$out"

    # 13g. Hidden administrators: API view against raw SQL.
    local api_admins raw_admins hidden
    api_admins=$($wp user list --role=administrator --field=user_login --format=csv 2>/dev/null | sort -u)
    raw_admins=$($wp db query "SELECT u.user_login FROM \`${prefix}users\` u
                               JOIN \`${prefix}usermeta\` m ON m.user_id = u.ID
                               WHERE m.meta_key = '${prefix}capabilities'
                                 AND m.meta_value LIKE '%administrator%';" \
                 --skip-column-names 2>/dev/null | sort -u)

    if [ -n "$raw_admins" ]; then
        hidden=$(comm -13 <(printf '%s\n' "$api_admins") <(printf '%s\n' "$raw_admins"))
        if [ -n "$hidden" ]; then
            while IFS= read -r u; do
                [ -n "$u" ] && crit "administrator '$u' exists in the database but is hidden from wp user list"
            done <<< "$hidden"
        else
            okay "administrator list matches the database (no pre_user_query concealment)"
        fi
        while IFS= read -r u; do
            [ -n "$u" ] || continue
            if printf '%s' "$u" | grep -qE "$ADMIN_PATTERN"; then
                crit "administrator '$u' matches the SC generated-name pattern"
            fi
        done <<< "$raw_admins"
    fi

    # 13h. Forged sessions. The implant writes session_tokens meta directly for
    # existing administrators, with a 14-day expiry. Rotating a password does
    # not invalidate those; only rotating the salts does.
    out=$($wp db query "SELECT COUNT(*) FROM \`${prefix}usermeta\`
                        WHERE meta_key = 'session_tokens';" --skip-column-names 2>/dev/null)
    if [ -n "$out" ] && [ "$out" -gt 0 ] 2>/dev/null; then
        info "$out user(s) hold session_tokens meta -- rotate the wp-config.php salts, not just passwords"
    fi
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

printf '%ssc403-scan %s -- read-only. Nothing on disk or in the database is modified.%s\n' "$D" "$VERSION" "$N"

if [ "${#SITES[@]}" -eq 0 ]; then
    printf '%sdiscovering WordPress installations (depth %s)...%s\n' "$D" "$DEPTH" "$N"
    while IFS= read -r s; do [ -n "$s" ] && SITES+=("$s"); done < <(discover_sites)
fi

if [ "${#SITES[@]}" -eq 0 ]; then
    echo "No WordPress installation found. Pass one explicitly with -p /path/to/site." >&2
    exit 64
fi

printf '%s%s site(s) in scope. SC 4.x spreads to every site the same OS user can write.%s\n' \
       "$D" "${#SITES[@]}" "$N"

for site in "${SITES[@]}"; do
    [ -d "$site" ] || { warn "not a directory: $site"; continue; }

    # ABSPATH as the malware normalises it: trailing slash, forward slashes.
    ABS="${site%/}/"
    derive_names "$ABS"

    if [ "$NAMES_ONLY" -eq 1 ]; then
        print_names "$site" "$ABS"
        continue
    fi

    head1 "$site"
    check_prepend         "$site"
    check_mu_plugins      "$site"
    check_dropins         "$site"
    check_derived_names   "$site" "$ABS"
    check_markers         "$site"
    check_hidden_loaders  "$site"
    check_padding         "$site"
    check_archives        "$site"
    check_theme_injection "$site"
    check_timestomp       "$site"
    check_hashes          "$site"
    check_logs            "$site"
    check_database        "$site" "$ABS"
done

[ "$NAMES_ONLY" -eq 1 ] && exit 0

head1 "Summary"
printf '  %scritical: %s%s   %swarnings: %s%s   %sinfo: %s%s\n\n' \
       "$R" "$CRIT_N" "$N" "$Y" "$WARN_N" "$N" "$B" "$INFO_N" "$N"

if [ "$CRIT_N" -gt 0 ]; then
    cat <<'MSG'
  Critical indicators found. Before you delete anything, read the eradication
  order in README.md. Deleting the file you can see, while the drop-ins, theme
  block, ZIP replicas, database payload and shared memory are still live, is
  what makes this malware look unkillable.

  Two things that are easy to get wrong and expensive to undo:

    1. Restart the PHP-FPM pool BEFORE you delete files. The payload also lives
       in System V shared memory and in a detached CLI process. Deleting first
       just gives them something to rebuild.

    2. Capture the database rows before you clean them. sc_c2_cache holds the
       live C2 URLs in cleartext, and the derived sw_url / issued rows name the
       service worker in your admins' browsers and the forged sessions. None of
       the derived rows start with sc_, so `DELETE ... LIKE 'sc\_%'` destroys
       the evidence and leaves the implant's own state behind.

  Do not log in to wp-admin from a browser you have used on this site until the
  service worker is unregistered -- it can re-upload the plugin using your own
  authenticated session. 00-sc403-sw-neutralizer.php does that passively.
MSG
    exit 2
fi
[ "$WARN_N" -gt 0 ] && { echo "  Leads to validate by hand. Warnings alone are not a diagnosis."; exit 1; }
echo "  No SC 4.x indicators found. This is not proof the site is clean; see README."
exit 0
