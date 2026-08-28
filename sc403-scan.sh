#!/usr/bin/env bash
#
# sc403-scan.sh -- read-only detector for the "SC 4.0.3" self-healing WordPress malware
#
# This script NEVER deletes, moves, quarantines or modifies anything. It reads and
# reports. That is deliberate: SC 4.0.3 keeps redundant copies of itself in PHP
# startup config, MU-plugins, WordPress drop-ins, theme code, ZIP archives, the
# options table, System V shared memory and administrator browsers. Removing one
# node while the others are live invites an immediate rebuild, so eradication has
# to be one coordinated pass by a human -- see README.md.
#
# Usage:
#   ./sc403-scan.sh                     # auto-discover every WordPress root you can read
#   ./sc403-scan.sh -p /var/www/site    # scan specific roots (repeatable)
#   ./sc403-scan.sh --no-db             # skip the WP-CLI database checks
#
# Exit codes:  0 = nothing found   1 = warnings only   2 = critical findings
#
# Repo:    https://github.com/ux2dev/wordpress-sc403-cleaner
# License: GPL-2.0-or-later
#
set -uo pipefail

VERSION="1.0.0"

# ---------------------------------------------------------------------------
# Indicators. Keep in sync with iocs.csv.
# ---------------------------------------------------------------------------

# Markers implemented directly in recovered SC 4.0.3 code. A hit is decisive.
STRONG_MARKERS=(
    'SC_ADV_BEGIN'
    'SC_ADV_END'
    'SC_DB_BEGIN'
    'SC_DB_END'
    'SC_TH_BEGIN'
    'SC_TH_END'
    'sc_payload_persistent'
    'sc_persist_manifest'
    'sc_cron_fetch'
    'sc_last_recovery_check'
    'sc_last_rpc'
    'sc_last_fetch_ts'
    '0x3bc5de30'
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
)

# Ethereum contracts used as the dead-drop C2 resolver.
CONTRACTS=(
    '0x9A4752cAA1C15868487A0ACb691F81bfA901E063'
    '0x839d1cE5c3F259e8d3D17114d7186EDabdbeA94b'
    '0x6d2c5435EF70196740a48904B69377935D50abBB'
)

# SHA-256 of artefacts recovered by MD Pabel (August 2026).
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

# Shared "timestomp" watermark: mtime %% 100000 == 93819.
WATERMARK=93819

# Shared-hosting roots the malware itself walks when looking for sibling sites.
SPREAD_ROOTS=(/home /var/www /var/www/vhosts /srv/www /srv/users)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------

SITES=()
DEPTH=6
DO_DB=1
DO_HASH=1
QUIET=0

usage() {
    sed -n '2,/^set -/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        -p|--path)  SITES+=("${2:-}"); shift 2 ;;
        -d|--depth) DEPTH="${2:-6}";   shift 2 ;;
        --no-db)    DO_DB=0;   shift ;;
        --no-hash)  DO_HASH=0; shift ;;
        -q|--quiet) QUIET=1;   shift ;;
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
    elif command -v md5    >/dev/null 2>&1; then printf '%s' "$1" | md5
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

    # wp-content is a separate scope worth checking explicitly.
    for f in "$site/wp-content/.user.ini" "$site/wp-content/.htaccess"; do
        [ -f "$f" ] || continue
        if grep -qs 'auto_prepend_file' "$f"; then
            crit "auto_prepend_file directive in $f"; found=1
        fi
    done

    [ "$found" -eq 0 ] && okay "no auto_prepend_file directives found"
    if [ "$found" -eq 1 ]; then
        note "PHP caches per-directory INI for user_ini.cache_ttl (default 300s);"
        note "removing the file does not stop workers that already read it."
    fi
}

# 2. Content markers anywhere under the site.
check_markers() {
    local site="$1" m hits args=()
    head2 "Content markers"

    for m in "${STRONG_MARKERS[@]}"; do args+=(-e "$m"); done
    hits=$(grep -rlI --include='*.php' --include='*.js' --include='*.ini' \
                 -F "${args[@]}" "$site" 2>/dev/null | head -50)
    if [ -n "$hits" ]; then
        while IFS= read -r f; do crit "SC 4.0.3 marker in $f"; done <<< "$hits"
    else
        okay "no SC 4.0.3 markers"
    fi

    args=()
    for m in "${CONTRACTS[@]}"; do args+=(-e "$m"); done
    hits=$(grep -rlI --include='*.php' --include='*.js' -F "${args[@]}" "$site" 2>/dev/null | head -20)
    [ -n "$hits" ] && while IFS= read -r f; do crit "C2 contract address in $f"; done <<< "$hits"

    args=()
    for m in "${WEAK_MARKERS[@]}"; do args+=(-e "$m"); done
    hits=$(grep -rlI --include='*.php' -F "${args[@]}" "$site/wp-content" 2>/dev/null | head -30)
    if [ -n "$hits" ]; then
        while IFS= read -r f; do warn "suspicious API in $f (verify by hand)"; done <<< "$hits"
    fi
}

# 3. MU-plugins. Size, and the twin-copy signature.
check_mu_plugins() {
    local site="$1" mu="$site/wp-content/mu-plugins" f base sz
    head2 "Must-use plugins"

    if [ ! -d "$mu" ]; then okay "no mu-plugins directory"; return; fi

    local any=0
    while IFS= read -r f; do
        any=1
        base="$(basename "$f" .php)"
        sz="$(file_size "$f")"
        if   [ "${sz:-0}" -gt 1048576 ]; then crit "MU-plugin ${sz}B is implausibly large: $f"
        elif [ "${sz:-0}" -gt 102400  ]; then warn "MU-plugin ${sz}B is unusually large: $f"
        else info "MU-plugin ${sz}B: $f"
        fi
        # The defining SC 4.0.3 layout: identical basename as MU-plugin AND as a
        # normal plugin, so either replica can restore the other.
        if [ -f "$site/wp-content/plugins/$base/$base.php" ]; then
            crit "twin copy: $base exists as both MU-plugin and ordinary plugin"
        fi
        # A read-only MU-plugin is how the implant discourages casual editing.
        if [ ! -w "$f" ]; then warn "MU-plugin is not writable (0444 is an SC 4.0.3 trait): $f"; fi
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
        if grep -qsF -e 'SC_DB_BEGIN' -e 'SC_ADV_BEGIN' -e 'sc_payload_persistent' "$f"; then
            crit "drop-in carries an SC 4.0.3 implant: $f"
        else
            info "drop-in present ($(file_size "$f")B): $f -- confirm it belongs to a caching/DB plugin you installed"
        fi
        # A drop-in holding a huge base64 run is an embedded payload.
        if has_long_b64 "$f" 4000; then
            crit "drop-in contains a >4000-char base64 run (embedded payload): $f"
        fi
    done
    [ "$any" -eq 0 ] && okay "no db.php / advanced-cache.php / object-cache.php drop-ins"
}

# 5. Names the malware derives from ABSPATH. Site-specific, high signal.
check_derived_names() {
    local site="$1" abspath ldr zip inst sw opt thm f
    head2 "Site-specific artefact names derived from ABSPATH"

    abspath="$site/"
    ldr="$(md5_str "${abspath}ldr")";  ldr="${ldr:0:8}"
    zip="$(md5_str "${abspath}zip")";  zip="${zip:0:8}"
    inst="$(md5_str "${abspath}inst")"; inst="${inst:0:8}"
    sw="$(md5_str "${abspath}sw")";    sw="${sw:0:8}"
    opt="$(md5_str "${abspath}opt")";  opt="${opt:0:10}"
    thm="$(md5_str "${abspath}th_m")"; thm="${thm:0:8}"

    note "loader=$ldr zip=$zip installer=$inst sw=$sw option=$opt theme-marker=$thm"
    DERIVED_OPT="$opt"

    local found=0
    for f in "$site/wp-content/$ldr.php" "$site/wp-content/.$ldr.php" \
             "$site/$ldr.php" "$site/.$ldr.php" \
             "$site/wp-content/$inst.php" "$site/wp-content/$sw.js"; do
        [ -e "$f" ] && { crit "predicted SC 4.0.3 artefact exists: $f"; found=1; }
    done
    while IFS= read -r f; do
        crit "predicted SC 4.0.3 archive exists: $f"; found=1
    done < <(find "$site" -maxdepth 4 -name "$zip.zip" 2>/dev/null)

    if grep -rqsF "$thm" "$site/wp-content/themes" 2>/dev/null; then
        crit "predicted theme marker $thm present in a theme file"; found=1
    fi

    [ "$found" -eq 0 ] && okay "none of the six predicted artefact names exist on disk"
}

# 6. Hidden loaders and guard stubs.
check_hidden_loaders() {
    local site="$1" f any=0
    head2 "Hidden loaders and guard stubs"

    while IFS= read -r f; do
        crit "guard stub: $f"; any=1
    done < <(find "$site" -type f -name '.g_*.php' 2>/dev/null | head -20)

    while IFS= read -r f; do
        warn "hex-named PHP file (validate contents, do not delete on sight): $f"; any=1
    done < <(find "$site/wp-content" -maxdepth 2 -type f \
                  \( -name '.[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f].php' \
                  -o -name '[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f].php' \) \
                  2>/dev/null | head -20)

    # PHP that has no business living in uploads or cache.
    while IFS= read -r f; do
        warn "PHP file in an upload/cache directory: $f"; any=1
    done < <(find "$site/wp-content/uploads" "$site/wp-content/cache" \
                  -type f -name '*.php' 2>/dev/null | head -20)

    [ "$any" -eq 0 ] && okay "no guard stubs or stray hex-named PHP files"
}

# 7. ZIP backups seeded around the tree.
check_archives() {
    local site="$1" f any=0
    head2 "Archive backups"
    while IFS= read -r f; do
        warn "archive inside wp-content (SC 4.0.3 seeds ZIP replicas here): $f"; any=1
    done < <(find "$site/wp-content" -maxdepth 4 -type f -name '*.zip' 2>/dev/null | head -20)
    [ "$any" -eq 0 ] && okay "no archives under wp-content"
}

# 8. The shared timestomp watermark.
check_timestomp() {
    local site="$1" any=0 f
    head2 "Timestamp watermark (mtime mod 100000 == $WATERMARK)"
    while IFS= read -r f; do
        crit "watermarked mtime: $f"; any=1
    done < <(php_mtimes "$site/wp-content" | awk -v w="$WATERMARK" '$1 % 100000 == w {sub(/^[0-9]+ /,""); print}' | head -20)
    [ "$any" -eq 0 ] && okay "no watermarked timestamps"
}

# 9. Known-bad file hashes.
check_hashes() {
    local site="$1" f h entry hash label any=0
    [ "$DO_HASH" -eq 1 ] || return
    head2 "Known SHA-256 artefacts"
    while IFS= read -r f; do
        h="$(sha256_file "$f")"
        [ -n "$h" ] || continue
        for entry in "${KNOWN_HASHES[@]}"; do
            hash="${entry%%:*}"; label="${entry#*:}"
            if [ "$h" = "$hash" ]; then crit "exact match ($label): $f"; any=1; fi
        done
    done < <(find "$site/wp-content" -maxdepth 3 -type f \( -name '*.php' -o -name '*.ini' \) -size +1k 2>/dev/null | head -400)
    [ "$any" -eq 0 ] && okay "no known-bad hashes among scanned files"
}

# 10. Theme injection.
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

# 11. Database, via WP-CLI. Read-only queries only.
check_database() {
    local site="$1" wp out prefix
    [ "$DO_DB" -eq 1 ] || return
    head2 "Database (WP-CLI)"

    if ! command -v wp >/dev/null 2>&1; then
        note "wp-cli not found -- skipping database checks (see README for the SQL equivalents)"
        return
    fi
    wp="wp --path=$site --skip-plugins --skip-themes --quiet"

    if ! $wp option get siteurl >/dev/null 2>&1; then
        note "wp-cli cannot bootstrap this site -- skipping database checks"
        return
    fi

    # SC options and transients.
    out=$($wp db query "SELECT option_name, LENGTH(option_value) AS bytes
                        FROM \`$($wp db prefix 2>/dev/null | tr -d '\r\n')options\`
                        WHERE option_name LIKE 'sc\\_%'
                           OR option_name LIKE '\\_transient%sc\\_%'
                        ORDER BY bytes DESC;" --skip-column-names 2>/dev/null)
    if [ -n "$out" ]; then
        while IFS= read -r line; do crit "SC option/transient: $line"; done <<< "$out"
    else
        okay "no sc_* options or transients"
    fi

    # The ABSPATH-derived option name predicted above.
    if [ -n "${DERIVED_OPT:-}" ]; then
        out=$($wp option get "$DERIVED_OPT" 2>/dev/null | head -c 40)
        [ -n "$out" ] && crit "predicted payload option '$DERIVED_OPT' exists in the database"
    fi

    # Oversized options are where the payload hides.
    out=$($wp db query "SELECT option_name, LENGTH(option_value) AS bytes
                        FROM \`$($wp db prefix 2>/dev/null | tr -d '\r\n')options\`
                        WHERE LENGTH(option_value) > 50000
                        ORDER BY bytes DESC LIMIT 10;" --skip-column-names 2>/dev/null)
    [ -n "$out" ] && while IFS= read -r line; do
        info "large option (validate ownership before touching): $line"
    done <<< "$out"

    # Scheduled recovery.
    if $wp cron event list --fields=hook --format=csv 2>/dev/null | grep -qi 'sc_cron_fetch'; then
        crit "scheduled event sc_cron_fetch is registered"
    else
        okay "sc_cron_fetch not scheduled"
    fi

    # Hidden administrators: compare what the API reports against raw SQL.
    # The implant filters pre_user_query and the REST results, but it cannot
    # filter a direct query against usermeta.
    local api_admins raw_admins
    api_admins=$($wp user list --role=administrator --field=user_login --format=csv 2>/dev/null | sort -u)
    prefix=$($wp db prefix 2>/dev/null | tr -d '\r\n')
    raw_admins=$($wp db query "SELECT u.user_login FROM \`${prefix}users\` u
                               JOIN \`${prefix}usermeta\` m ON m.user_id = u.ID
                               WHERE m.meta_key = '${prefix}capabilities'
                                 AND m.meta_value LIKE '%administrator%';" \
                 --skip-column-names 2>/dev/null | sort -u)

    if [ -n "$raw_admins" ]; then
        local hidden
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
                crit "administrator '$u' matches the SC 4.0.3 generated-name pattern"
            fi
        done <<< "$raw_admins"
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

printf '%s%s site(s) in scope. SC 4.0.3 spreads to every site the same OS user can write.%s\n' \
       "$D" "${#SITES[@]}" "$N"

for site in "${SITES[@]}"; do
    [ -d "$site" ] || { warn "not a directory: $site"; continue; }
    head1 "$site"
    DERIVED_OPT=""
    check_prepend         "$site"
    check_mu_plugins      "$site"
    check_dropins         "$site"
    check_derived_names   "$site"
    check_markers         "$site"
    check_hidden_loaders  "$site"
    check_archives        "$site"
    check_theme_injection "$site"
    check_timestomp       "$site"
    check_hashes          "$site"
    check_database        "$site"
done

head1 "Summary"
printf '  %scritical: %s%s   %swarnings: %s%s   %sinfo: %s%s\n\n' \
       "$R" "$CRIT_N" "$N" "$Y" "$WARN_N" "$N" "$B" "$INFO_N" "$N"

if [ "$CRIT_N" -gt 0 ]; then
    cat <<'MSG'
  Critical indicators found. Before you delete anything, read the eradication
  order in README.md. Deleting the file you can see, while the drop-ins, theme
  block, ZIP replicas, database payload and shared memory are still live, is
  what makes this malware look unkillable.

  Do not log in to wp-admin from a browser you have used on this site until the
  service worker is unregistered -- it can re-upload the plugin using your
  own authenticated session.
MSG
    exit 2
fi
[ "$WARN_N" -gt 0 ] && { echo "  Leads to validate by hand. Warnings alone are not a diagnosis."; exit 1; }
echo "  No SC 4.0.3 indicators found. This is not proof the site is clean; see README."
exit 0
