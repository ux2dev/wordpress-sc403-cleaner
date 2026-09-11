#!/usr/bin/env bash
# SC WordPress account-level cleanup coordinator v43-offline.
# Root-only. Quarantines every WordPress installation under one cPanel account
# before cleaning any single site, then runs the embedded per-site cleaner.

set -Eeuo pipefail
umask 077

SCRIPT_NAME="${0##*/}"
GUARD_PID=""
GUARD_PARENT_PID=$$
WORKER_FILE=""
# Where evidence/report trees are written. Overridable so the suite can exercise
# the real code paths without writing under /root.
SC_REPORT_ROOT="${SC_REPORT_ROOT:-/root/wp-sc-account-cleaner}"

usage() {
    cat <<EOF
Usage:
  $SCRIPT_NAME CPANEL_USER

Example:
  $SCRIPT_NAME wpclient

Behavior:
  * discovers every valid WordPress tree below the cPanel user's home
  * quarantines ALL discovered sites before cleaning the first one
  * pauses the user's crontab once for the entire account
  * kills existing account PHP processes and runs a continuous malware guard
  * runs the full SC cleaner against every WordPress installation
  * releases the account only if every site verifies clean
  * wp-includes is locked only while cleanup is running and -i/-a are ALWAYS cleared before exit
EOF
}

# `grep -q` stops at the first match and closes the pipe. Under `pipefail` the
# producer is then killed by SIGPIPE and the pipeline reports 141, which turns a
# real match into a silent miss. Every "does this text match" test therefore
# lets grep drain stdin instead of exiting early.
matches_stdin() {
    grep -Ei -- "$1" >/dev/null
}

# Extract the file that one auto_prepend_file directive points at. Handles the
# Apache forms (`php_value` / `php_admin_value NAME VALUE`) and the ini form
# (`NAME = VALUE`), single or double quotes, and any letter case.
sc_auto_prepend_target() {
    local line="$1" target
    target="$(printf '%s\n' "$line" | awk '{ l=tolower($0); p=index(l,"auto_prepend_file"); if (p) print substr($0,p+17) }')"
    [[ -n "$target" ]] || return 0
    target="${target#"${target%%[![:space:]]*}"}"
    if [[ "$target" == =* ]]; then
        target="${target#=}"
        target="${target#"${target%%[![:space:]]*}"}"
    fi
    case "$target" in
        \"*) target="${target#\"}"; target="${target%%\"*}" ;;
        \'*) target="${target#\'}"; target="${target%%\'*}" ;;
        *)   target="${target%%[[:space:];#]*}" ;;
    esac
    printf '%s\n' "$target"
}

# Probe a path with a hard timeout. `if timeout ...; then` cannot report 124,
# because a bare `if` whose branch is not taken resets $? to 0.
sc_path_exists_timed() {
    local rc=0
    timeout 2s /usr/bin/test -e "$1" || rc=$?
    return "$rc"
}

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_GREEN=$'\033[32m'; C_BLUE=$'\033[34m'; C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'; C_BOLD=$'\033[1m'; C_RESET=$'\033[0m'
else
    C_GREEN=''; C_BLUE=''; C_YELLOW=''; C_RED=''; C_BOLD=''; C_RESET=''
fi

status() {
    local kind="$1"; shift
    local color=""
    case "$kind" in
        CLEAN) color="$C_GREEN" ;;
        FIXED) color="$C_BLUE" ;;
        REVIEW) color="$C_YELLOW" ;;
        FOUND|FAILED) color="$C_RED" ;;
    esac
    printf '%b%-7s%b %s\n' "$color$C_BOLD" "$kind" "$C_RESET" "$*"
    if [[ -n "${LOG_FILE:-}" ]]; then
        printf '%-7s %s\n' "$kind" "$*" >> "$LOG_FILE"
    fi
    return 0
}

log() {
    printf '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG_FILE"
}

section() {
    printf '\n======================================================================\n%s\n======================================================================\n' "$*" | tee -a "$LOG_FILE"
}

fatal() {
    status FAILED "$*"
    exit 1
}

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    if [[ "${SC_ALLOW_NONROOT_TEST:-0}" == 1 ]]; then
        echo "WARNING: running unprivileged under SC_ALLOW_NONROOT_TEST=1; this is a test mode only." >&2
    else
        echo "ERROR: Run as root." >&2
        exit 1
    fi
fi
[[ $# -eq 1 ]] || { usage; exit 2; }
CPUSER="$1"

id "$CPUSER" >/dev/null 2>&1 || { echo "ERROR: Unix user '$CPUSER' does not exist." >&2; exit 1; }
for cmd in find realpath chattr lsattr pgrep pkill ps crontab grep awk sed sort md5sum mktemp cp cat chmod chown stat timeout head wc unzip; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR: Required command not found: $cmd" >&2; exit 1; }
done

USER_HOME="$(getent passwd "$CPUSER" | awk -F: '{print $6}')"
USER_HOME="$(realpath -e "$USER_HOME")"
STAMP="$(date '+%Y%m%d-%H%M%S')"
REPORT_DIR="${SC_REPORT_ROOT}/${CPUSER}/${STAMP}"
mkdir -p "$REPORT_DIR/quarantine" "$REPORT_DIR/sites"
LOG_FILE="$REPORT_DIR/account-cleanup.log"
touch "$LOG_FILE"
ROOTS_FILE="$REPORT_DIR/wordpress-roots.txt"
RESULTS_FILE="$REPORT_DIR/site-results.tsv"
HTMETA="$REPORT_DIR/quarantine/htaccess.tsv"
ACCOUNT_HTACCESS_RESTORED=0
LOCKMETA="$REPORT_DIR/quarantine/wp-includes.tsv"
CRONTAB_BACKUP="$REPORT_DIR/quarantine/crontab.before"
HARD_GUARD_FLAG="$REPORT_DIR/account-guard-hard.flag"
: > "$RESULTS_FILE"; : > "$HTMETA"; : > "$LOCKMETA"; : > "$CRONTAB_BACKUP"
rm -f -- "$HARD_GUARD_FLAG"

section "SC WORDPRESS ACCOUNT CLEANER v43-offline"
log "cPanel user: $CPUSER"
log "Home: $USER_HOME"
log "Account report: $REPORT_DIR"

# Find all full WordPress installations. This intentionally includes valid sibling
# copies below the account home because any writable WordPress tree can act as a
# persistence/re-seeding target during this campaign.
find "$USER_HOME" -type f -name wp-config.php -print 2>/dev/null \
    | while IFS= read -r cfg; do
        root="${cfg%/wp-config.php}"
        [[ -d "$root/wp-includes" && -f "$root/wp-includes/version.php" && -d "$root/wp-admin" && -d "$root/wp-content" ]] || continue
        realpath -e "$root" 2>/dev/null || true
      done \
    | sort -u > "$ROOTS_FILE"

SITE_COUNT="$(awk 'END{print NR+0}' "$ROOTS_FILE")"
[[ "$SITE_COUNT" -gt 0 ]] || fatal "No valid WordPress installations found below $USER_HOME"
status FOUND "Discovered $SITE_COUNT WordPress installation(s) under $CPUSER"
sed 's/^/         /' "$ROOTS_FILE" | tee -a "$LOG_FILE"

site_id() {
    printf '%s' "$1" | md5sum | awk '{print substr($1,1,12)}'
}

attr_flags() {
    lsattr -d "$1" 2>/dev/null | awk '{print $1}' | head -n1 || true
}

lock_all_wp_includes() {
    # A filesystem without chattr support (overlayfs, some NFS/quota setups) must
    # degrade to "no temporary lock", not abort the whole account cleanup. The
    # HTTP 503, the paused crontab and the HARD PHP guard remain in force.
    local root dir flags id unlocked=0
    : > "$REPORT_DIR/wp-includes-lock-unavailable.txt"
    while IFS= read -r root; do
        [[ -n "$root" ]] || continue
        dir="$root/wp-includes"
        flags="$(attr_flags "$dir")"
        id="$(site_id "$root")"
        printf '%s\t%s\t%s\n' "$id" "$root" "${flags:--}" >> "$LOCKMETA"
        if [[ "$flags" == *i* ]]; then
            status CLEAN "wp-includes already immutable: $root"
        elif chattr +i "$dir" 2>/dev/null; then
            status FIXED "Locked wp-includes: $root"
        else
            printf '%s\n' "$dir" >> "$REPORT_DIR/wp-includes-lock-unavailable.txt"
            unlocked=$((unlocked+1))
            status REVIEW "Filesystem does not support the temporary wp-includes lock: $root"
        fi
    done < "$ROOTS_FILE"
    if [[ "$unlocked" -gt 0 ]]; then
        status REVIEW "$unlocked wp-includes director(y/ies) could not be locked; continuing with HTTP 503 + cron pause + HARD PHP guard only"
    fi
    return 0
}

sanitize_campaign_auto_prepend_in_htaccess() {
    local root="$1" f="$2" line target resolved bn tmp malicious=0
    [[ -f "$f" ]] || return 0
    while IFS= read -r line; do
        target="$(sc_auto_prepend_target "$line")"
        [[ -n "$target" ]] || continue
        if [[ "$target" = /* ]]; then resolved="$(realpath -m "$target" 2>/dev/null || true)"; else resolved="$(realpath -m "$root/$target" 2>/dev/null || true)"; fi
        [[ -n "$resolved" ]] || continue
        case "$resolved" in "$root"/*) ;; *) continue ;; esac
        bn="${resolved##*/}"
        if [[ "$bn" =~ ^\.?[A-Za-z0-9]{6,40}\.php$ ]] || { [[ -f "$resolved" ]] && grep -Eqi 'SC_(ADV|DB|OC|DD|TH|DP)|SCOCV:|SCV:[0-9]+\.|elite-module-cue|SCD1:|--sc-cli|--sc-succ|__scf_[A-Za-z0-9_]{6,}|SC_CORE_BOOT_VER' "$resolved" 2>/dev/null; }; then
            malicious=1
        fi
    done < <(grep -Ei 'php(_admin)?_value[[:space:]]+auto_prepend_file|auto_prepend_file' "$f" 2>/dev/null || true)
    [[ "$malicious" -eq 1 ]] || return 0
    cp -a -- "$f" "$f.sc-malicious-before" 2>/dev/null || true
    tmp="$(mktemp "$REPORT_DIR/quarantine/htaccess-sanitize.XXXXXX")"
    grep -Evi 'php(_admin)?_value[[:space:]]+auto_prepend_file|^[[:space:]]*auto_prepend_file[[:space:]]*=' "$f" > "$tmp" 2>/dev/null || true
    cat "$tmp" > "$f"
    rm -f -- "$tmp"
    status FIXED "Removed campaign auto_prepend_file from quarantined .htaccess backup: $root"
}

quarantine_site_htaccess() {
    local root="$1" id ht backup existed=0 flags='' tmp tmp_orig group
    id="$(site_id "$root")"
    ht="$root/.htaccess"
    backup="$REPORT_DIR/quarantine/${id}.htaccess.original"
    if [[ -L "$ht" ]]; then
        status FAILED "Refusing to replace symlinked .htaccess: $ht"
        return 1
    fi
    if [[ -e "$ht" ]]; then
        existed=1
        cp -a -- "$ht" "$backup"
        flags="$(attr_flags "$ht")"
        chattr -ia -- "$ht" 2>/dev/null || true

        # Idempotent recovery from an interrupted earlier cleaner run. Our
        # quarantine block is always prepended at the start of .htaccess. If it
        # is already present, strip that block from the backup so "original"
        # really means the pre-quarantine contents and we do not stack 503
        # blocks or permanently restore a quarantine marker on release.
        if grep -q '^# BEGIN SC-ACCOUNT-CLEANER-QUARANTINE$' "$backup" 2>/dev/null; then
            tmp_orig="$(mktemp "$REPORT_DIR/quarantine/${id}.original.XXXXXX")"
            awk '
                /^# BEGIN SC-ACCOUNT-CLEANER-QUARANTINE$/ {skip=1; next}
                /^# END SC-ACCOUNT-CLEANER-QUARANTINE$/   {skip=0; next}
                !skip {print}
            ' "$backup" > "$tmp_orig"
            cat "$tmp_orig" > "$backup"
            rm -f "$tmp_orig"
            status CLEAN "Existing cleaner quarantine marker detected and normalized: $root"
        fi
        sanitize_campaign_auto_prepend_in_htaccess "$root" "$backup"
    else
        : > "$backup"
    fi
    tmp="$(mktemp "$REPORT_DIR/quarantine/${id}.htaccess.XXXXXX")"
    cat > "$tmp" <<'EOF'
# BEGIN SC-ACCOUNT-CLEANER-QUARANTINE
ErrorDocument 503 "Temporarily unavailable during security cleanup"
RewriteEngine On
RewriteRule ^ - [R=503,L]
# END SC-ACCOUNT-CLEANER-QUARANTINE
EOF
    if [[ "$existed" -eq 1 ]]; then
        cat "$backup" >> "$tmp"
        cat "$tmp" > "$ht"
        chown --reference="$backup" "$ht" 2>/dev/null || true
        chmod --reference="$backup" "$ht" 2>/dev/null || true
    else
        cat "$tmp" > "$ht"
        group="$(id -gn "$CPUSER")"
        chown "$CPUSER:$group" "$ht" 2>/dev/null || true
        chmod 0644 "$ht" 2>/dev/null || true
    fi
    rm -f "$tmp"
    printf '%s\t%s\t%s\t%s\t%s\n' "$id" "$root" "$existed" "${flags:--}" "$backup" >> "$HTMETA"
    status FIXED "HTTP 503 quarantine enabled: $root"
}

quarantine_all_sites() {
    local root failed=0
    while IFS= read -r root; do
        [[ -n "$root" ]] || continue
        quarantine_site_htaccess "$root" || failed=1
    done < "$ROOTS_FILE"
    [[ "$failed" -eq 0 ]] || fatal "Could not quarantine every WordPress site; refusing partial account cleanup"
}

restore_all_htaccess() {
    # HARD RULE: a temporary 503 must never survive this script. One site that
    # cannot be restored must therefore never stop the remaining sites from being
    # released, and the "already restored" flag must stay clear so the EXIT trap
    # gets another attempt.
    local id root existed flags backup ht failed=0
    [[ "${ACCOUNT_HTACCESS_RESTORED:-0}" -eq 0 ]] || return 0
    [[ -s "$HTMETA" ]] || { ACCOUNT_HTACCESS_RESTORED=1; return 0; }
    while IFS=$'\t' read -r id root existed flags backup; do
        [[ -n "$root" ]] || continue
        ht="$root/.htaccess"
        # TAB is IFS whitespace, so a run of tabs collapses and an empty flags
        # column shifts the row. The backup path is fully derivable from the site
        # id, so the one step that must not fail never depends on that column.
        backup="$REPORT_DIR/quarantine/${id}.htaccess.original"
        chattr -ia -- "$ht" 2>/dev/null || true
        if [[ "$existed" == 1 ]]; then
            if cp -a -- "$backup" "$ht" 2>/dev/null; then
                [[ "$flags" == *i* ]] && chattr +i -- "$ht" 2>/dev/null || true
                [[ "$flags" == *a* ]] && chattr +a -- "$ht" 2>/dev/null || true
                status FIXED "Original .htaccess restored: $root"
            else
                failed=$((failed+1))
                status FAILED "Could not restore $ht from $backup; remove the SC-ACCOUNT-CLEANER-QUARANTINE block manually"
                printf '%s\t%s\n' "$ht" "$backup" >> "$REPORT_DIR/htaccess-restore-failed.tsv"
            fi
        else
            if rm -f -- "$ht" 2>/dev/null; then
                status FIXED "Cleaner-created .htaccess removed: $root"
            else
                failed=$((failed+1))
                status FAILED "Could not remove cleaner-created $ht"
                printf '%s\t%s\n' "$ht" "(created-by-cleaner)" >> "$REPORT_DIR/htaccess-restore-failed.tsv"
            fi
        fi
    done < "$HTMETA"
    if [[ "$failed" -gt 0 ]]; then
        return 1
    fi
    ACCOUNT_HTACCESS_RESTORED=1
    return 0
}

pause_account_cron() {
    if crontab -u "$CPUSER" -l > "$CRONTAB_BACKUP" 2>/dev/null; then
        crontab -u "$CPUSER" -r 2>/dev/null || true
        echo 1 > "$REPORT_DIR/quarantine/crontab.existed"
        status FIXED "User crontab paused for the entire account"
    else
        echo 0 > "$REPORT_DIR/quarantine/crontab.existed"
        status CLEAN "No user crontab exists"
    fi
    # Do not use grep -R here. /etc/cron.d may contain symlinks or unusual
    # entries on hosting servers and recursive grep can walk outside cron.d or
    # appear to hang. Inspect only regular files directly inside cron.d.
    status CLEAN "Checking system cron references for $CPUSER"
    : > "$REPORT_DIR/system-cron-user-references.txt"
    if [[ -f /etc/crontab ]]; then
        grep -HE "(^|[[:space:]])${CPUSER}([[:space:]]|$)" /etc/crontab \
            >> "$REPORT_DIR/system-cron-user-references.txt" 2>/dev/null || true
    fi
    if [[ -d /etc/cron.d ]]; then
        while IFS= read -r -d '' cron_file; do
            grep -HE "(^|[[:space:]])${CPUSER}([[:space:]]|$)" "$cron_file" \
                >> "$REPORT_DIR/system-cron-user-references.txt" 2>/dev/null || true
        done < <(find /etc/cron.d -maxdepth 1 -type f -print0 2>/dev/null)
    fi
    if [[ -s "$REPORT_DIR/system-cron-user-references.txt" ]]; then
        status REVIEW "System cron entries reference $CPUSER; review system-cron-user-references.txt"
    else
        status CLEAN "No system cron references found for $CPUSER"
    fi
}

# Every containment measure this script leaves in place must come with the exact
# command that undoes it. The user crontab intentionally stays paused on review
# and abort paths, so the operator has to be told how to bring it back.
print_manual_restore_hints() {
    local f="$REPORT_DIR/RESTORE-COMMANDS.txt"
    {
        echo "# Manual restore commands for $CPUSER (report: $REPORT_DIR)"
        if [[ "$(cat "$REPORT_DIR/quarantine/crontab.existed" 2>/dev/null || echo 0)" == 1 ]]; then
            printf 'crontab -u %q %q\n' "$CPUSER" "$CRONTAB_BACKUP"
        else
            echo "# no user crontab existed before cleanup"
        fi
        if [[ -s "$REPORT_DIR/htaccess-restore-failed.tsv" ]]; then
            echo "# .htaccess files that could NOT be restored automatically:"
            awk -F'\t' '{printf "cp -a %s %s\n", $2, $1}' "$REPORT_DIR/htaccess-restore-failed.tsv"
        fi
        if [[ -s "$REPORT_DIR/wp-includes-lock-unavailable.txt" ]]; then
            echo "# wp-includes directories that could not be locked (no chattr support):"
            sed 's/^/# /' "$REPORT_DIR/wp-includes-lock-unavailable.txt"
        fi
    } > "$f" 2>/dev/null || return 0
    status REVIEW "User crontab remains paused. Restore commands: $f"
    return 0
}

restore_account_cron() {
    local existed
    existed="$(cat "$REPORT_DIR/quarantine/crontab.existed" 2>/dev/null || echo 0)"
    if [[ "$existed" -eq 1 ]]; then
        crontab -u "$CPUSER" "$CRONTAB_BACKUP" || return 1
        status FIXED "User crontab restored"
    fi
}

list_account_php_pids() {
    # Enumerate PHP-family processes owned by the cPanel user without relying on
    # malware filenames. During hard quarantine every one of these is unwanted.
    #
    # IMPORTANT: ps(1) may return 1 when the account currently owns no processes.
    # Under set -e + pipefail that normal idle state used to abort the entire
    # cleaner before HARD quarantine was enabled. Treat an empty process list as
    # success and always return 0 from this enumerator.
    { ps -u "$CPUSER" -o pid=,comm=,args= 2>/dev/null || true; } | while read -r pid comm args; do
        [[ "$pid" =~ ^[0-9]+$ ]] || continue
        case "$comm" in
            php|php[0-9]*|php-cgi|php-fpm|lsphp)
                printf '%s\n' "$pid"
                continue
                ;;
        esac
        case "$args" in
            /opt/cpanel/ea-php*/root/usr/bin/php*|/opt/alt/php*/usr/bin/php*|/usr/local/bin/php*|/usr/bin/php*|*/lsphp*)
                printf '%s\n' "$pid"
                ;;
        esac
    done | sort -u
    return 0
}

hard_guard_kill_account_php() {
    local pids="" killed=0
    # v43-offline has no WP-CLI/PHP allowlist. Every account-owned PHP process
    # is forbidden for the whole HARD quarantine window.
    while IFS= read -r pid; do
        [[ "$pid" =~ ^[0-9]+$ ]] || continue
        pids+="${pid} "
    done < <(list_account_php_pids)

    if [[ -n "$pids" ]]; then
        {
            printf '[%s] HARD QUARANTINE killing account PHP PIDs: %s\n' "$(date '+%F %T')" "$pids"
            ps -o user,pid,ppid,lstart,etime,args -p "$(printf '%s' "$pids" | xargs | tr ' ' ',')" 2>/dev/null || true
        } >> "$REPORT_DIR/account-quarantine-guard.log"
        kill -9 $pids 2>/dev/null || true
        killed="$(printf '%s' "$pids" | awk '{print NF}')"
    fi
    return 0
}

kill_account_php() {
    local pids count
    pids="$(list_account_php_pids | tr '\n' ' ' || true)"
    if [[ -z "$pids" ]]; then
        status CLEAN "No existing PHP processes required termination"
        return 0
    fi
    ps -o user,pid,ppid,lstart,etime,args -p "$(printf '%s' "$pids" | xargs | tr ' ' ',')" \
        > "$REPORT_DIR/account-php-processes-killed.txt" 2>/dev/null || true
    count="$(printf '%s' "$pids" | awk '{print NF}')"
    kill -9 $pids 2>/dev/null || true
    status FIXED "Killed $count existing PHP process(es) for $CPUSER"
}

# One definition of the campaign IOC set, shared by the account-wide scanners
# and by the worker, which carries an identical copy in its own half. v41 kept
# three private copies of this regex, and the DB-only indicators (the C2 host,
# the reversed-slug version marker and the campaign cron schedule name) were
# missing from every one of them.
IOC_REGEX='SC_DB_BEGIN|SC_DB_END|SC_ADV_BEGIN|SC_ADV_END|SC_OC_BEGIN|SC_OC_END|SCOCV:|SCV:[0-9]+\.|SC_DD_BEGIN|SC_DD_END|SC_TH_BEGIN|SC_TH_END|SC_TH_LD_|SCD1:|sc_payload_persistent|sc_payload_t|sc_cron_fetch|a18xgj672mowjoum|0x3bc5de30|/\.sc_[[:xdigit:]]+|\.gr_[[:xdigit:]]{32}\.php|\.grd_[[:xdigit:]]{8,40}|--sc-cli|--sc-succ|echo-compiler-plus|elite-module-cue|unity-manager-lite|\.wp-object-cache-[[:xdigit:]]{8,32}\.dat(\.lkg)?|\.(bt|sd|rd|q)_elite-module-cue|\.kk_[[:xdigit:]]{6,40}|\$_sc_done|\$_sc_lock|\$_sc_files|goto[[:space:]]+_sc_end|SC_FAIL|_sc_(padf|ul|coreld|corep|fpc|mkdir|unp|qok|aw|any_live|phpok_src|src)[[:space:]]*\(|static[[:space:]]*\$a=null;[[:space:]]*if[[:space:]]*\([[:space:]]*\$a===null[[:space:]]*\)[[:space:]]*\{[[:space:]]*\$a=array_merge\(array\(|/th[bv]_[[:xdigit:]]{8,40}\.bak|"gen":"[[:xdigit:]]{8,16}"|root-cherry|php\.euc-eludom-etile|sc_guard_interval|__scf_[A-Za-z0-9_]{6,}|SC_CORE_BOOT_VER|sc_boot_ver|SC_COVER_HOOKS|SC_AUTO_PREPEND|SC_DP_BEGIN|SC_DP_END|sc_cron_guard|/\.(sd|bt|swm|q|rd)_[A-Za-z0-9][A-Za-z0-9._-]{5,}|/\.mu_st_[A-Za-z0-9]{4,}|\.php\.scold[0-9]{3,}|0x9A4752cAA1C15868487A0ACb691F81bfA901E063|0x839d1cE5c3F259e8d3D17114d7186EDabdbeA94b|0x6d2c5435EF70196740a48904B69377935D50abBB'

# Legitimate software that ships its own `sc_`-prefixed names. ThemeREX Addons
# (`trx_addons`) and the themes bundling it name shortcodes, files and options
# `sc_*`, which collides with the campaign's family prefix. The allowlist may
# only ever suppress WEAK signals: a file inside an allowlisted path that also
# carries a decisive campaign marker is still treated as malicious, and known
# campaign option names are never spared. Extend per run with SC_EXTRA_LEGIT_RE.
SC_LEGIT_PATH_RE='(^|/)(trx_addons|trx-addons)(/|$)'

# Markers that settle the question on their own. Anything here outweighs the
# allowlist; everything else the IOC regex matches counts as a weak signal.
SC_DECISIVE_RE='SCV:[[:space:]]*[0-9]+\.|__scf_[A-Za-z0-9_]{6,}|SC_CORE_BOOT_VER|sc_boot_ver|SC_(TH|OC|DD|ADV|DB|DP)_(BEGIN|END)|SCOCV:|SCD1:|--sc-(cli|succ)|ionic-scheduler-orb|echo-compiler-plus|elite-module-cue|unity-manager-lite'

sc_legit_path_re() {
    if [[ -n "${SC_EXTRA_LEGIT_RE:-}" ]]; then
        printf '%s|%s' "$SC_LEGIT_PATH_RE" "$SC_EXTRA_LEGIT_RE"
    else
        printf '%s' "$SC_LEGIT_PATH_RE"
    fi
}

sc_path_is_legit() {
    # Bash's own matcher, not `printf | grep -q`: an early-exit grep on the far
    # side of a pipe is exactly the SIGPIPE trap this script bans everywhere.
    local p="$1" re
    [[ -n "$p" ]] || return 1
    re="$(sc_legit_path_re)"
    [[ "$p" =~ $re ]]
}

sc_file_is_decisive() {
    local f="$1"
    [[ -f "$f" ]] || return 1
    grep -Eq --binary-files=without-match "$SC_DECISIVE_RE" "$f" 2>/dev/null
}

# Filter `path:line:text` IOC hits. A hit inside allowlisted software is dropped
# only when that file carries no decisive marker, and every drop is recorded -
# an exclusion that leaves no trace in the report is a detection hole.
sc_filter_legit_ioc_lines() {
    local line f
    local -A verdict=()
    while IFS= read -r line; do
        f="${line%%:*}"
        if [[ -n "$f" ]] && sc_path_is_legit "$f"; then
            if [[ -z "${verdict[$f]:-}" ]]; then
                if sc_file_is_decisive "$f"; then verdict[$f]=keep; else verdict[$f]=drop; fi
            fi
            if [[ "${verdict[$f]}" == "drop" ]]; then
                printf '%s\n' "$line" >> "${REPORT_DIR:-/tmp}/legit-excluded.txt" 2>/dev/null || true
                continue
            fi
        fi
        printf '%s\n' "$line"
    done
    return 0
}


scan_global_g_files() {
    local root
    while IFS= read -r root; do
        [[ -n "$root" ]] || continue
        find "$root" -type f -iname '.g_*.php' -print 2>/dev/null || true
    done < "$ROOTS_FILE" | sort -u
}

scan_global_ionic_paths() {
    local root
    while IFS= read -r root; do
        [[ -n "$root" ]] || continue
        if [[ -d "$root/wp-content/plugins" ]]; then
            find "$root/wp-content/plugins" -mindepth 1 -maxdepth 1 -type d -name 'ionic-scheduler-orb*' -print 2>/dev/null || true
        fi
        if [[ -f "$root/wp-content/mu-plugins/ionic-scheduler-orb.php" ]]; then
            printf '%s\n' "$root/wp-content/mu-plugins/ionic-scheduler-orb.php"
        fi
    done < "$ROOTS_FILE" | sort -u
}

scan_global_echo_compiler_paths() {
    local root p rc verbose="${1:-0}"
    while IFS= read -r root; do
        [[ -n "$root" ]] || continue
        if [[ "$verbose" -eq 1 ]]; then
            status INFO "echo-compiler scan: $root" >&2
        fi
        for p in \
            "$root/wp-content/plugins/echo-compiler-plus" \
            "$root/wp-content/mu-plugins/echo-compiler-plus" \
            "$root/wp-content/mu-plugins/echo-compiler-plus.php"; do
            rc=0
            sc_path_exists_timed "$p" || rc=$?
            case "$rc" in
                0)   printf '%s\n' "$p" ;;
                124) printf '%s\n' "$p" >> "${PATH_SCAN_TIMEOUT_FILE:-/dev/null}"
                     status REVIEW "Timed out checking path: $p" >&2 ;;
            esac
        done
    done < "$ROOTS_FILE" | sort -u
}

scan_global_elite_module_cue_paths() {
    # This scanner covers confirmed campaign plugin slugs. unity-manager-lite was
    # observed being created by the same incident family; keep it in the same
    # high-confidence path gate so preflight/guard/final verification all agree.
    local root p
    while IFS= read -r root; do
        [[ -n "$root" ]] || continue
        for p in \
            "$root/wp-content/plugins/elite-module-cue" \
            "$root/wp-content/mu-plugins/elite-module-cue" \
            "$root/wp-content/mu-plugins/elite-module-cue.php" \
            "$root/wp-content/plugins/unity-manager-lite" \
            "$root/wp-content/mu-plugins/unity-manager-lite" \
            "$root/wp-content/mu-plugins/unity-manager-lite.php"; do
            if [[ -e "$p" ]]; then
                printf '%s\n' "$p"
            fi
        done
    done < "$ROOTS_FILE" | sort -u
}

scan_global_elite_state_artifacts() {
    local root p
    while IFS= read -r root; do
        [[ -n "$root" ]] || continue
        for p in \
            "$root/wp-content/.rd_elite-module-cue" \
            "$root/wp-content/.q_elite-module-cue" \
            "$root/wp-content/plugins/elite-module-cue/.bt_elite-module-cue" \
            "$root/wp-content/plugins/elite-module-cue/.sd_elite-module-cue" \
            "$root/wp-content/mu-plugins/.bt_elite-module-cue" \
            "$root/wp-content/mu-plugins/.sd_elite-module-cue"; do
            if [[ -e "$p" ]]; then printf '%s\n' "$p"; fi
        done
    done < "$ROOTS_FILE" | sort -u
}

scan_global_extensionless_payloads() {
    local root f
    while IFS= read -r root; do
        [[ -n "$root" ]] || continue
        for f in "$root/wp-admin/__PATH__" "$root/__PATH__" "$root/wp-content/__PATH__"; do
            [[ -f "$f" ]] || continue
            # 64 bytes and a case-insensitive tag: payloads have been seen with a
            # shebang, a BOM or `<?PHP` ahead of the opening tag.
            head -c 64 -- "$f" 2>/dev/null | matches_stdin '<\?php' || continue
            grep -Eqi 'elite-module-cue|unity-manager-lite|SCOCV:|SCV:[0-9]+\.|SC_OC_|SC_DD_|SC_DP_|SCD1:|__scf_[A-Za-z0-9_]{6,}|SC_CORE_BOOT_VER' "$f" 2>/dev/null || continue
            printf '%s\n' "$f"
        done
    done < "$ROOTS_FILE" | sort -u
}

scan_global_sc_runtime_paths() {
    local root wc d f
    while IFS= read -r root; do
        [[ -n "$root" ]] || continue
        wc="$root/wp-content"
        [[ -d "$wc" ]] || continue
        while IFS= read -r -d '' d; do
            [[ "${d##*/}" =~ ^\.sc_[[:xdigit:]]{6,40}$ ]] || continue
            f="$(find "$d" -maxdepth 1 -type f -regextype posix-extended -regex '.*/\.gr_[[:xdigit:]]{16,64}\.php' -print -quit 2>/dev/null || true)"
            if [[ -z "$f" ]]; then
                # `break` inside the reader can SIGPIPE find(1); with `pipefail` that
                # would fail the assignment and abort the whole run.
                f="$(find "$d" -maxdepth 1 -type f \( -name 'own_*.php' -o -name 'core_*.php' -o -name '.grd_*' \) -print 2>/dev/null | {
                        while IFS= read -r candidate; do
                            if grep -Eq 'elite-module-cue|unity-manager-lite|SCOCV:|SCV:[0-9]+\.|SC_OC_|SC_DD_|SC_DP_|--sc-cli|--sc-succ|__scf_[A-Za-z0-9_]{6,}|SC_CORE_BOOT_VER' "$candidate" 2>/dev/null; then
                                printf '%s\n' "$candidate"; break
                            fi
                        done
                        cat >/dev/null
                      } || true)"
            fi
            if [[ -z "$f" ]]; then
                local state_count core_count own_count grd_count
                state_count="$(find "$d" -maxdepth 1 \( -type f -o -type d \) -regextype posix-extended -regex '.*/\.(gk|gl|gm|gp|gs|gt|gv)_[[:xdigit:]]{8,40}(\.d)?' -printf x 2>/dev/null | wc -c)"
                core_count="$(find "$d" -maxdepth 1 -type f -name 'core_*.php' -printf x 2>/dev/null | wc -c)"
                own_count="$(find "$d" -maxdepth 1 -type f -name 'own_*.php' -printf x 2>/dev/null | wc -c)"
                grd_count="$(find "$d" -maxdepth 1 -type f -name '.grd_*' -printf x 2>/dev/null | wc -c)"
                if (( state_count >= 3 && core_count >= 1 && own_count >= 1 && grd_count >= 1 )); then
                    f="$d/.sc-structure-confirmed"
                fi
            fi
            [[ -n "$f" ]] || continue
            printf '%s\n%s\n' "$d" "$f"
        done < <(find "$wc" -mindepth 1 -maxdepth 1 -type d -name '.sc_*' -print0 2>/dev/null || true)
    done < "$ROOTS_FILE" | sort -u
}

scan_global_loose_gr_runners() {
    local root f bn
    while IFS= read -r root; do
        [[ -n "$root" && -d "$root" ]] || continue
        while IFS= read -r -d '' f; do
            [[ -f "$f" ]] || continue
            bn="${f##*/}"
            [[ "$bn" =~ ^\.gr_[[:xdigit:]]{32}\.php$ ]] || continue
            grep -Fq -- '--sc-cli' "$f" 2>/dev/null || continue
            grep -Fq -- '--sc-succ' "$f" 2>/dev/null || continue
            printf '%s\n' "$f"
        done < <(find "$root" -type f -name '.gr_*.php' -print0 2>/dev/null || true)
    done < "$ROOTS_FILE" | sort -u
}

scan_global_wp_object_cache_ioc() {
    local root f bn
    while IFS= read -r root; do
        [[ -n "$root" && -d "$root/wp-content" ]] || continue
        while IFS= read -r -d '' f; do
            [[ -f "$f" ]] || continue
            bn="${f##*/}"
            [[ "$bn" =~ ^\.wp-object-cache-[[:xdigit:]]{8,32}\.dat(\.lkg)?$ ]] || continue
            if head -c 16 -- "$f" 2>/dev/null | matches_stdin 'SCD1:'; then
                printf '%s\n' "$f"
                continue
            fi
            grep -Eq "$IOC_REGEX" "$f" 2>/dev/null || continue
            printf '%s\n' "$f"
        done < <(find "$root/wp-content" -type f \( -name '.wp-object-cache-*.dat' -o -name '.wp-object-cache-*.dat.lkg' \) -size -8M -print0 2>/dev/null || true)
    done < "$ROOTS_FILE" | sort -u
}

scan_global_sc_state_clusters() {
    local root wc p bn token
    while IFS= read -r root; do
        [[ -n "$root" ]] || continue
        wc="$root/wp-content"
        [[ -d "$wc" ]] || continue

        # One directory pass per WordPress root. v21 rescanned wp-content for
        # every candidate token (O(n^2)), which became very expensive while
        # the account guard was active.
        declare -A sc_state_count=()
        declare -A sc_state_paths=()
        while IFS= read -r -d '' p; do
            bn="${p##*/}"
            if [[ "$bn" =~ ^\.(gk|gl|gm|gp|gs|gt|gv)_([[:xdigit:]]{8,40})(\.d)?$ ]]; then
                token="${BASH_REMATCH[2]}"
                sc_state_count["$token"]=$(( ${sc_state_count["$token"]:-0} + 1 ))
                sc_state_paths["$token"]+="${p}"$'\n'
            fi
        done < <(find "$wc" -mindepth 1 -maxdepth 1 \( -type f -o -type d \) -name '.*_*' -print0 2>/dev/null || true)

        for token in "${!sc_state_count[@]}"; do
            if (( sc_state_count["$token"] >= 3 )); then
                printf '%s' "${sc_state_paths["$token"]}"
            fi
        done
        unset sc_state_count sc_state_paths
    done < "$ROOTS_FILE" | sort -u
}

scan_global_sc_ioc_lines() {
    local root
    while IFS= read -r root; do
        [[ -n "$root" && -d "$root" ]] || continue

        # Do not grep every byte under the whole WordPress tree. Large upload,
        # cache and backup trees made the v21 account-wide gate appear hung.
        # Campaign code observed so far lives in PHP/PHTML/PHAR, .user.ini or
        # small backup-like text files. Cap candidate size to avoid huge blobs.
        find "$root" -type f -size -32M \( \
                -iname '*.php' -o -iname '*.phtml' -o -iname '*.phar' \
                -o -iname '*.bak' -o -name '.user.ini' -o -name '.htaccess' \
            \) ! -name 'error_log' ! -name 'error_log.*' -print0 2>/dev/null \
            | xargs -0 -r grep -HnE --binary-files=without-match "$IOC_REGEX" 2>/dev/null \
            | sc_filter_legit_ioc_lines || true
    done < "$ROOTS_FILE"
}

scan_global_scv_wp_content_php() {
    local root wc
    while IFS= read -r root; do
        [[ -n "$root" ]] || continue
        wc="$root/wp-content"
        [[ -d "$wc" ]] || continue
        find "$wc" -type f -iname '*.php' -print0 2>/dev/null \
            | xargs -0 -r grep -liE --binary-files=without-match 'SCV:[[:space:]]*[0-9]+(\.[0-9]+){1,3}' 2>/dev/null || true
    done < "$ROOTS_FILE" | sort -u
}

SC_CAMPAIGN_ZIP_RE='(^|/)(ionic-scheduler-orb[^/]*|elite-module-cue|unity-manager-lite)/|(^|/)(ionic-scheduler-orb[^/]*|elite-module-cue|unity-manager-lite)\.php$'

# The 4.5.3 generation ships almost no literal campaign text: every builtin call
# goes through a `$GLOBALS['__scf_<rand>_<n>']` pointer built from an obfuscated
# string table, and the only stable strings left are the boot guard and the
# drop-in markers. Matching that shape keeps detection working when the campaign
# renames or drops its SCV marker, which is the one string it fully controls.
scan_global_obf_loaders() {
    local root wc
    while IFS= read -r root; do
        [[ -n "$root" ]] || continue
        wc="$root/wp-content"
        [[ -d "$wc" ]] || continue
        find "$wc" -type f -iname '*.php' -print0 2>/dev/null \
            | xargs -0 -r grep -lE --binary-files=without-match '__scf_[A-Za-z0-9_]{6,}|SC_CORE_BOOT_VER|sc_boot_ver|SC_COVER_HOOKS|SC_AUTO_PREPEND|SC_DP_(BEGIN|END):' 2>/dev/null || true
    done < "$ROOTS_FILE" | sort -u
}

scan_global_campaign_zip_ioc() {
    local root z listing
    while IFS= read -r root; do
        [[ -n "$root" && -d "$root" ]] || continue
        while IFS= read -r -d '' z; do
            [[ -f "$z" ]] || continue
            listing="$(unzip -Z1 "$z" 2>/dev/null || true)"
            [[ -n "$listing" ]] || continue
            if printf '%s\n' "$listing" | matches_stdin "$SC_CAMPAIGN_ZIP_RE"; then
                printf '%s\n' "$z"
            fi
        done < <(find "$root" -type f -iname '*.zip' -size -64M -print0 2>/dev/null || true)
    done < "$ROOTS_FILE" | sort -u
}

scan_global_malware_processes() {
    pgrep -afu "$CPUSER" '\.g_[[:xdigit:]]+\.php|/wp-content/plugins/ionic-scheduler-orb[^/]*/|/wp-content/mu-plugins/ionic-scheduler-orb\.php|/wp-content/(plugins|mu-plugins)/echo-compiler-plus([^/]*/|/)|/wp-content/(plugins|mu-plugins)/(elite-module-cue|unity-manager-lite)([^/]*/|/)|/wp-content/\.sc_[[:xdigit:]]+/\.gr_[[:xdigit:]]+\.php|/\.gr_[[:xdigit:]]{32}\.php' 2>/dev/null || true
}

guard_log() {
    printf '[%s] %s\n' "$(date '+%F %T')" "$*" >> "$REPORT_DIR/account-quarantine-guard.log" 2>/dev/null || true
    return 0
}

guard_preserve_evidence() {
    # Anything the background guard deletes is evidence too. v33 preserved only
    # SCV hits here, so artifacts removed by the guard vanished without a copy.
    local p="$1" label="${2:-guard-artifact}" key dst
    [[ -n "$p" && -e "$p" ]] || return 0
    mkdir -p "$REPORT_DIR/quarantine-files-global" 2>/dev/null || return 0
    key="$(printf '%s' "$p" | md5sum | awk '{print $1}' 2>/dev/null || true)"
    [[ -n "$key" ]] || key="nokey"
    dst="$REPORT_DIR/quarantine-files-global/${label}__${key}__${p##*/}"
    cp -a -- "$p" "$dst" 2>/dev/null || true
    printf '%s\t%s\t%s\n' "$label" "$p" "$dst" >> "$REPORT_DIR/quarantine-files-global.tsv" 2>/dev/null || true
    return 0
}

guard_remove_path() {
    local p="$1" label="$2"
    [[ -n "$p" && -e "$p" ]] || return 0
    guard_log "removing $label: $p"
    guard_preserve_evidence "$p" "$label"
    if [[ -d "$p" ]]; then
        chattr -R -ia -- "$p" 2>/dev/null || true
        rm -rf -- "$p" 2>/dev/null || true
    else
        chattr -ia -- "$p" 2>/dev/null || true
        rm -f -- "$p" 2>/dev/null || true
    fi
    return 0
}

# One complete guard sweep. This function must never fail: the guard is the only
# thing standing between the cleanup and re-seeding persistence, so every step is
# best-effort and HARD-mode process killing is interleaved between scanners so a
# slow account-wide sweep cannot open a multi-second window for account PHP.
account_guard_pass() {
    local d f
    [[ -f "$HARD_GUARD_FLAG" ]] && hard_guard_kill_account_php

    while IFS= read -r d; do guard_remove_path "$d" "respawned-ionic-scheduler-orb"; done < <(scan_global_ionic_paths)
    while IFS= read -r d; do guard_remove_path "$d" "respawned-echo-compiler-plus"; done < <(scan_global_echo_compiler_paths)
    [[ -f "$HARD_GUARD_FLAG" ]] && hard_guard_kill_account_php

    while IFS= read -r d; do guard_remove_path "$d" "respawned-campaign-plugin"; done < <(scan_global_elite_module_cue_paths)
    while IFS= read -r d; do guard_remove_path "$d" "respawned-elite-state-artifact"; done < <(scan_global_elite_state_artifacts)
    while IFS= read -r f; do guard_remove_path "$f" "respawned-extensionless-SC-payload"; done < <(scan_global_extensionless_payloads)
    [[ -f "$HARD_GUARD_FLAG" ]] && hard_guard_kill_account_php

    # An SCV marker of any generation, and the 4.5.3 obfuscated-loader shape, are
    # high-confidence campaign markers in any wp-content PHP file: removed on
    # sight, with evidence, at every stage including this guard.
    while IFS= read -r f; do guard_remove_path "$f" "respawned-SCV-PHP"; done < <(scan_global_scv_wp_content_php)
    while IFS= read -r f; do guard_remove_path "$f" "respawned-obfuscated-SC-loader"; done < <(scan_global_obf_loaders)
    while IFS= read -r f; do guard_remove_path "$f" "respawned-campaign-zip"; done < <(scan_global_campaign_zip_ioc)
    while IFS= read -r f; do guard_remove_path "$f" "respawned-malicious-wp-object-cache"; done < <(scan_global_wp_object_cache_ioc)
    [[ -f "$HARD_GUARD_FLAG" ]] && hard_guard_kill_account_php

    while IFS= read -r d; do guard_remove_path "$d" "respawned-SC-runtime-dir"; done < <(scan_global_sc_runtime_paths)
    while IFS= read -r f; do guard_remove_path "$f" "respawned-loose-gr-runner"; done < <(scan_global_loose_gr_runners)
    # State/lock artifacts are only removed as a >=3-artifact cluster.
    while IFS= read -r d; do guard_remove_path "$d" "respawned-SC-state-cluster"; done < <(scan_global_sc_state_clusters)
    [[ -f "$HARD_GUARD_FLAG" ]] && hard_guard_kill_account_php

    # wp-includes is immutable while cleanup runs, so recreation there should be
    # blocked; the worker owns any copy that predates the lock.
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        case "$f" in
            */wp-includes/*) ;;
            *) guard_remove_path "$f" "respawned-g-file" ;;
        esac
    done < <(scan_global_g_files)
    return 0
}

account_guard_loop() {
    # The guard is a long-lived background child of the coordinator. Run it with
    # errexit disabled and no ERR trap: in v33 a single unwritable log append was
    # enough to kill the guard silently and leave the account unprotected for the
    # rest of the run.
    set +e
    trap - ERR
    local guard_tick=12
    while :; do
        # Watchdog: never outlive the coordinator that owns the quarantine, or a
        # SIGKILLed run would leave a process deleting files under the account.
        kill -0 "$GUARD_PARENT_PID" 2>/dev/null || exit 0

        if [[ -f "$HARD_GUARD_FLAG" ]]; then
            # HARD mode: no account-owned PHP is allowed, with no exceptions.
            hard_guard_kill_account_php
        else
            pids="$(pgrep -u "$CPUSER" -f '\.g_[[:xdigit:]]+\.php|/wp-content/plugins/ionic-scheduler-orb[^/]*/|/wp-content/mu-plugins/ionic-scheduler-orb\.php|/wp-content/(plugins|mu-plugins)/echo-compiler-plus([^/]*/|/)|/wp-content/(plugins|mu-plugins)/(elite-module-cue|unity-manager-lite)([^/]*/|/)|/wp-content/\.sc_[[:xdigit:]]+/\.gr_[[:xdigit:]]+\.php|/\.gr_[[:xdigit:]]{32}\.php' 2>/dev/null)"
            if [[ -n "$pids" ]]; then
                guard_log "respawned malware PIDs: $(echo "$pids" | tr '\n' ' ')"
                ps -o user,pid,ppid,lstart,etime,args -p "$(echo "$pids" | paste -sd, -)" \
                    >> "$REPORT_DIR/account-quarantine-guard.log" 2>/dev/null
                kill -9 $pids 2>/dev/null
            fi
        fi

        # During controlled global verification the guard is process-only. The
        # coordinator toggles this flag file so the background guard cannot
        # compete with the deterministic account-wide scans for filesystem I/O.
        if [[ -f "$REPORT_DIR/account-guard-process-only.flag" ]]; then
            sleep 0.25
            continue
        fi

        # Process killing stays frequent; the expensive account-wide filesystem
        # sweep runs roughly every 3 seconds instead of every 0.25 seconds.
        guard_tick=$((guard_tick+1))
        if (( guard_tick >= 12 )); then
            guard_tick=0
            account_guard_pass
        fi
        sleep 0.25
    done
}

# Re-scan the WHOLE account after each site, not only after the last one.
#
# Sites under one account share a user, a PHP pool and a filesystem, so site B
# can re-seed site A while A is already finished. Scanning once at the end hides
# that: either the guard removed the respawn (and the final scan is clean, with
# no record that it happened) or it lands after the report is written. The
# checkpoint records what came back, hands it to the guard, and re-checks.
CHECKPOINT_DIRTY=0
run_account_checkpoint() {
    local safe="$1" found=0 after=0 f
    local -a scans=(
        "g-files:scan_global_g_files"
        "ionic:scan_global_ionic_paths"
        "echo-compiler:scan_global_echo_compiler_paths"
        "elite-module-cue:scan_global_elite_module_cue_paths"
        "sc-runtime:scan_global_sc_runtime_paths"
        "loose-gr:scan_global_loose_gr_runners"
        "wp-object-cache-ioc:scan_global_wp_object_cache_ioc"
        "campaign-zip:scan_global_campaign_zip_ioc"
    )
    local entry name fn

    # The checkpoint crawls the whole account itself and hands what it finds to
    # account_guard_pass, so the guard's own filesystem sweep during this window
    # would re-read the same inodes for nothing. Process killing continues.
    : > "$REPORT_DIR/account-guard-process-only.flag"

    # SCV:4.x is the primary campaign marker, so it gets its own named report.
    scan_global_scv_wp_content_php > "$REPORT_DIR/checkpoint-${safe}-scv-php.txt" 2>/dev/null || true
    if [[ -s "$REPORT_DIR/checkpoint-${safe}-scv-php.txt" ]]; then found=1; fi
    scan_global_obf_loaders > "$REPORT_DIR/checkpoint-${safe}-obf-loaders.txt" 2>/dev/null || true
    if [[ -s "$REPORT_DIR/checkpoint-${safe}-obf-loaders.txt" ]]; then found=1; fi
    for entry in "${scans[@]}"; do
        name="${entry%%:*}"; fn="${entry#*:}"
        "$fn" > "$REPORT_DIR/checkpoint-${safe}-${name}.txt" 2>/dev/null || true
        [[ -s "$REPORT_DIR/checkpoint-${safe}-${name}.txt" ]] && found=1
    done

    if [[ "$found" -eq 0 ]]; then
        rm -f -- "$REPORT_DIR/account-guard-process-only.flag"
        status CLEAN "Post-site account checkpoint clean: $safe"
        return 0
    fi

    status FOUND "Campaign artifacts present account-wide after finishing $safe; handing them to the guard"
    account_guard_pass

    scan_global_scv_wp_content_php > "$REPORT_DIR/checkpoint-${safe}-scv-php-after.txt" 2>/dev/null || true
    if [[ -s "$REPORT_DIR/checkpoint-${safe}-scv-php-after.txt" ]]; then after=1; fi
    for entry in "${scans[@]}"; do
        name="${entry%%:*}"; fn="${entry#*:}"
        "$fn" > "$REPORT_DIR/checkpoint-${safe}-${name}-after.txt" 2>/dev/null || true
        [[ -s "$REPORT_DIR/checkpoint-${safe}-${name}-after.txt" ]] && after=1
    done

    rm -f -- "$REPORT_DIR/account-guard-process-only.flag"
    if [[ "$after" -eq 1 ]]; then
        CHECKPOINT_DIRTY=1
        status REVIEW "Account checkpoint after $safe still finds campaign artifacts; see checkpoint-${safe}-*-after.txt"
        return 1
    fi
    status FIXED "Account checkpoint after $safe: respawned artifacts removed by the guard"
    return 0
}

start_guard() {
    : > "$REPORT_DIR/account-quarantine-guard.log"
    GUARD_PARENT_PID=$$
    account_guard_loop &
    GUARD_PID=$!
    status FIXED "Account-wide continuous malware guard started (PID $GUARD_PID)"
}

stop_guard() {
    [[ -n "${GUARD_PID:-}" ]] || return 0
    if kill -0 "$GUARD_PID" 2>/dev/null; then
        kill "$GUARD_PID" 2>/dev/null || true
        wait "$GUARD_PID" 2>/dev/null || true
    fi
    GUARD_PID=""
    status FIXED "Account-wide malware guard stopped"
}

unlock_all_wp_includes() {
    local root flags failed=0
    [[ -s "${ROOTS_FILE:-/nonexistent}" ]] || return 0
    while IFS= read -r root; do
        [[ -n "$root" && -d "$root/wp-includes" ]] || continue
        flags="$(attr_flags "$root/wp-includes")"
        # Clear unconditionally. lsattr can be missing, unsupported or silent on
        # some hosting filesystems, and trusting its output would silently skip
        # the one step this script is never allowed to skip. chattr -ia on an
        # already-clear directory is a no-op.
        if chattr -ia -- "$root/wp-includes" 2>/dev/null; then
            if [[ "$flags" == *i* || "$flags" == *a* ]]; then
                status FIXED "Cleared immutable/append-only flags from wp-includes: $root"
            else
                status CLEAN "wp-includes updateable (-i/-a clear): $root"
            fi
            continue
        fi
        # chattr itself may be unsupported here; only a flag that is still set
        # after the attempt counts as a failure.
        flags="$(attr_flags "$root/wp-includes")"
        if [[ "$flags" == *i* || "$flags" == *a* ]]; then
            status FAILED "Could not clear immutable/append-only flags from wp-includes: $root"
            failed=1
        else
            status CLEAN "wp-includes updateable (-i/-a clear): $root"
        fi
    done < "$ROOTS_FILE"
    [[ "$failed" -eq 0 ]]
}

extract_worker() {
    # The embedded worker is read back out of this script, so $0 must be the real
    # file. Refuse rather than run a truncated worker.
    local self="$0"
    [[ -f "$self" && -r "$self" ]] || fatal "Cannot read own source '$self'; run this script from a file, not a pipe."
    grep -q '^__SC_SITE_WORKER_BELOW__$' "$self" || fatal "Embedded site worker marker missing from '$self'."
    WORKER_FILE="$(mktemp "${SC_REPORT_ROOT}/wp-sc-site-worker-v43-offline.XXXXXX" 2>/dev/null || mktemp /tmp/wp-sc-site-worker-v43-offline.XXXXXX)"
    awk 'f{print} /^__SC_SITE_WORKER_BELOW__$/ {f=1;next}' "$self" > "$WORKER_FILE"
    [[ -s "$WORKER_FILE" ]] || fatal "Extracted site worker is empty."
    chmod 700 "$WORKER_FILE"
}

cleanup_temp() {
    local rc=$?
    [[ -n "${WORKER_FILE:-}" && -f "$WORKER_FILE" ]] && rm -f "$WORKER_FILE" || true
    # Keep HARD mode active until the guard itself is stopped. This avoids a
    # last-moment window where unknown PHP could start during exit cleanup.
    stop_guard >/dev/null 2>&1 || true
    rm -f -- "${HARD_GUARD_FLAG:-}" 2>/dev/null || true

    # HARD RULE: wp-includes immutable/append-only flags inserted or inherited
    # during this cleanup must never survive the account cleaner exit. This keeps
    # WordPress core updates functional after CLEAN, REVIEW, FAILED, INT or TERM.
    if [[ -s "${ROOTS_FILE:-/nonexistent}" ]]; then
        unlock_all_wp_includes || status FAILED "Exit cleanup could not clear -i/-a from one or more wp-includes directories" || true
    fi

    # HARD RULE: a 503 inserted by this cleaner must never survive script exit.
    # This runs on success, review/failure, Ctrl+C, TERM and HUP.
    if [[ "${ACCOUNT_HTACCESS_RESTORED:-0}" -eq 0 && -s "${HTMETA:-/nonexistent}" ]]; then
        printf '\n' >&2
        status REVIEW "Exit cleanup: removing temporary HTTP 503 quarantine before returning control" || true
        restore_all_htaccess || status FAILED "Exit cleanup could not restore one or more .htaccess files; manual restoration required from $HTMETA" || true
    fi
    return "$rc"
}
trap cleanup_temp EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# Print exact per-site/account review reasons in the final terminal output.
# The detailed worker reports remain the source of truth; this function surfaces
# the actionable lines so the operator does not have to hunt through directories.
REVIEW_DETAILS_FILE="$REPORT_DIR/review-details.txt"
: > "$REVIEW_DETAILS_FILE"

review_detail_line() {
    local text="$*"
    printf '        %s\n' "$text" | tee -a "$LOG_FILE" "$REVIEW_DETAILS_FILE"
}

review_detail_file() {
    local label="$1" file="$2" limit="${3:-20}"
    [[ -s "$file" ]] || return 0
    local count
    count="$(awk 'END{print NR+0}' "$file")"
    status REVIEW "$label: $count item(s)"
    awk -v n="$limit" 'NR<=n {print "        " $0}' "$file" | tee -a "$LOG_FILE" "$REVIEW_DETAILS_FILE"
    if [[ "$count" -gt "$limit" ]]; then
        review_detail_line "... $((count-limit)) more item(s); full list: $file"
    fi
    return 0
}

worker_report_dir_for_site() {
    local root="$1" id tlog
    id="$(site_id "$root")"
    tlog="$REPORT_DIR/sites/${id}.terminal.log"
    [[ -f "$tlog" ]] || return 1
    grep -m1 'Report directory:' "$tlog" 2>/dev/null | sed -E 's/^.*Report directory:[[:space:]]*//' | tail -n1
}

print_site_review_reason() {
    local result="$1" rc="$2" root="$3" wr='' id tlog
    id="$(site_id "$root")"
    tlog="$REPORT_DIR/sites/${id}.terminal.log"
    wr="$(worker_report_dir_for_site "$root" 2>/dev/null || true)"

    status REVIEW "WordPress requiring attention: $root"
    review_detail_line "Worker result: $result (exit code $rc)"

    if [[ -z "$wr" || ! -d "$wr" ]]; then
        review_detail_line "Worker report directory could not be resolved. Terminal log: $tlog"
        if [[ -s "$tlog" ]]; then
            review_detail_line "Last worker messages:"
            tail -n 12 "$tlog" | sed 's/^/        /' | tee -a "$LOG_FILE" "$REVIEW_DETAILS_FILE"
        fi
        return 0
    fi

    review_detail_line "Worker report: $wr"

    case "$result" in
        REVIEW_FILESYSTEM)
            review_detail_line "Reason: high-confidence filesystem persistence remains after automatic cleanup."
            review_detail_file ".g_* malware files" "$wr/fs-g-files.txt"
            review_detail_file ".sc_/.gr_ runtime paths" "$wr/fs-sc-runtime.txt"
            review_detail_file "Clustered SC state/lock artifacts" "$wr/fs-sc-state.txt"
            review_detail_file "SC marker/injection lines" "$wr/fs-ioc-lines.txt"
            review_detail_file "SCV-marked PHP files under wp-content" "$wr/fs-scv-php.txt"
            review_detail_file "Obfuscated SC loader PHP files under wp-content" "$wr/fs-obf-loaders.txt"
            review_detail_file "Running .g_* malware processes" "$wr/fs-g-processes.txt"
            review_detail_file "Malicious drop-in markers" "$wr/fs-dropin-markers.txt"
            review_detail_file "Derived SC artifacts" "$wr/fs-derived-artifacts.txt"
            review_detail_file "ionic-scheduler-orb paths still present" "$wr/ionic-plugin-remaining.txt"
            review_detail_file "Theme functions.php requiring manual cleanup" "$wr/theme-functions-review.txt"
            # auto_prepend is a reason for the filesystem gate only when it points
            # at a campaign-style loader; still show the exact remaining directive.
            review_detail_file "auto_prepend_file directives" "$wr/fs-auto-prepend.txt"
            ;;
        REVIEW_VERIFICATION)
            review_detail_line "Reason: final integrity/persistence verification failed."
            review_detail_file "Remaining .g_* files after cleanup" "$wr/fs-g-files-after.txt"
            review_detail_file "Remaining .sc_/.gr_ runtime paths" "$wr/fs-sc-runtime-after.txt"
            review_detail_file "Remaining clustered SC state artifacts" "$wr/fs-sc-state-after.txt"
            review_detail_file "Remaining SC filesystem markers after cleanup" "$wr/fs-ioc-lines-after.txt"
            review_detail_file "Remaining SCV-marked PHP files under wp-content" "$wr/fs-scv-php-after.txt"
            review_detail_file "Remaining obfuscated SC loader PHP files" "$wr/fs-obf-loaders-after.txt"
            review_detail_file "Remaining malware processes after cleanup" "$wr/fs-g-processes-after.txt"
            review_detail_file "Remaining ionic-scheduler-orb paths" "$wr/ionic-plugin-remaining.txt"
            review_detail_file "SC database rows remaining after cleanup" "$wr/db-sc-options-after.tsv"
            if [[ -s "$wr/core-checksums.txt" ]] && grep -Eqi 'error|warning|does not verify|checksum|extra file|modified' "$wr/core-checksums.txt"; then
                review_detail_file "WordPress core checksum output" "$wr/core-checksums.txt" 30
            fi
            ;;
        REVIEW_DB_SKIPPED)
            review_detail_line "Reason: filesystem cleanup completed, but the direct DB phase could not run for this site."
            review_detail_line "The account-wide filesystem verification and release were NOT blocked by this."
            review_detail_file "Direct database diagnostic" "$wr/db-connectivity-error.txt" 10
            review_detail_file "Skip record"                "$wr/db-phase-skipped.txt" 10
            review_detail_file "Tables that could not be read" "$wr/db-table-validation-errors.txt" 10
            ;;
        REINFECTION)
            review_detail_line "Reason: reinfection was detected after the worker cleanup/release test."
            review_detail_file "Reinfection evidence" "$wr/reinfection.txt" 40
            ;;
        FAILED_*)
            review_detail_line "Reason: site worker terminated unexpectedly."
            if [[ -s "$tlog" ]]; then
                grep -E 'ERROR:|FAILED|command failed|exit code' "$tlog" | tail -n 20 | sed 's/^/        /' | tee -a "$LOG_FILE" "$REVIEW_DETAILS_FILE" || true
                review_detail_line "Terminal log: $tlog"
            fi
            ;;
        *)
            review_detail_line "Reason: $result"
            ;;
    esac

    # Surface manual-review items that are useful context for a failing site.
    if [[ -f "$wr/db-suspicious-users-after.tsv" ]]; then
        review_detail_file "Suspicious WordPress users remaining after cleanup" "$wr/db-suspicious-users-after.tsv"
    else
        review_detail_file "Suspicious WordPress users" "$wr/db-suspicious-users.tsv"
    fi
    review_detail_file "Campaign rogue admins that could not be auto-deleted" "$wr/db-auto-rogue-admins-failed.tsv"
    review_detail_file "Hex-named DB options requiring review" "$wr/db-hex-options.tsv"
    review_detail_file "Path-derived DB option requiring review" "$wr/db-derived-option.tsv"
    review_detail_file "Executable files under uploads" "$wr/fs-uploads-php.txt"
    review_detail_file "PHP files under wp-content/cache" "$wr/fs-cache-php.txt"
    review_detail_file "Other large MU-plugin PHP files" "$wr/fs-mu-plugins-over-5k.tsv"
    return 0
}

print_account_review_details() {
    section "REVIEW DETAILS"
    local result rc root any=0
    while IFS=$'\t' read -r result rc root; do
        [[ -n "$root" ]] || continue
        [[ "$result" == "CLEAN" ]] && continue
        any=1
        print_site_review_reason "$result" "$rc" "$root"
        printf '\n' | tee -a "$LOG_FILE" "$REVIEW_DETAILS_FILE"
    done < "$RESULTS_FILE"

    if [[ -s "$REPORT_DIR/global-g-files-after.txt" ]]; then
        any=1
        status REVIEW "Account-wide .g_* files remain"
        review_detail_file "Account-wide .g_* paths" "$REPORT_DIR/global-g-files-after.txt" 50
    fi
    if [[ -s "$REPORT_DIR/global-ionic-after.txt" ]]; then
        any=1
        status REVIEW "Account-wide ionic-scheduler-orb paths remain"
        review_detail_file "Account-wide ionic-scheduler-orb paths" "$REPORT_DIR/global-ionic-after.txt" 50
    fi
    if [[ -s "$REPORT_DIR/global-sc-ioc-after.txt" ]]; then
        any=1
        status REVIEW "Account-wide SC filesystem markers remain"
        review_detail_file "Account-wide SC filesystem markers" "$REPORT_DIR/global-sc-ioc-after.txt" 50
    fi
    if [[ -s "$REPORT_DIR/global-malware-processes-after.txt" ]]; then
        any=1
        status REVIEW "Account-wide malware processes remain"
        review_detail_file "Account-wide malware processes" "$REPORT_DIR/global-malware-processes-after.txt" 50
    fi

    if [[ "$any" -eq 0 ]]; then
        status CLEAN "No concrete review reason was recorded."
    else
        status REVIEW "Consolidated review file: $REVIEW_DETAILS_FILE"
    fi
    return 0
}

section "ACCOUNT QUARANTINE"
lock_all_wp_includes
quarantine_all_sites
pause_account_cron
status CLEAN "Checking and terminating existing PHP processes for $CPUSER"
kill_account_php
: > "$HARD_GUARD_FLAG"
status FIXED "HARD PHP quarantine enabled: all account-owned PHP/lsphp/php-fpm processes will be killed with no worker exemption"
status CLEAN "Starting continuous account malware guard"
start_guard
status CLEAN "Preparing per-site cleanup worker"
extract_worker
status CLEAN "Account quarantine initialization complete"

section "ACCOUNT-WIDE HIGH-CONFIDENCE PRE-CLEAN"
PREFLIGHT_OK=1
: > "$REPORT_DIR/preflight-results.tsv"
while IFS= read -r root; do
    [[ -n "$root" ]] || continue
    id="$(site_id "$root")"
    status FOUND "Pre-cleaning high-confidence filesystem persistence: $root"
    set +e
    SC_ACCOUNT_MODE=1 SC_PREFLIGHT_ONLY=1 NO_COLOR="${NO_COLOR:-}" \
        SC_EVIDENCE_OUT="$REPORT_DIR/sites/${id}.evidence" \
        "$WORKER_FILE" "$CPUSER" "$root" 2>&1 | tee "$REPORT_DIR/sites/${id}.preflight.terminal.log"
    rc=${PIPESTATUS[0]}
    set -e
    printf '%s\t%s\n' "$rc" "$root" >> "$REPORT_DIR/preflight-results.tsv"
    if [[ "$rc" -ne 0 ]]; then
        PREFLIGHT_OK=0
        status REVIEW "High-confidence filesystem persistence could not be fully cleared during preflight: $root"
    else
        status CLEAN "Preflight high-confidence filesystem gate clear: $root"
    fi
done < "$ROOTS_FILE"

# Per-site high-confidence cleanup is complete. Keep the background guard alive
# for process killing only while the coordinator performs deterministic global
# verification. This avoids two concurrent account-wide filesystem crawls.
: > "$REPORT_DIR/account-guard-process-only.flag"
PATH_SCAN_TIMEOUT_FILE="$REPORT_DIR/preflight-path-timeouts.txt"
: > "$PATH_SCAN_TIMEOUT_FILE"
status INFO "Global preflight guard mode: HARD PHP process-only (all account PHP blocked)"

status INFO "Global preflight 1/15: scanning .g_* files"
scan_global_g_files > "$REPORT_DIR/preflight-global-g.txt"
status INFO "Global preflight 2/15: scanning ionic-scheduler-orb paths"
scan_global_ionic_paths > "$REPORT_DIR/preflight-global-ionic.txt"
status INFO "Global preflight 3/15: scanning echo-compiler-plus paths"
scan_global_echo_compiler_paths 1 > "$REPORT_DIR/preflight-global-echo-compiler.txt"
status INFO "Global preflight 4/15: scanning elite-module-cue/unity-manager-lite paths"
scan_global_elite_module_cue_paths > "$REPORT_DIR/preflight-global-elite-module-cue.txt"
status INFO "Global preflight 5/15: scanning elite-module-cue state artifacts"
scan_global_elite_state_artifacts > "$REPORT_DIR/preflight-global-elite-state.txt"
status INFO "Global preflight 6/15: scanning extensionless SC payloads"
scan_global_extensionless_payloads > "$REPORT_DIR/preflight-global-extensionless.txt"
status INFO "Global preflight 7/15: scanning .sc_ runtime paths"
scan_global_sc_runtime_paths > "$REPORT_DIR/preflight-global-sc-runtime.txt"
status INFO "Global preflight 8/15: scanning loose .gr_<32hex>.php runners"
scan_global_loose_gr_runners > "$REPORT_DIR/preflight-global-loose-gr.txt"
status INFO "Global preflight 9/15: scanning SC state clusters"
scan_global_sc_state_clusters > "$REPORT_DIR/preflight-global-sc-state.txt"
status INFO "Global preflight 10/15: scanning confirmed .wp-object-cache IOC files"
scan_global_wp_object_cache_ioc > "$REPORT_DIR/preflight-global-wp-object-cache-ioc.txt"
status INFO "Global preflight 11/15: scanning every wp-content PHP file for SCV markers"
scan_global_scv_wp_content_php > "$REPORT_DIR/preflight-global-scv-php.txt"
status INFO "Global preflight 12/15: scanning every wp-content PHP file for obfuscated SC loaders"
scan_global_obf_loaders > "$REPORT_DIR/preflight-global-obf-loaders.txt"
status INFO "Global preflight 13/15: scanning campaign IOC text"
scan_global_sc_ioc_lines > "$REPORT_DIR/preflight-global-sc-ioc.txt"
status INFO "Global preflight 14/15: scanning campaign payload ZIPs"
scan_global_campaign_zip_ioc > "$REPORT_DIR/preflight-global-campaign-zips.txt"
status INFO "Global preflight 15/15: scanning malware processes"
scan_global_malware_processes > "$REPORT_DIR/preflight-global-processes.txt"
[[ -s "$REPORT_DIR/preflight-global-g.txt" ]] && PREFLIGHT_OK=0
[[ -s "$REPORT_DIR/preflight-global-ionic.txt" ]] && PREFLIGHT_OK=0
[[ -s "$REPORT_DIR/preflight-global-echo-compiler.txt" ]] && PREFLIGHT_OK=0
[[ -s "$REPORT_DIR/preflight-global-elite-module-cue.txt" ]] && PREFLIGHT_OK=0
[[ -s "$REPORT_DIR/preflight-global-elite-state.txt" ]] && PREFLIGHT_OK=0
[[ -s "$REPORT_DIR/preflight-global-extensionless.txt" ]] && PREFLIGHT_OK=0
[[ -s "$REPORT_DIR/preflight-global-sc-runtime.txt" ]] && PREFLIGHT_OK=0
[[ -s "$REPORT_DIR/preflight-global-loose-gr.txt" ]] && PREFLIGHT_OK=0
[[ -s "$REPORT_DIR/preflight-global-sc-state.txt" ]] && PREFLIGHT_OK=0
[[ -s "$REPORT_DIR/preflight-global-wp-object-cache-ioc.txt" ]] && PREFLIGHT_OK=0
[[ -s "$REPORT_DIR/preflight-global-scv-php.txt" ]] && PREFLIGHT_OK=0
[[ -s "$REPORT_DIR/preflight-global-obf-loaders.txt" ]] && PREFLIGHT_OK=0
[[ -s "$REPORT_DIR/preflight-global-sc-ioc.txt" ]] && PREFLIGHT_OK=0
[[ -s "$REPORT_DIR/preflight-global-campaign-zips.txt" ]] && PREFLIGHT_OK=0
[[ -s "$REPORT_DIR/preflight-global-processes.txt" ]] && PREFLIGHT_OK=0
[[ -s "$PATH_SCAN_TIMEOUT_FILE" ]] && PREFLIGHT_OK=0

if [[ "$PREFLIGHT_OK" -ne 1 ]]; then
    section "ACCOUNT-WIDE OFFLINE RE-CLEAN PASS 2"
    status REVIEW "First global preflight still found high-confidence persistence; running one automatic offline re-clean pass before refusing the full cleanup phase."
    : > "$REPORT_DIR/preflight-results-pass2.tsv"
    while IFS= read -r root; do
        [[ -n "$root" ]] || continue
        id="$(site_id "$root")"
        status FOUND "Second-pass pre-clean: $root"
        set +e
        SC_ACCOUNT_MODE=1 SC_PREFLIGHT_ONLY=1 NO_COLOR="${NO_COLOR:-}" \
            SC_EVIDENCE_OUT="$REPORT_DIR/sites/${id}.evidence" \
            "$WORKER_FILE" "$CPUSER" "$root" 2>&1 | tee "$REPORT_DIR/sites/${id}.preflight-pass2.terminal.log"
        rc=${PIPESTATUS[0]}
        set -e
        printf '%s\t%s\n' "$rc" "$root" >> "$REPORT_DIR/preflight-results-pass2.tsv"
    done < "$ROOTS_FILE"

    PREFLIGHT_OK=1
    : > "$PATH_SCAN_TIMEOUT_FILE"
    status INFO "Second global preflight 1/15: scanning .g_* files"
    scan_global_g_files > "$REPORT_DIR/preflight2-global-g.txt"
    status INFO "Second global preflight 2/15: scanning ionic-scheduler-orb paths"
    scan_global_ionic_paths > "$REPORT_DIR/preflight2-global-ionic.txt"
    status INFO "Second global preflight 3/15: scanning echo-compiler-plus paths"
    scan_global_echo_compiler_paths 1 > "$REPORT_DIR/preflight2-global-echo-compiler.txt"
    status INFO "Second global preflight 4/15: scanning elite-module-cue/unity-manager-lite paths"
    scan_global_elite_module_cue_paths > "$REPORT_DIR/preflight2-global-elite-module-cue.txt"
    status INFO "Second global preflight 5/15: scanning elite-module-cue state artifacts"
    scan_global_elite_state_artifacts > "$REPORT_DIR/preflight2-global-elite-state.txt"
    status INFO "Second global preflight 6/15: scanning extensionless SC payloads"
    scan_global_extensionless_payloads > "$REPORT_DIR/preflight2-global-extensionless.txt"
    status INFO "Second global preflight 7/15: scanning .sc_ runtime paths"
    scan_global_sc_runtime_paths > "$REPORT_DIR/preflight2-global-sc-runtime.txt"
    status INFO "Second global preflight 8/15: scanning loose .gr_<32hex>.php runners"
    scan_global_loose_gr_runners > "$REPORT_DIR/preflight2-global-loose-gr.txt"
    status INFO "Second global preflight 9/15: scanning SC state clusters"
    scan_global_sc_state_clusters > "$REPORT_DIR/preflight2-global-sc-state.txt"
    status INFO "Second global preflight 10/15: scanning confirmed .wp-object-cache IOC files"
    scan_global_wp_object_cache_ioc > "$REPORT_DIR/preflight2-global-wp-object-cache-ioc.txt"
    status INFO "Second global preflight 11/15: scanning every wp-content PHP file for SCV markers"
    scan_global_scv_wp_content_php > "$REPORT_DIR/preflight2-global-scv-php.txt"
    status INFO "Second global preflight 12/15: scanning every wp-content PHP file for obfuscated SC loaders"
    scan_global_obf_loaders > "$REPORT_DIR/preflight2-global-obf-loaders.txt"
    status INFO "Second global preflight 13/15: scanning campaign IOC text"
    scan_global_sc_ioc_lines > "$REPORT_DIR/preflight2-global-sc-ioc.txt"
    status INFO "Second global preflight 14/15: scanning campaign payload ZIPs"
    scan_global_campaign_zip_ioc > "$REPORT_DIR/preflight2-global-campaign-zips.txt"
    status INFO "Second global preflight 15/15: scanning malware processes"
    scan_global_malware_processes > "$REPORT_DIR/preflight2-global-processes.txt"
    [[ -s "$REPORT_DIR/preflight2-global-g.txt" ]] && PREFLIGHT_OK=0
    [[ -s "$REPORT_DIR/preflight2-global-ionic.txt" ]] && PREFLIGHT_OK=0
    [[ -s "$REPORT_DIR/preflight2-global-echo-compiler.txt" ]] && PREFLIGHT_OK=0
    [[ -s "$REPORT_DIR/preflight2-global-elite-module-cue.txt" ]] && PREFLIGHT_OK=0
    [[ -s "$REPORT_DIR/preflight2-global-elite-state.txt" ]] && PREFLIGHT_OK=0
    [[ -s "$REPORT_DIR/preflight2-global-extensionless.txt" ]] && PREFLIGHT_OK=0
    [[ -s "$REPORT_DIR/preflight2-global-sc-runtime.txt" ]] && PREFLIGHT_OK=0
    [[ -s "$REPORT_DIR/preflight2-global-loose-gr.txt" ]] && PREFLIGHT_OK=0
    [[ -s "$REPORT_DIR/preflight2-global-sc-state.txt" ]] && PREFLIGHT_OK=0
    [[ -s "$REPORT_DIR/preflight2-global-wp-object-cache-ioc.txt" ]] && PREFLIGHT_OK=0
    [[ -s "$REPORT_DIR/preflight2-global-scv-php.txt" ]] && PREFLIGHT_OK=0
    [[ -s "$REPORT_DIR/preflight2-global-obf-loaders.txt" ]] && PREFLIGHT_OK=0
    [[ -s "$REPORT_DIR/preflight2-global-sc-ioc.txt" ]] && PREFLIGHT_OK=0
    [[ -s "$REPORT_DIR/preflight2-global-campaign-zips.txt" ]] && PREFLIGHT_OK=0
    [[ -s "$REPORT_DIR/preflight2-global-processes.txt" ]] && PREFLIGHT_OK=0
    [[ -s "$PATH_SCAN_TIMEOUT_FILE" ]] && PREFLIGHT_OK=0
fi

# Re-enable filesystem guard only after both deterministic global passes finish.
rm -f -- "$REPORT_DIR/account-guard-process-only.flag"

if [[ "$PREFLIGHT_OK" -ne 1 ]]; then
    section "FINAL STATUS"
    status REVIEW "ACCOUNT PRE-CLEAN FAILED AFTER TWO PASSES - FULL CLEANUP PHASE NOT ALLOWED"
    status REVIEW "Known high-confidence filesystem persistence remains somewhere in the account after automatic re-clean."
    status FIXED "Temporary wp-includes locks will be cleared before script exit."
    status CLEAN "User crontab remains paused."
    status REVIEW "Inspect preflight-results*.tsv, preflight-global-*.txt, preflight2-global-*.txt and preflight-path-timeouts.txt under $REPORT_DIR"
    stop_guard
    # Deliberately do NOT force ACCOUNT_HTACCESS_RESTORED here: if the restore was
    # only partial the EXIT trap must be allowed to try again.
    restore_all_htaccess || status FAILED "Could not restore one or more .htaccess files; see $HTMETA"
    print_manual_restore_hints
    exit 10
fi
status CLEAN "Account-wide high-confidence filesystem gate is clear; entering offline direct-DB phase while HARD PHP quarantine remains active"

section "PER-SITE CLEANUP"
ALL_CLEAN=1
DB_REVIEW=0
while IFS= read -r root; do
    [[ -n "$root" ]] || continue
    id="$(site_id "$root")"
    printf '\n'
    status FOUND "Processing WordPress: $root"
    PREVIOUS_CAMPAIGN_EVIDENCE=0
    # Authoritative signal: the preflight worker records every high-confidence
    # campaign finding in a machine-readable file. v33 relied only on grepping
    # human-readable log text, and its SCV pattern ('SCV:4\.[0-9]+') never matched
    # the literal string the worker prints ('SCV:4.x'), so SCV-only sites were
    # never marked campaign-proven.
    if [[ -s "$REPORT_DIR/sites/${id}.evidence" ]]; then
        PREVIOUS_CAMPAIGN_EVIDENCE=1
    fi
    if [[ "$PREVIOUS_CAMPAIGN_EVIDENCE" -eq 0 ]] && grep -Eqi 'SC hidden runtime directory with \.gr_ runner|Loose SC \.gr runner with --sc-cli/--sc-succ|Campaign-named PHP file contains SC runtime/IOC evidence|Confirmed SC IOC inside \.wp-object-cache artifact|Confirmed malicious echo-compiler-plus path|Confirmed malicious campaign plugin persistence|Confirmed elite-module-cue state artifact|Confirmed extensionless SC PHP payload|Confirmed SCV campaign marker in wp-content PHP|Removed [0-9]+ SCV-marked PHP file|Confirmed obfuscated SC loader in wp-content PHP|Removed [0-9]+ obfuscated SC loader file|SC campaign generation detected|Malicious( \.htaccess)? auto_prepend_file persistence detected|Campaign ZIP contains ionic-scheduler-orb/elite-module-cue/unity-manager-lite payload|Running ionic-scheduler-orb process|ionic-scheduler-orb detected in [0-9]+ confirmed malicious path|Campaign ZIP contains ionic-scheduler-orb|SC_TH marker\(s\) detected|Markerless echo-compiler-plus downloader detected|Removed [0-9]+ marker-confirmed malicious WordPress drop-in|Removed [0-9]+ campaign \.g_' \
        "$REPORT_DIR/sites/${id}.preflight.terminal.log" "$REPORT_DIR/sites/${id}.preflight-pass2.terminal.log" 2>/dev/null; then
        PREVIOUS_CAMPAIGN_EVIDENCE=1
    fi
    set +e
    SC_ACCOUNT_MODE=1 \
        SC_PREVIOUS_CAMPAIGN_EVIDENCE="$PREVIOUS_CAMPAIGN_EVIDENCE" \
        SC_EVIDENCE_OUT="$REPORT_DIR/sites/${id}.evidence" \
        NO_COLOR="${NO_COLOR:-}" \
        "$WORKER_FILE" "$CPUSER" "$root" 2>&1 | tee "$REPORT_DIR/sites/${id}.terminal.log"
    rc=${PIPESTATUS[0]}
    set -e
    hard_guard_kill_account_php
    safe="$id"
    run_account_checkpoint "$safe" || true
    case "$rc" in
        0)
            status CLEAN "Site SC IOC verification clean: $root"
            result="CLEAN"
            ;;
        10)
            status REVIEW "Site still has filesystem persistence/review items: $root"
            result="REVIEW_FILESYSTEM"
            ALL_CLEAN=0
            ;;
        20)
            status REVIEW "Site failed integrity/final verification: $root"
            result="REVIEW_VERIFICATION"
            ALL_CLEAN=0
            ;;
        30)
            status FAILED "Site reinfected during worker release test: $root"
            result="REINFECTION"
            ALL_CLEAN=0
            ;;
        40)
            status REVIEW "Site filesystem cleaned, but direct DB phase was skipped: $root"
            result="REVIEW_DB_SKIPPED"
            DB_REVIEW=1
            ;;
        *)
            status FAILED "Site worker failed with exit code $rc: $root"
            result="FAILED_${rc}"
            ALL_CLEAN=0
            ;;
    esac
    printf '%s\t%s\t%s\n' "$result" "$rc" "$root" >> "$RESULTS_FILE"
done < "$ROOTS_FILE"

section "ACCOUNT-WIDE VERIFICATION"
scan_global_g_files > "$REPORT_DIR/global-g-files-after.txt"
scan_global_ionic_paths > "$REPORT_DIR/global-ionic-after.txt"
scan_global_echo_compiler_paths > "$REPORT_DIR/global-echo-compiler-after.txt"
scan_global_elite_module_cue_paths > "$REPORT_DIR/global-elite-module-cue-after.txt"
scan_global_elite_state_artifacts > "$REPORT_DIR/global-elite-state-after.txt"
scan_global_extensionless_payloads > "$REPORT_DIR/global-extensionless-after.txt"
scan_global_sc_runtime_paths > "$REPORT_DIR/global-sc-runtime-after.txt"
scan_global_loose_gr_runners > "$REPORT_DIR/global-loose-gr-after.txt"
scan_global_sc_state_clusters > "$REPORT_DIR/global-sc-state-after.txt"
scan_global_wp_object_cache_ioc > "$REPORT_DIR/global-wp-object-cache-ioc-after.txt"
scan_global_scv_wp_content_php > "$REPORT_DIR/global-scv-php-after.txt"
scan_global_obf_loaders > "$REPORT_DIR/global-obf-loaders-after.txt"
scan_global_sc_ioc_lines > "$REPORT_DIR/global-sc-ioc-after.txt"
scan_global_campaign_zip_ioc > "$REPORT_DIR/global-campaign-zips-after.txt"
scan_global_malware_processes > "$REPORT_DIR/global-malware-processes-after.txt"

G_REMAIN="$(awk 'END{print NR+0}' "$REPORT_DIR/global-g-files-after.txt")"
IONIC_REMAIN="$(awk 'END{print NR+0}' "$REPORT_DIR/global-ionic-after.txt")"
ECHO_REMAIN="$(awk 'END{print NR+0}' "$REPORT_DIR/global-echo-compiler-after.txt")"
ELITE_REMAIN="$(awk 'END{print NR+0}' "$REPORT_DIR/global-elite-module-cue-after.txt")"
ELITE_STATE_REMAIN="$(awk 'END{print NR+0}' "$REPORT_DIR/global-elite-state-after.txt")"
EXTLESS_REMAIN="$(awk 'END{print NR+0}' "$REPORT_DIR/global-extensionless-after.txt")"
SCRUNTIME_REMAIN="$(awk 'END{print NR+0}' "$REPORT_DIR/global-sc-runtime-after.txt")"
SCSTATE_REMAIN="$(awk 'END{print NR+0}' "$REPORT_DIR/global-sc-state-after.txt")"
WPOBJCACHE_REMAIN="$(awk 'END{print NR+0}' "$REPORT_DIR/global-wp-object-cache-ioc-after.txt")"
SCV_REMAIN="$(awk 'END{print NR+0}' "$REPORT_DIR/global-scv-php-after.txt")"
OBF_REMAIN="$(awk 'END{print NR+0}' "$REPORT_DIR/global-obf-loaders-after.txt")"
SC_REMAIN="$(awk 'END{print NR+0}' "$REPORT_DIR/global-sc-ioc-after.txt")"
ZIP_REMAIN="$(awk 'END{print NR+0}' "$REPORT_DIR/global-campaign-zips-after.txt")"
PROC_REMAIN="$(awk 'END{print NR+0}' "$REPORT_DIR/global-malware-processes-after.txt")"
[[ "$G_REMAIN" -eq 0 ]] && status CLEAN "No .g_* PHP files remain across discovered WordPress sites" || { status FOUND "$G_REMAIN .g_* file(s) remain account-wide"; ALL_CLEAN=0; }
[[ "$IONIC_REMAIN" -eq 0 ]] && status CLEAN "No ionic-scheduler-orb plugin/MU-plugin paths remain" || { status FOUND "$IONIC_REMAIN ionic-scheduler-orb path(s) remain"; ALL_CLEAN=0; }
[[ "$ECHO_REMAIN" -eq 0 ]] && status CLEAN "No echo-compiler-plus plugin/MU-plugin paths remain" || { status FOUND "$ECHO_REMAIN echo-compiler-plus path(s) remain"; ALL_CLEAN=0; }
[[ "$ELITE_REMAIN" -eq 0 ]] && status CLEAN "No elite-module-cue/unity-manager-lite plugin/MU-plugin paths remain" || { status FOUND "$ELITE_REMAIN elite-module-cue/unity-manager-lite path(s) remain"; ALL_CLEAN=0; }
[[ "$ELITE_STATE_REMAIN" -eq 0 ]] && status CLEAN "No elite-module-cue state artifacts remain" || { status FOUND "$ELITE_STATE_REMAIN elite state artifact(s) remain"; ALL_CLEAN=0; }
[[ "$EXTLESS_REMAIN" -eq 0 ]] && status CLEAN "No extensionless SC PHP payloads remain" || { status FOUND "$EXTLESS_REMAIN extensionless SC payload(s) remain"; ALL_CLEAN=0; }
[[ "$SCRUNTIME_REMAIN" -eq 0 ]] && status CLEAN "No .sc_/.gr_ runtime paths remain" || { status FOUND "$SCRUNTIME_REMAIN .sc_/.gr_ runtime path(s) remain"; ALL_CLEAN=0; }
[[ "$SCSTATE_REMAIN" -eq 0 ]] && status CLEAN "No clustered SC state artifacts remain" || { status FOUND "$SCSTATE_REMAIN clustered SC state artifact(s) remain"; ALL_CLEAN=0; }
[[ "$WPOBJCACHE_REMAIN" -eq 0 ]] && status CLEAN "No confirmed malicious .wp-object-cache-*.dat files remain" || { status FOUND "$WPOBJCACHE_REMAIN confirmed malicious .wp-object-cache file(s) remain"; ALL_CLEAN=0; }
[[ "$SCV_REMAIN" -eq 0 ]] && status CLEAN "No SCV-marked PHP files remain under wp-content" || { status FOUND "$SCV_REMAIN SCV-marked PHP file(s) remain under wp-content"; ALL_CLEAN=0; }
[[ "$OBF_REMAIN" -eq 0 ]] && status CLEAN "No obfuscated SC loader files remain under wp-content" || { status FOUND "$OBF_REMAIN obfuscated SC loader file(s) remain under wp-content"; ALL_CLEAN=0; }
[[ "$SC_REMAIN" -eq 0 ]] && status CLEAN "No SC filesystem markers remain account-wide" || { status FOUND "$SC_REMAIN SC filesystem marker line(s) remain account-wide"; ALL_CLEAN=0; }
[[ "$ZIP_REMAIN" -eq 0 ]] && status CLEAN "No campaign payload ZIPs remain" || { status FOUND "$ZIP_REMAIN campaign payload ZIP(s) remain"; ALL_CLEAN=0; }
[[ "$PROC_REMAIN" -eq 0 ]] && status CLEAN "No campaign malware processes are currently running" || { status FOUND "$PROC_REMAIN campaign process(es) remain"; ALL_CLEAN=0; }

if [[ "$ALL_CLEAN" -ne 1 ]]; then
    section "FINAL STATUS"
    status REVIEW "ACCOUNT NEEDS REVIEW"
    status REVIEW "One or more WordPress installations/account-wide checks require action."
    print_account_review_details
    status FIXED "Temporary wp-includes locks will be cleared before script exit."
    status FIXED "Temporary HTTP 503 will be removed automatically before script exit."
    status CLEAN "User crontab remains paused."
    stop_guard
    restore_all_htaccess || status FAILED "Could not restore one or more .htaccess files; see $HTMETA"
    status FIXED "Temporary HTTP 503 removed despite review/failure status"
    print_manual_restore_hints
    status REVIEW "Per-site result table: $RESULTS_FILE"
    status REVIEW "Concrete review details: $REVIEW_DETAILS_FILE"
    status REVIEW "Account report: $REPORT_DIR"
    exit 10
fi

section "ACCOUNT RELEASE"
# Keep HTTP+cron quarantine and HARD PHP guard active while temporary directory
# locks are removed. Kill any last stray PHP immediately before disabling the
# hard guard; HTTP remains 503 and user cron remains paused until afterwards.
hard_guard_kill_account_php
unlock_all_wp_includes || { status FAILED "Could not clear wp-includes -i/-a flags; exit cleanup will retry"; exit 20; }
hard_guard_kill_account_php
rm -f -- "$HARD_GUARD_FLAG"
stop_guard
restore_account_cron || { status FAILED "Could not restore user crontab; HTTP 503 will still be removed by exit trap"; exit 20; }
restore_all_htaccess || { status FAILED "Could not restore all .htaccess files"; exit 20; }

status CLEAN "All sites released. Watching account for immediate reinfection."
sleep 10
scan_global_g_files > "$REPORT_DIR/reinfection-g-10s.txt"
scan_global_ionic_paths > "$REPORT_DIR/reinfection-ionic-10s.txt"
scan_global_echo_compiler_paths > "$REPORT_DIR/reinfection-echo-compiler-10s.txt"
scan_global_elite_module_cue_paths > "$REPORT_DIR/reinfection-elite-module-cue-10s.txt"
scan_global_elite_state_artifacts > "$REPORT_DIR/reinfection-elite-state-10s.txt"
scan_global_extensionless_payloads > "$REPORT_DIR/reinfection-extensionless-10s.txt"
scan_global_sc_runtime_paths > "$REPORT_DIR/reinfection-sc-runtime-10s.txt"
scan_global_loose_gr_runners > "$REPORT_DIR/reinfection-loose-gr-10s.txt"
scan_global_sc_state_clusters > "$REPORT_DIR/reinfection-sc-state-10s.txt"
scan_global_wp_object_cache_ioc > "$REPORT_DIR/reinfection-wp-object-cache-ioc-10s.txt"
scan_global_scv_wp_content_php > "$REPORT_DIR/reinfection-scv-php-10s.txt"
scan_global_obf_loaders > "$REPORT_DIR/reinfection-obf-loaders-10s.txt"
scan_global_sc_ioc_lines > "$REPORT_DIR/reinfection-sc-ioc-10s.txt"
scan_global_campaign_zip_ioc > "$REPORT_DIR/reinfection-campaign-zips-10s.txt"
scan_global_malware_processes > "$REPORT_DIR/reinfection-processes-10s.txt"
sleep 30
scan_global_g_files > "$REPORT_DIR/reinfection-g-40s.txt"
scan_global_ionic_paths > "$REPORT_DIR/reinfection-ionic-40s.txt"
scan_global_echo_compiler_paths > "$REPORT_DIR/reinfection-echo-compiler-40s.txt"
scan_global_elite_module_cue_paths > "$REPORT_DIR/reinfection-elite-module-cue-40s.txt"
scan_global_elite_state_artifacts > "$REPORT_DIR/reinfection-elite-state-40s.txt"
scan_global_extensionless_payloads > "$REPORT_DIR/reinfection-extensionless-40s.txt"
scan_global_sc_runtime_paths > "$REPORT_DIR/reinfection-sc-runtime-40s.txt"
scan_global_loose_gr_runners > "$REPORT_DIR/reinfection-loose-gr-40s.txt"
scan_global_sc_state_clusters > "$REPORT_DIR/reinfection-sc-state-40s.txt"
scan_global_wp_object_cache_ioc > "$REPORT_DIR/reinfection-wp-object-cache-ioc-40s.txt"
scan_global_scv_wp_content_php > "$REPORT_DIR/reinfection-scv-php-40s.txt"
scan_global_obf_loaders > "$REPORT_DIR/reinfection-obf-loaders-40s.txt"
scan_global_sc_ioc_lines > "$REPORT_DIR/reinfection-sc-ioc-40s.txt"
scan_global_campaign_zip_ioc > "$REPORT_DIR/reinfection-campaign-zips-40s.txt"
scan_global_malware_processes > "$REPORT_DIR/reinfection-processes-40s.txt"

if [[ -s "$REPORT_DIR/reinfection-g-10s.txt" || -s "$REPORT_DIR/reinfection-ionic-10s.txt" || -s "$REPORT_DIR/reinfection-echo-compiler-10s.txt" || -s "$REPORT_DIR/reinfection-elite-module-cue-10s.txt" || -s "$REPORT_DIR/reinfection-sc-runtime-10s.txt" || -s "$REPORT_DIR/reinfection-sc-state-10s.txt" || -s "$REPORT_DIR/reinfection-wp-object-cache-ioc-10s.txt" || -s "$REPORT_DIR/reinfection-scv-php-10s.txt" || -s "$REPORT_DIR/reinfection-obf-loaders-10s.txt" || -s "$REPORT_DIR/reinfection-sc-ioc-10s.txt" || -s "$REPORT_DIR/reinfection-processes-10s.txt" || \
      -s "$REPORT_DIR/reinfection-g-40s.txt" || -s "$REPORT_DIR/reinfection-ionic-40s.txt" || -s "$REPORT_DIR/reinfection-echo-compiler-40s.txt" || -s "$REPORT_DIR/reinfection-elite-module-cue-40s.txt" || -s "$REPORT_DIR/reinfection-sc-runtime-40s.txt" || -s "$REPORT_DIR/reinfection-sc-state-40s.txt" || -s "$REPORT_DIR/reinfection-wp-object-cache-ioc-40s.txt" || -s "$REPORT_DIR/reinfection-scv-php-40s.txt" || -s "$REPORT_DIR/reinfection-obf-loaders-40s.txt" || -s "$REPORT_DIR/reinfection-sc-ioc-40s.txt" || -s "$REPORT_DIR/reinfection-processes-40s.txt" ]]; then
    section "REINFECTION DETECTED"
    status FAILED "Campaign artifact/process reappeared after account release"
    kill_account_php
    # Do NOT re-enable HTTP 503 here. The operator explicitly requires every
    # temporary 503 inserted by the cleaner to be removed on every exit path.
    # Pause restored crontab again using the already preserved original backup.
    if [[ "$(cat "$REPORT_DIR/quarantine/crontab.existed" 2>/dev/null || echo 0)" -eq 1 ]]; then
        crontab -u "$CPUSER" -r 2>/dev/null || true
    fi
    print_manual_restore_hints
    status REVIEW "User cron containment restored; wp-includes remains updateable (-i/-a cleared on exit); HTTP 503 intentionally left OFF"
    status REVIEW "Inspect reinfection-* reports and $REPORT_DIR/account-quarantine-guard.log"
    exit 30
fi

# Final idempotent release pass immediately before successful exit.
unlock_all_wp_includes || { status FAILED "Final release could not clear wp-includes -i/-a flags"; exit 20; }

section "FINAL SUMMARY"
if [[ "$CHECKPOINT_DIRTY" -eq 1 ]]; then
    status REVIEW "One or more post-site account checkpoints found artifacts the guard could not clear; see checkpoint-*-after.txt"
fi
if [[ "$DB_REVIEW" -eq 1 ]]; then
    status REVIEW "ACCOUNT FILESYSTEM CLEAN; ONE OR MORE SITE DIRECT DB PHASES WERE SKIPPED"
    status REVIEW "See REVIEW_DB_SKIPPED rows in $RESULTS_FILE and each site's db-connectivity-error.txt/db-phase-skipped.txt."
else
    status CLEAN "ACCOUNT CLEAN OF DETECTED SC 4.3.24 IOCs"
fi
status CLEAN "$SITE_COUNT WordPress installation(s) processed; account-wide filesystem verification completed"
status REVIEW "Core/plugin package checksums were intentionally not executed in v43-offline; verify/reinstall from trusted packages after containment"
status CLEAN "No .g_* / ionic-scheduler-orb / echo-compiler-plus / elite-module-cue / unity-manager-lite / matching processes detected after release watch"
status CLEAN "All discovered wp-includes directories were released with immutable/append-only flags cleared"
status CLEAN "Original user crontab and .htaccess files restored"
log "Per-site results: $RESULTS_FILE"
log "Full account report: $REPORT_DIR"
rm -f "$WORKER_FILE"; WORKER_FILE=""
trap - EXIT INT TERM HUP
exit 0

# Everything after this marker is the embedded single-site worker. The account
# coordinator extracts it to a temporary root-only file and invokes it for each
# WordPress while the whole account remains quarantined.
exit 0
__SC_SITE_WORKER_BELOW__
#!/usr/bin/env bash
# SC WordPress cleanup/final verification helper v43-offline.
# Root-only. Designed for cPanel/CloudLinux shared hosting.
#
# Safety model:
#   1) Always collect filesystem + database evidence first.
#   2) wp-config.php DB settings are parsed as literal text by Bash; it is never included or executed.
#   3) Database inspection/cleanup uses the mysql/mariadb client directly.
#   4) No WP-CLI command is executed at any point. WP-Cron cleanup and salt rotation
#      are performed offline; package checksum verification is explicitly skipped.
#   5) Unknown hex option names, unknown admins, custom plugins/themes, ZIPs,
#      cache/upload PHP and shared-memory segments are report-only.
#
# Exit codes:
#   0  clean/verified
#   10 filesystem IOCs remain; strict direct-DB cleanup was done; later offline mutations skipped
#   20 verification failure after cleanup
#   30 immediate .g_* reinfection after unlocking wp-includes
#   40 filesystem cleanup completed, but direct DB phase was skipped for review
#   1  operational error
#   2  usage error

set -Eeuo pipefail
umask 077

SCRIPT_NAME="${0##*/}"
SC_ACCOUNT_MODE="${SC_ACCOUNT_MODE:-0}"

usage() {
    cat <<USAGE
Usage:
  $SCRIPT_NAME CPANEL_USER /absolute/path/to/wordpress

Example:
  $SCRIPT_NAME wpclient /home/wpclient/public_html

The script ALWAYS performs direct database inspection and strict SC database cleanup,
even when filesystem IOCs are still present. It never invokes WP-CLI. After the
filesystem gate is clear, WP-Cron is rewritten offline, salts are rotated by editing
literal wp-config.php define() values, and filesystem/direct-DB IOC verification runs.
Core/plugin package checksum verification is intentionally not executed in this mode.
USAGE
}

log() {
    printf '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG_FILE"
}

fatal() {
    log "ERROR: $*"
    exit 1
}

# Human-readable terminal reporting. Keep it plain-text so it remains useful
# over SSH, in ticket transcripts, and when output is redirected to a file.
term_line() {
    printf '%s\n' "$*" | tee -a "$LOG_FILE"
}

term_section() {
    term_line ""
    term_line "======================================================================"
    term_line "$*"
    term_line "======================================================================"
}

# Color is terminal-only; reports/logs remain plain text. Honor NO_COLOR and
# automatically disable ANSI escapes when stdout is not a TTY.
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_GREEN=$'\033[32m'
    C_BLUE=$'\033[34m'
    C_YELLOW=$'\033[33m'
    C_RED=$'\033[31m'
    C_BOLD=$'\033[1m'
    C_RESET=$'\033[0m'
else
    C_GREEN=''
    C_BLUE=''
    C_YELLOW=''
    C_RED=''
    C_BOLD=''
    C_RESET=''
fi

status_line() {
    local kind="$1"
    shift
    local color label
    case "$kind" in
        CLEAN)  color="$C_GREEN";  label="CLEAN" ;;
        FIXED)  color="$C_BLUE";   label="FIXED" ;;
        REVIEW) color="$C_YELLOW"; label="REVIEW" ;;
        FOUND)  color="$C_RED";    label="FOUND" ;;
        FAILED) color="$C_RED";    label="FAILED" ;;
        INFO)   color="";          label="INFO" ;;
        *)      color="";          label="$kind" ;;
    esac
    printf '%b%-6s%b %s\n' "$color$C_BOLD" "$label" "$C_RESET" "$*"
    printf '%-6s %s\n' "$label" "$*" >> "$LOG_FILE"
    return 0
}

# `grep -q` exits at the first match and closes the pipe; under `pipefail` the
# producer is then SIGPIPEd and the pipeline reports 141, silently turning a real
# match into a miss. Let grep drain stdin instead of exiting early.
matches_stdin() {
    grep -Ei -- "$1" >/dev/null
}

# Extract the file that one auto_prepend_file directive points at. Handles the
# Apache forms (`php_value` / `php_admin_value NAME VALUE`) and the ini form
# (`NAME = VALUE`), single or double quotes, and any letter case.
sc_auto_prepend_target() {
    local line="$1" target
    target="$(printf '%s\n' "$line" | awk '{ l=tolower($0); p=index(l,"auto_prepend_file"); if (p) print substr($0,p+17) }')"
    [[ -n "$target" ]] || return 0
    target="${target#"${target%%[![:space:]]*}"}"
    if [[ "$target" == =* ]]; then
        target="${target#=}"
        target="${target#"${target%%[![:space:]]*}"}"
    fi
    case "$target" in
        \"*) target="${target#\"}"; target="${target%%\"*}" ;;
        \'*) target="${target#\'}"; target="${target%%\'*}" ;;
        *)   target="${target%%[[:space:];#]*}" ;;
    esac
    printf '%s\n' "$target"
}

# Machine-readable record that this site carries proven campaign infection. The
# coordinator reads it instead of grepping human-readable log text.
CAMPAIGN_EVIDENCE_RECORDED=0
sc_mark_campaign_evidence() {
    local reason="$*" stamp
    CAMPAIGN_EVIDENCE_RECORDED=1
    stamp="$(date '+%F %T' 2>/dev/null || true)"
    printf '%s\t%s\n' "$stamp" "$reason" >> "$REPORT_DIR/campaign-evidence.txt" 2>/dev/null || true
    if [[ -n "${SC_EVIDENCE_OUT:-}" ]]; then
        printf '%s\t%s\t%s\n' "$stamp" "${WP_PATH:-?}" "$reason" >> "$SC_EVIDENCE_OUT" 2>/dev/null || true
    fi
    return 0
}

file_count() {
    local f="$1"
    [[ -s "$f" ]] || { printf '0'; return 0; }
    awk 'END { print NR+0 }' "$f"
}

preview_file() {
    local f="$1"
    local limit="${2:-8}"
    [[ -s "$f" ]] || return 0
    sed -n "1,${limit}p" "$f" | sed 's/^/    /' | tee -a "$LOG_FILE"
    local count
    count="$(file_count "$f")"
    if [[ "$count" -gt "$limit" ]]; then
        term_line "    ... $((count-limit)) more; full report: $f"
    fi
}

print_inspection_summary() {
    local g_count runtime_count state_count ioc_count scv_count obf_count proc_count dropin_count theme_count derived_count watermark_count
    local auto_count hidden_count cache_count uploads_count zip_count hexfile_count mu_count
    local db_sc_count db_large_count db_hex_count db_derived_count susp_user_count admin_count rogue_auto_count
    local ionic_found_count ionic_removed_count ionic_proc_count ionic_remaining_count
    local sessions_count=0 shm_count=0

    g_count="$(file_count "$REPORT_DIR/fs-g-files.txt")"
    runtime_count="$(file_count "$REPORT_DIR/fs-sc-runtime.txt")"
    state_count="$(file_count "$REPORT_DIR/fs-sc-state.txt")"
    ioc_count="$(file_count "$REPORT_DIR/fs-ioc-lines.txt")"
    scv_count="$(file_count "$REPORT_DIR/fs-scv-php.txt")"
    obf_count="$(file_count "$REPORT_DIR/fs-obf-loaders.txt")"
    proc_count="$(file_count "$REPORT_DIR/fs-g-processes.txt")"
    dropin_count="$(file_count "$REPORT_DIR/fs-dropin-markers.txt")"
    theme_count="$(file_count "$REPORT_DIR/fs-theme-function-markers.txt")"
    derived_count="$(file_count "$REPORT_DIR/fs-derived-artifacts.txt")"
    watermark_count="$(file_count "$REPORT_DIR/fs-watermark-files.txt")"
    auto_count="$(file_count "$REPORT_DIR/fs-auto-prepend.txt")"
    hidden_count="$(file_count "$REPORT_DIR/fs-hidden-php.txt")"
    cache_count="$(file_count "$REPORT_DIR/fs-cache-php.txt")"
    uploads_count="$(file_count "$REPORT_DIR/fs-uploads-php.txt")"
    zip_count="$(file_count "$REPORT_DIR/fs-zip-files.txt")"
    hexfile_count="$(file_count "$REPORT_DIR/fs-short-hex-artifacts.txt")"
    mu_count="$(file_count "$REPORT_DIR/fs-mu-plugins-over-5k.tsv")"
    db_sc_count="$(file_count "$REPORT_DIR/db-sc-options.tsv")"
    db_large_count="$(file_count "$REPORT_DIR/db-large-options.tsv")"
    db_hex_count="$(file_count "$REPORT_DIR/db-hex-options.tsv")"
    db_derived_count="$(file_count "$REPORT_DIR/db-derived-option.tsv")"
    susp_user_count="$(file_count "$REPORT_DIR/db-suspicious-users.tsv")"
    admin_count="$(file_count "$REPORT_DIR/db-admins.tsv")"
    rogue_auto_count="$(file_count "$REPORT_DIR/db-auto-rogue-admins.tsv")"
    ionic_found_count="$(file_count "$REPORT_DIR/ionic-plugin-found.txt")"
    ionic_removed_count="$(file_count "$REPORT_DIR/ionic-plugin-removed.txt")"
    ionic_proc_count="$(file_count "$REPORT_DIR/ionic-processes-killed.txt")"
    ionic_remaining_count="$(file_count "$REPORT_DIR/ionic-plugin-remaining.txt")"
    if [[ -s "$REPORT_DIR/db-session-summary-before.tsv" ]]; then
        sessions_count="$(awk 'NR==1 {print $1+0}' "$REPORT_DIR/db-session-summary-before.tsv")"
    fi
    if [[ -s "$REPORT_DIR/systemv-shm-user.txt" ]]; then
        shm_count="$(awk -v u="$CPUSER" '$3==u {c++} END {print c+0}' "$REPORT_DIR/systemv-shm-user.txt")"
    fi

    term_section "INSPECTION SUMMARY"
    term_line "WordPress: $WP_PATH"
    term_line "Database:  $DB_NAME_CFG   prefix: $PREFIX"
    term_line "Runtime quarantine: account-wide HTTP 503 + cron pause + continuous process guard"
    if [[ "$FS_DIRTY" -eq 1 ]]; then
        status_line FOUND "Filesystem high-confidence IOC(s) remain"
    else
        status_line CLEAN "Filesystem high-confidence IOC gate is clear"
    fi
    if [[ "$ionic_found_count" -gt 0 ]]; then
        status_line FIXED "ionic-scheduler-orb: found $ionic_found_count path(s), removed $ionic_removed_count; killed $ionic_proc_count matching process(es)"
    else
        status_line CLEAN "ionic-scheduler-orb plugin not found"
    fi
    if [[ "$ionic_remaining_count" -gt 0 ]]; then
        status_line FAILED "ionic-scheduler-orb still present after cleanup: $ionic_remaining_count path(s)"
    fi

    term_line ""
    term_line "FOUND - HIGH CONFIDENCE"
    term_line "  ionic-scheduler-orb paths found:   $ionic_found_count"
    [[ "$ionic_found_count" -gt 0 ]] && preview_file "$REPORT_DIR/ionic-plugin-found.txt" 8
    term_line "  .g_* PHP files:                    $g_count"
    [[ "$g_count" -gt 0 ]] && preview_file "$REPORT_DIR/fs-g-files.txt" 8
    term_line "  SC marker/injection lines:         $ioc_count"
    [[ "$ioc_count" -gt 0 ]] && preview_file "$REPORT_DIR/fs-ioc-lines.txt" 8
    term_line "  SCV-marked PHP files in wp-content: $scv_count"
    [[ "$scv_count" -gt 0 ]] && preview_file "$REPORT_DIR/fs-scv-php.txt" 8
    term_line "  Obfuscated SC loader PHP files:    $obf_count"
    [[ "$obf_count" -gt 0 ]] && preview_file "$REPORT_DIR/fs-obf-loaders.txt" 8
    term_line "  Running .g_* processes:            $proc_count"
    [[ "$proc_count" -gt 0 ]] && preview_file "$REPORT_DIR/fs-g-processes.txt" 8
    term_line "  Known infected drop-in markers:    $dropin_count"
    if [[ "$dropin_count" -gt 0 ]]; then preview_file "$REPORT_DIR/fs-dropin-markers.txt" 8; fi
    term_line "  SC_TH theme function markers:      $theme_count"
    if [[ "$theme_count" -gt 0 ]]; then preview_file "$REPORT_DIR/fs-theme-function-markers.txt" 8; fi
    term_line "  Derived SC artifact candidates:    $derived_count"
    [[ "$derived_count" -gt 0 ]] && preview_file "$REPORT_DIR/fs-derived-artifacts.txt" 8
    term_line "  SC DB options/transients:          $db_sc_count (strict evidence count: $SC_DB_EVIDENCE_COUNT)"
    [[ "$db_sc_count" -gt 0 ]] && preview_file "$REPORT_DIR/db-sc-options.tsv" 8

    term_line ""
    term_line "FOUND - REVIEW REQUIRED"
    term_line "  auto_prepend_file directives:      $auto_count"
    [[ "$auto_count" -gt 0 ]] && preview_file "$REPORT_DIR/fs-auto-prepend.txt" 6
    term_line "  Watermark timestamp candidates:    $watermark_count"
    [[ "$watermark_count" -gt 0 ]] && preview_file "$REPORT_DIR/fs-watermark-files.txt" 5
    term_line "  Hidden PHP files:                  $hidden_count"
    [[ "$hidden_count" -gt 0 ]] && preview_file "$REPORT_DIR/fs-hidden-php.txt" 5
    term_line "  PHP files in wp-content/cache:     $cache_count"
    [[ "$cache_count" -gt 0 ]] && preview_file "$REPORT_DIR/fs-cache-php.txt" 5
    term_line "  PHP/PHTML/PHAR in uploads:         $uploads_count"
    [[ "$uploads_count" -gt 0 ]] && preview_file "$REPORT_DIR/fs-uploads-php.txt" 5
    term_line "  ZIP files under wp-content:        $zip_count"
    [[ "$zip_count" -gt 0 ]] && preview_file "$REPORT_DIR/fs-zip-files.txt" 5
    term_line "  Short-hex PHP/ZIP artifacts:       $hexfile_count"
    [[ "$hexfile_count" -gt 0 ]] && preview_file "$REPORT_DIR/fs-short-hex-artifacts.txt" 6
    term_line "  Other MU-plugin PHP files >5 KiB:  $mu_count"
    [[ "$mu_count" -gt 0 ]] && preview_file "$REPORT_DIR/fs-mu-plugins-over-5k.tsv" 5
    term_line "  Large DB options >=20 KiB:         $db_large_count"
    [[ "$db_large_count" -gt 0 ]] && preview_file "$REPORT_DIR/db-large-options.tsv" 5
    term_line "  8-12 char hex DB options:          $db_hex_count"
    [[ "$db_hex_count" -gt 0 ]] && preview_file "$REPORT_DIR/db-hex-options.tsv" 6
    term_line "  Path-derived DB option candidate:  $db_derived_count"
    [[ "$db_derived_count" -gt 0 ]] && preview_file "$REPORT_DIR/db-derived-option.tsv" 4
    term_line "  Administrators in DB:              $admin_count"
    term_line "  Suspicious user-name/email hits:   $susp_user_count"
    [[ "$susp_user_count" -gt 0 ]] && preview_file "$REPORT_DIR/db-suspicious-users.tsv" 8
    term_line "  High-confidence rogue admins:      $rogue_auto_count"
    [[ "$rogue_auto_count" -gt 0 ]] && preview_file "$REPORT_DIR/db-auto-rogue-admins.tsv" 8
    term_line "  Users with stored session tokens:  $sessions_count"
    term_line "  SysV SHM segments owned by user:   $shm_count"

    if [[ -s "$REPORT_DIR/db-cron-indicators.tsv" ]]; then
        local cron_id cron_len cron_md5 cron_sc_fetch cron_random cron_any_sc
        read -r cron_id cron_len cron_md5 cron_sc_fetch cron_random cron_any_sc < "$REPORT_DIR/db-cron-indicators.tsv" || true
        term_line ""
        term_line "WP-CRON RAW DB INDICATORS"
        term_line "  cron option present:               YES"
        term_line "  contains sc_cron_fetch:            ${cron_sc_fetch:-0}"
        term_line "  contains r1ckj5tjyx1yjm:           ${cron_random:-0}"
        term_line "  contains any sc_ string:           ${cron_any_sc:-0}"
    fi

    term_line ""
    term_line "WHAT TO DO NEXT"
    if [[ "$FS_DIRTY" -eq 1 ]]; then
        term_line "  1. Remove the high-confidence filesystem items shown above."
        term_line "  2. The cleaner will use a temporary wp-includes lock on rerun; do not leave +i/+a set after maintenance."
        term_line "  3. Rerun this site after filesystem cleanup; strict SC DB/session cleanup was already performed, while WP-Cron/salts/checksums/unlock were skipped."
    else
        term_line "  Filesystem high-confidence gate passed; automatic DB/session/cron cleanup will continue."
    fi
    [[ "$db_hex_count" -gt 0 ]] && term_line "  Review hex-named DB options before deleting them; they are not auto-deleted."
    [[ "$db_derived_count" -gt 0 ]] && term_line "  Review the path-derived DB option candidate; it is not auto-deleted."
    [[ "$susp_user_count" -gt 0 ]] && term_line "  Campaign-pattern rogue admins will be auto-deleted when a legitimate reassign target exists; other suspicious users remain review-only."
    [[ "$uploads_count" -gt 0 ]] && term_line "  Review executable files under uploads; they are not auto-deleted."
    [[ "$cache_count" -gt 0 ]] && term_line "  Review PHP under wp-content/cache; it is not auto-deleted unless matched by an SC IOC."
    [[ "$mu_count" -gt 0 ]] && term_line "  Review large MU plugins against known-good sources."
    [[ "$shm_count" -gt 0 ]] && term_line "  Review user-owned SysV shared-memory segments before using ipcrm."
    term_line "  Full evidence directory: $REPORT_DIR"
}

print_final_summary() {
    local final_status="$1"
    local db_after=0 sess_after=0 g_after=0 ioc_after=0 proc_after=0
    [[ -f "$REPORT_DIR/db-sc-options-after.tsv" ]] && db_after="$(file_count "$REPORT_DIR/db-sc-options-after.tsv")"
    if [[ -s "$REPORT_DIR/db-session-summary-after.tsv" ]]; then
        sess_after="$(awk 'NR==1 {print $1+0}' "$REPORT_DIR/db-session-summary-after.tsv")"
    fi
    [[ -f "$REPORT_DIR/fs-g-files-after.txt" ]] && g_after="$(file_count "$REPORT_DIR/fs-g-files-after.txt")"
    [[ -f "$REPORT_DIR/fs-ioc-lines-after.txt" ]] && ioc_after="$(file_count "$REPORT_DIR/fs-ioc-lines-after.txt")"
    [[ -f "$REPORT_DIR/fs-g-processes-after.txt" ]] && proc_after="$(file_count "$REPORT_DIR/fs-g-processes-after.txt")"

    term_section "FINAL SUMMARY"
    case "$final_status" in
        CLEAN*) status_line CLEAN "$final_status" ;;
        *REINFECTION*|FAILED*) status_line FAILED "$final_status" ;;
        *) status_line REVIEW "$final_status" ;;
    esac
    local ionic_remaining=0
    [[ -f "$REPORT_DIR/ionic-plugin-remaining.txt" ]] && ionic_remaining="$(file_count "$REPORT_DIR/ionic-plugin-remaining.txt")"
    term_line "Remaining ionic-scheduler-orb:    $ionic_remaining"
    term_line "Remaining .g_* files:              $g_after"
    term_line "Remaining SC filesystem markers:   $ioc_after"
    term_line "Remaining .g_* processes:          $proc_after"
    term_line "Remaining strict SC DB rows:       $STRICT_DB_REMAIN"
    term_line "Users with session tokens:         $sess_after"
    term_line "Core checksum status:              ${CORE_CHECK_STATUS:-$([[ "${CORE_OK:-0}" -eq 1 ]] && echo PASS || echo FAIL)}"
    term_line "Plugin checksum status:            ${PLUGIN_CHECK_STATUS:-$([[ "${PLUGIN_OK:-0}" -eq 1 ]] && echo PASS || echo REVIEW)}"
    local lock_state="NO"
    wp_includes_has_attr i && lock_state="YES" || true
    term_line "wp-includes immutable now:         $lock_state (temporary during cleanup)"

    term_line ""
    term_line "ADDITIONAL ACTIONS"
    if [[ "${CORE_OK:-0}" -ne 1 ]]; then
        term_line "  Restore/reinstall the WordPress core from a trusted package before release."
    fi
    if [[ "${PLUGIN_OK:-0}" -ne 1 ]]; then
        term_line "  Review plugin-checksums.txt; reinstall modified WordPress.org plugins from trusted packages."
    fi
    if [[ "${CORE_CHECK_STATUS:-}" == "SKIPPED_NO_WPCLI" || "${PLUGIN_CHECK_STATUS:-}" == "SKIPPED_NO_WPCLI" ]]; then
        term_line "  Integrity checks were not executed to preserve zero-WP-CLI containment; reinstall/verify core and plugins from trusted packages after cleanup."
    fi
    [[ -s "$REPORT_DIR/db-hex-options.tsv" ]] && term_line "  Review db-hex-options.tsv; hex DB options were intentionally not auto-deleted."
    [[ -s "$REPORT_DIR/db-derived-option.tsv" ]] && term_line "  Review db-derived-option.tsv; the path-derived option was intentionally not auto-deleted."
    [[ -s "$REPORT_DIR/db-suspicious-users-after.tsv" ]] && term_line "  Review db-suspicious-users-after.tsv; these suspicious users remain after automatic campaign-admin cleanup."
    [[ -s "$REPORT_DIR/fs-uploads-php.txt" ]] && term_line "  Review executable files listed in fs-uploads-php.txt."
    [[ -s "$REPORT_DIR/fs-cache-php.txt" ]] && term_line "  Review PHP files listed in fs-cache-php.txt."
    [[ -s "$REPORT_DIR/fs-mu-plugins-over-5k.tsv" ]] && term_line "  Review other MU plugins listed in fs-mu-plugins-over-5k.tsv; exact ionic-scheduler-orb.php is auto-removed."
    [[ -s "$REPORT_DIR/db-auto-rogue-admins-failed.tsv" ]] && term_line "  REVIEW: campaign rogue admin(s) remain because automatic deletion/reassignment failed."
    term_line "  Clear site data/service-worker storage in browsers used for WordPress administration."
    term_line "  Keep the server-wide ModSecurity containment rules enabled during the incident."
    if [[ -s "$REPORT_DIR/quarantine-guard.log" ]]; then
        term_line "  The quarantine guard killed/re-removed respawned artifacts; review quarantine-guard.log."
    fi
    term_line "  Exit policy: wp-includes must not retain immutable/append-only flags after standalone completion."
    term_line "  Full report: $REPORT_DIR"
}

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    if [[ "${SC_ALLOW_NONROOT_TEST:-0}" == 1 ]]; then
        echo "WARNING: running unprivileged under SC_ALLOW_NONROOT_TEST=1; this is a test mode only." >&2
    else
        echo "ERROR: Run as root." >&2
        exit 1
    fi
fi

[[ $# -eq 2 ]] || {
    usage
    exit 2
}

CPUSER="$1"
WP_INPUT="$2"
SC_PREFLIGHT_ONLY="${SC_PREFLIGHT_ONLY:-0}"
SC_PREVIOUS_CAMPAIGN_EVIDENCE="${SC_PREVIOUS_CAMPAIGN_EVIDENCE:-0}"
[[ "$SC_PREFLIGHT_ONLY" == 0 || "$SC_PREFLIGHT_ONLY" == 1 ]] || { echo "ERROR: SC_PREFLIGHT_ONLY must be 0 or 1" >&2; exit 2; }
[[ "$SC_PREVIOUS_CAMPAIGN_EVIDENCE" == 0 || "$SC_PREVIOUS_CAMPAIGN_EVIDENCE" == 1 ]] || { echo "ERROR: SC_PREVIOUS_CAMPAIGN_EVIDENCE must be 0 or 1" >&2; exit 2; }

id "$CPUSER" >/dev/null 2>&1 || {
    echo "ERROR: Unix user '$CPUSER' does not exist." >&2
    exit 1
}

for cmd in realpath chattr lsattr pgrep pkill grep find awk sed date tee getent md5sum ipcs stat crontab cp mktemp chmod chown id sleep paste base64; do
    command -v "$cmd" >/dev/null 2>&1 || {
        echo "ERROR: Required command not found: $cmd" >&2
        exit 1
    }
done

WP_PATH="$(realpath -e "$WP_INPUT")" || {
    echo "ERROR: WordPress path does not exist: $WP_INPUT" >&2
    exit 1
}
USER_HOME="$(getent passwd "$CPUSER" | awk -F: '{print $6}')"
USER_HOME="$(realpath -e "$USER_HOME")"

case "$WP_PATH/" in
    "$USER_HOME"/*) ;;
    *)
        echo "ERROR: '$WP_PATH' is not inside '$USER_HOME'." >&2
        exit 1
        ;;
esac

[[ -f "$WP_PATH/wp-config.php" ]] || { echo "ERROR: wp-config.php missing." >&2; exit 1; }
[[ -d "$WP_PATH/wp-includes" ]] || { echo "ERROR: wp-includes missing." >&2; exit 1; }
[[ -d "$WP_PATH/wp-admin" ]] || { echo "ERROR: wp-admin missing." >&2; exit 1; }
[[ -d "$WP_PATH/wp-content" ]] || { echo "ERROR: wp-content missing." >&2; exit 1; }

STAMP="$(date '+%Y%m%d-%H%M%S')"
SITE_HASH="$(printf '%s' "$WP_PATH" | md5sum | awk '{print substr($1,1,8)}')"
MODE_SUFFIX=""
[[ "$SC_PREFLIGHT_ONLY" -eq 1 ]] && MODE_SUFFIX="-preflight"
SC_REPORT_ROOT="${SC_REPORT_ROOT:-/root/wp-sc-cleaner}"
REPORT_DIR="${SC_REPORT_ROOT}/${CPUSER}/${STAMP}-${SITE_HASH}${MODE_SUFFIX}"
mkdir -p "$REPORT_DIR"
LOG_FILE="$REPORT_DIR/cleanup.log"
touch "$LOG_FILE"

worker_err_report() {
    local rc=$? line="${BASH_LINENO[0]:-?}" cmd="${BASH_COMMAND:-?}"
    printf '[%s] ERROR: worker command failed rc=%s line=%s command=%q\n' "$(date '+%F %T')" "$rc" "$line" "$cmd" | tee -a "$LOG_FILE" >&2
    return "$rc"
}
trap worker_err_report ERR

# v43-offline deliberately does not invoke WP-CLI. Even before_wp_load commands
# still start PHP, and account-mode v35 exempted every PHP descendant of the
# controlled worker from the HARD guard. A compromised CLI bootstrap or PHP
# auto_prepend therefore had a path to re-seed the account while being allowlisted.
#
# wp-config.php is read as PLAIN TEXT by Bash. It is never sourced, included,
# evaluated by PHP or passed to WP-CLI. Only ordinary literal define() values and
# a literal $table_prefix assignment are accepted. Dynamic/env/concatenated
# configurations are deliberately refused and become REVIEW_DB_SKIPPED.
DB_CLIENT=""
DB_DEFAULTS_FILE=""
DB_NAME_CFG=""
DB_USER_CFG=""
DB_PASSWORD_CFG=""
DB_HOST_CFG=""
DB_HOSTNAME=""
DB_PORT=""
DB_SOCKET=""
PREFIX=""
OFFLINE_CONFIG_ERROR=""

# Decode one PHP quoted string appearing on the same line as a define() or
# $table_prefix assignment. This does NOT evaluate PHP.
#
# Single-quoted PHP strings: only \\ and \' are interpreted by PHP; all other
# backslashes remain literal. Double-quoted strings are accepted only when they
# contain no interpolation and use only the unambiguous escapes \\, \" and \$.
# More complex double-quoted forms are refused instead of guessing.
sc_decode_php_literal_rhs() {
    local rhs="$1" terminator="${2:-define}" quote ch next out="" tail
    local i=1 len

    rhs="${rhs#"${rhs%%[![:space:]]*}"}"
    [[ -n "$rhs" ]] || return 2
    quote="${rhs:0:1}"
    [[ "$quote" == "'" || "$quote" == '"' ]] || return 2
    len=${#rhs}

    while (( i < len )); do
        ch="${rhs:i:1}"

        if [[ "$ch" == "$quote" ]]; then
            tail="${rhs:i+1}"
            # Require a complete assignment/define terminator after the literal.
            if [[ "$terminator" == "define" ]]; then
                [[ "$tail" =~ ^[[:space:]]*\)[[:space:]]*\; ]] || return 2
            else
                [[ "$tail" =~ ^[[:space:]]*\; ]] || return 2
            fi
            printf '%s\n' "$out"
            return 0
        fi

        if [[ "$ch" == "\\" ]]; then
            ((i++))
            (( i < len )) || return 2
            next="${rhs:i:1}"
            if [[ "$quote" == "'" ]]; then
                case "$next" in
                    "'"|"\\") out+="$next" ;;
                    *) out+="\\$next" ;;
                esac
            else
                case "$next" in
                    '"'|'\\'|'$') out+="$next" ;;
                    *) return 2 ;;
                esac
            fi
            ((i++))
            continue
        fi

        # An unescaped $ in a double-quoted PHP string can interpolate variables.
        [[ "$quote" != '"' || "$ch" != '$' ]] || return 2
        out+="$ch"
        ((i++))
    done
    return 2
}

# Read one literal define('KEY', 'value'); from wp-config.php. Only active lines
# outside obvious full-line block comments are considered. Multiple definitions
# are rejected as ambiguous rather than silently choosing one.
wp_config_literal_define() {
    local key="$1" file="$WP_PATH/wp-config.php"
    local line trimmed rhs decoded found=0 in_block=0
    local re_sq re_dq
    re_sq="^[[:space:]]*define[[:space:]]*\\([[:space:]]*'${key}'[[:space:]]*,[[:space:]]*(.*)$"
    re_dq="^[[:space:]]*define[[:space:]]*\\([[:space:]]*\"${key}\"[[:space:]]*,[[:space:]]*(.*)$"

    while IFS= read -r line || [[ -n "$line" ]]; do
        trimmed="${line#"${line%%[![:space:]]*}"}"

        if (( in_block )); then
            if [[ "$trimmed" == *'*/'* ]]; then in_block=0; fi
            continue
        fi
        case "$trimmed" in
            '/*'*)
                [[ "$trimmed" == *'*/'* ]] || in_block=1
                continue
                ;;
            '//'*|'#'*) continue ;;
        esac

        rhs=""
        if [[ "$line" =~ $re_sq ]]; then
            rhs="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ $re_dq ]]; then
            rhs="${BASH_REMATCH[1]}"
        else
            continue
        fi

        ((found++))
        (( found == 1 )) || return 3
        if decoded="$(sc_decode_php_literal_rhs "$rhs")"; then
            printf '%s\n' "$decoded"
        else
            return 2
        fi
    done < "$file"

    (( found == 1 )) || return 1
    return 0
}

# Read a literal $table_prefix = 'wp_'; assignment. WordPress itself documents
# this as letters/numbers/underscores; anything else is refused.
wp_config_literal_prefix() {
    local file="$WP_PATH/wp-config.php"
    local line trimmed rhs decoded found=0 in_block=0
    local re='^[[:space:]]*\$table_prefix[[:space:]]*=[[:space:]]*(.*)$'

    while IFS= read -r line || [[ -n "$line" ]]; do
        trimmed="${line#"${line%%[![:space:]]*}"}"

        if (( in_block )); then
            if [[ "$trimmed" == *'*/'* ]]; then in_block=0; fi
            continue
        fi
        case "$trimmed" in
            '/*'*)
                [[ "$trimmed" == *'*/'* ]] || in_block=1
                continue
                ;;
            '//'*|'#'*) continue ;;
        esac

        [[ "$line" =~ $re ]] || continue
        rhs="${BASH_REMATCH[1]}"
        ((found++))
        (( found == 1 )) || return 3

        # Reuse the literal decoder by making the assignment tail look like a
        # define() tail. The decoder only validates the quoted value + ); suffix.
        if decoded="$(sc_decode_php_literal_rhs "$rhs" assign)"; then
            [[ "$decoded" =~ ^[A-Za-z0-9_]+$ ]] || return 4
            printf '%s\n' "$decoded"
        else
            return 2
        fi
    done < "$file"

    (( found == 1 )) || return 1
    return 0
}

offline_config_load() {
    local rc
    OFFLINE_CONFIG_ERROR=""

    if PREFIX="$(wp_config_literal_prefix)"; then :; else
        rc=$?
        OFFLINE_CONFIG_ERROR="table_prefix is missing, duplicated, dynamic, or not a safe literal (parser rc=$rc)"
        return 1
    fi
    if DB_NAME_CFG="$(wp_config_literal_define DB_NAME)"; then :; else
        rc=$?
        OFFLINE_CONFIG_ERROR="DB_NAME is missing, duplicated, or not a supported literal (parser rc=$rc)"
        return 1
    fi
    if DB_USER_CFG="$(wp_config_literal_define DB_USER)"; then :; else
        rc=$?
        OFFLINE_CONFIG_ERROR="DB_USER is missing, duplicated, or not a supported literal (parser rc=$rc)"
        return 1
    fi
    if DB_PASSWORD_CFG="$(wp_config_literal_define DB_PASSWORD)"; then :; else
        rc=$?
        OFFLINE_CONFIG_ERROR="DB_PASSWORD is missing, duplicated, or not a supported literal (parser rc=$rc)"
        return 1
    fi
    if DB_HOST_CFG="$(wp_config_literal_define DB_HOST)"; then :; else
        rc=$?
        OFFLINE_CONFIG_ERROR="DB_HOST is missing, duplicated, or not a supported literal (parser rc=$rc)"
        return 1
    fi

    [[ "$PREFIX" =~ ^[A-Za-z0-9_]+$ ]] || {
        OFFLINE_CONFIG_ERROR="table_prefix contains characters outside [A-Za-z0-9_]"
        return 1
    }
    [[ -n "$DB_NAME_CFG" ]] || { OFFLINE_CONFIG_ERROR="DB_NAME is empty"; return 1; }
    [[ -n "$DB_USER_CFG" ]] || { OFFLINE_CONFIG_ERROR="DB_USER is empty"; return 1; }
    [[ -n "$DB_HOST_CFG" ]] || { OFFLINE_CONFIG_ERROR="DB_HOST is empty"; return 1; }
    # An empty DB_PASSWORD is unusual but valid, so it is not rejected here.
    return 0
}

select_db_client() {
    if command -v mariadb >/dev/null 2>&1; then
        DB_CLIENT="$(command -v mariadb)"
    elif command -v mysql >/dev/null 2>&1; then
        DB_CLIENT="$(command -v mysql)"
    else
        return 1
    fi
}

parse_db_host() {
    DB_HOSTNAME="$DB_HOST_CFG"; DB_PORT=""; DB_SOCKET=""
    if [[ "$DB_HOST_CFG" == /* ]]; then
        DB_HOSTNAME="localhost"; DB_SOCKET="$DB_HOST_CFG"
    elif [[ "$DB_HOST_CFG" =~ ^\[([^]]+)\]:([0-9]+)$ ]]; then
        DB_HOSTNAME="${BASH_REMATCH[1]}"; DB_PORT="${BASH_REMATCH[2]}"
    elif [[ "$DB_HOST_CFG" =~ ^([^:]+):([0-9]+)$ ]]; then
        DB_HOSTNAME="${BASH_REMATCH[1]}"; DB_PORT="${BASH_REMATCH[2]}"
    elif [[ "$DB_HOST_CFG" =~ ^([^:]+):(/.*)$ ]]; then
        DB_HOSTNAME="${BASH_REMATCH[1]}"; DB_SOCKET="${BASH_REMATCH[2]}"
    fi
}

sc_mysql_option_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}

prepare_db_defaults() {
    local u p h sock
    rm -f -- "${DB_DEFAULTS_FILE:-}" 2>/dev/null || true
    DB_DEFAULTS_FILE="$(mktemp "$REPORT_DIR/.mysql-client.XXXXXX")" || return 1
    chmod 600 "$DB_DEFAULTS_FILE" || return 1

    u="$(sc_mysql_option_escape "$DB_USER_CFG")"
    p="$(sc_mysql_option_escape "$DB_PASSWORD_CFG")"
    h="$(sc_mysql_option_escape "$DB_HOSTNAME")"
    sock="$(sc_mysql_option_escape "$DB_SOCKET")"

    {
        echo '[client]'
        printf 'user="%s"\n' "$u"
        printf 'password="%s"\n' "$p"
        if [[ -n "$DB_SOCKET" ]]; then
            echo 'protocol=SOCKET'
            printf 'socket="%s"\n' "$sock"
        else
            printf 'host="%s"\n' "$h"
            [[ -n "$DB_PORT" ]] && printf 'port=%s\n' "$DB_PORT"
        fi
    } > "$DB_DEFAULTS_FILE"
    chmod 600 "$DB_DEFAULTS_FILE"
}

db_client_run() {
    local -a args
    [[ -n "$DB_CLIENT" && -n "$DB_DEFAULTS_FILE" && -f "$DB_DEFAULTS_FILE" ]] || return 127
    # --defaults-extra-file must be the first client option. Credentials never
    # appear in argv or in an account-owned process environment.
    args=(--defaults-extra-file="$DB_DEFAULTS_FILE" --batch --raw --skip-column-names --database="$DB_NAME_CFG")
    "$DB_CLIENT" "${args[@]}" "$@"
}

db_query() {
    local sql="$1"
    db_client_run --execute="$sql"
}

db_query_file() {
    local sql_file="$1"
    db_client_run < "$sql_file"
}


offline_clean_cron_option() {
    local in_hex="$REPORT_DIR/wp-cron-before.hex"
    local out_hex="$REPORT_DIR/wp-cron-after.hex"
    local removed="$REPORT_DIR/wp-cron-removed-hooks.txt"
    local kept="$REPORT_DIR/wp-cron-kept-referenced-hooks.txt"
    local names="$REPORT_DIR/.offline-cron-hooks.txt"
    local drop="$REPORT_DIR/.offline-cron-drop.txt"
    local helper="$REPORT_DIR/.offline-cron-cleaner.php"
    local cands="$REPORT_DIR/.offline-cron-candidates.txt"
    local ondisk="$REPORT_DIR/.offline-cron-referenced.txt"
    local sql_file="$REPORT_DIR/.offline-cron-update.sql"
    local bin hook

    db_query "SELECT HEX(option_value) FROM ${OPTIONS_TABLE} WHERE option_name='cron' LIMIT 1;" > "$in_hex" 2>>"$LOG_FILE" || return 1
    if [[ ! -s "$in_hex" ]]; then
        : > "$removed"
        status_line CLEAN "No WordPress cron option is present"
        return 0
    fi

    bin="$(sc_php_serialization_bin)" || {
        log "REVIEW: No PHP >= 7 interpreter is available for the isolated offline cron serializer."
        return 1
    }
    status_line CLEAN "Offline cron serializer: $bin ($($bin -n -r 'echo PHP_VERSION;' 2>/dev/null || echo unknown))"

    # The serializer only ever decodes and re-encodes. WHICH hooks disappear is
    # decided in Bash, so the rule stays testable and the orphan check can look
    # at the filesystem - something the PHP side has no business doing.
    #
    # Every `}` below is indented on purpose: the regression harness ends a
    # function at the first `}` in column 1, and would otherwise truncate this
    # function at the heredoc and silently test nothing.
    cat > "$helper" <<'PHP'
<?php
if ($argc < 4) exit(2);
$mode = (string)$argv[1];
$hex  = trim((string)@file_get_contents($argv[2]));
$raw  = @hex2bin($hex);
if ($raw === false) exit(3);
$v = @unserialize($raw, ['allowed_classes' => false]);
if (!is_array($v)) exit(4);
function sc_plain_data($x) {
    if (is_object($x) || is_resource($x)) return false;
    if (is_array($x)) foreach ($x as $e) if (!sc_plain_data($e)) return false;
    return true;
 }
if (!sc_plain_data($v)) exit(5);

if ($mode === 'list') {
    $names = [];
    foreach ($v as $ts => $hooks) {
        if ($ts === 'version' || !is_array($hooks)) continue;
        foreach (array_keys($hooks) as $h) $names[(string)$h] = 1;
    }
    $out = array_keys($names);
    file_put_contents($argv[3], implode("\n", $out) . (empty($out) ? '' : "\n"));
    exit(0);
 }

if ($mode !== 'apply' || $argc !== 6) exit(2);
$list = @file($argv[4], FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
if ($list === false) $list = [];
$drop = array_flip($list);
$removed = [];
foreach ($v as $ts => &$hooks) {
    if ($ts === 'version' || !is_array($hooks)) continue;
    foreach (array_keys($hooks) as $h) {
        if (isset($drop[(string)$h])) { unset($hooks[$h]); $removed[(string)$h] = 1; }
    }
    if (empty($hooks)) unset($v[$ts]);
 }
unset($hooks);
file_put_contents($argv[3], strtoupper(bin2hex(serialize($v))) . "\n");
$r = array_keys($removed);
file_put_contents($argv[5], implode("\n", $r) . (empty($r) ? '' : "\n"));
PHP
    chmod 600 "$helper"

    if ! "$bin" -n -d auto_prepend_file= -d auto_append_file= "$helper" list "$in_hex" "$names" 2>>"$LOG_FILE"; then
        rm -f -- "$helper"
        return 1
    fi

    : > "$drop"; : > "$kept"
    # Every sc_-prefixed hook goes unconditionally; that prefix is the campaign's
    # own namespace and has never collided with a legitimate hook.
    grep -E '^sc_' "$names" >> "$drop" 2>/dev/null || true

    # Everything else is a judgement call, so it needs campaign proof for this
    # site AND has to be an orphan on disk.
    if [[ "${CAMPAIGN_SITE_PROVEN:-0}" -eq 1 ]]; then
        sc_filter_random_cron_hooks < "$names" > "$cands"
        # One tree walk for every candidate, instead of one walk per candidate.
        # If that lookup cannot run, every hook would look like an orphan and be
        # deleted, so a failure here must keep hooks, never drop them.
        if ! sc_cron_hooks_referenced_on_disk < "$cands" > "$ondisk"; then
            status_line REVIEW "Could not determine which randomized cron hooks are referenced on disk; none were deleted"
            : > "$cands"
        fi
        while IFS= read -r hook; do
            [[ -n "$hook" ]] || continue
            if grep -qxF -- "$hook" "$ondisk" 2>/dev/null; then
                printf '%s\n' "$hook" >> "$kept"
                status_line REVIEW "Cron hook '$hook' looks randomized but is still referenced on disk; kept"
            else
                printf '%s\n' "$hook" >> "$drop"
            fi
        done < "$cands"
        rm -f -- "$cands" "$ondisk"
    else
        log "Site is not campaign-proven; only sc_* cron hooks are eligible for deletion."
    fi

    if [[ -s "$drop" ]]; then
        sort -u -o "$drop" "$drop"
    fi
    if [[ ! -s "$drop" ]]; then
        : > "$removed"
        rm -f -- "$helper"
        status_line CLEAN "No campaign WP-Cron hooks required deletion (offline serialized-data check)"
        return 0
    fi

    if ! "$bin" -n -d auto_prepend_file= -d auto_append_file= "$helper" apply "$in_hex" "$out_hex" "$drop" "$removed" 2>>"$LOG_FILE"; then
        rm -f -- "$helper"
        return 1
    fi
    rm -f -- "$helper"

    if cmp -s "$in_hex" "$out_hex"; then
        status_line CLEAN "No campaign WP-Cron hooks required deletion (offline serialized-data check)"
        return 0
    fi

    {
        printf 'UPDATE `%s` SET option_value=UNHEX(%s' "$OPTIONS_TABLE" "'"
        tr -d '\r\n' < "$out_hex"
        printf "%s\n" "') WHERE option_name='cron';" "SELECT ROW_COUNT();"
    } > "$sql_file"
    if ! db_query_file "$sql_file" > "$REPORT_DIR/wp-cron-update-result.txt" 2>>"$LOG_FILE"; then
        rm -f -- "$sql_file"
        return 1
    fi
    rm -f -- "$sql_file"
    db_query "SELECT HEX(option_value) FROM ${OPTIONS_TABLE} WHERE option_name='cron' LIMIT 1;" > "$REPORT_DIR/wp-cron-verify.hex" 2>>"$LOG_FILE" || return 1
    tr -d '\r\n' < "$out_hex" > "$REPORT_DIR/.wp-cron-expected.norm"
    tr -d '\r\n' < "$REPORT_DIR/wp-cron-verify.hex" > "$REPORT_DIR/.wp-cron-actual.norm"
    if ! cmp -s "$REPORT_DIR/.wp-cron-expected.norm" "$REPORT_DIR/.wp-cron-actual.norm"; then
        rm -f -- "$REPORT_DIR/.wp-cron-expected.norm" "$REPORT_DIR/.wp-cron-actual.norm"
        return 1
    fi
    rm -f -- "$REPORT_DIR/.wp-cron-expected.norm" "$REPORT_DIR/.wp-cron-actual.norm"
    if [[ -s "$removed" ]]; then
        sc_mark_campaign_evidence "campaign WP-Cron hook(s) removed from the serialized cron option"
        status_line FIXED "Removed $(awk 'END{print NR+0}' "$removed") campaign WP-Cron hook(s) without bootstrapping WordPress"
    else
        status_line CLEAN "Cron option rewritten without campaign hooks"
    fi
    return 0
}

offline_rotate_salts() {
    local cfg="$WP_PATH/wp-config.php" backup="$REPORT_DIR/wp-config.before-salt-rotation.php"
    local tmp="$REPORT_DIR/.wp-config-salts.$$.tmp" key val flags found=0 missing=0
    local keys=(AUTH_KEY SECURE_AUTH_KEY LOGGED_IN_KEY NONCE_KEY AUTH_SALT SECURE_AUTH_SALT LOGGED_IN_SALT NONCE_SALT)
    cp -a -- "$cfg" "$backup" || return 1
    cp -a -- "$cfg" "$tmp" || return 1
    for key in "${keys[@]}"; do
        val="$(head -c 48 /dev/urandom | base64 | tr -d '\r\n')"
        if awk -v k="$key" -v v="$val" '
            BEGIN{done=0}
            {
                if (!done && $0 ~ "^[[:space:]]*define[[:space:]]*\\([[:space:]]*[\047\042]" k "[\047\042][[:space:]]*,") {
                    print "define( \047" k "\047, \047" v "\047 );"; done=1
                } else print
            }
            END{if(!done) exit 42}
        ' "$tmp" > "$tmp.next"; then
            mv -f -- "$tmp.next" "$tmp"
            found=$((found+1))
        else
            rm -f -- "$tmp.next"
            missing=$((missing+1))
        fi
    done
    if [[ "$found" -eq 0 ]]; then
        rm -f -- "$tmp"
        status_line REVIEW "Authentication salts are not literal define() values; offline rotation skipped"
        return 2
    fi
    if ! sc_php_syntax_ok "$tmp"; then
        rm -f -- "$tmp"
        status_line REVIEW "Refusing offline salt rotation because the rewritten wp-config.php does not parse cleanly"
        return 1
    fi
    flags="$(lsattr -d "$cfg" 2>/dev/null | awk '{print $1}' | head -n1 || true)"
    chattr -ia -- "$cfg" 2>/dev/null || true
    if ! cat "$tmp" > "$cfg"; then
        cp -a -- "$backup" "$cfg" 2>/dev/null || true
        rm -f -- "$tmp"
        return 1
    fi
    rm -f -- "$tmp"
    [[ "$flags" == *i* ]] && chattr +i -- "$cfg" 2>/dev/null || true
    [[ "$flags" == *a* ]] && chattr +a -- "$cfg" 2>/dev/null || true
    if [[ "$missing" -eq 0 ]]; then
        status_line FIXED "Rotated all 8 WordPress authentication salts offline"
        return 0
    fi
    status_line REVIEW "Rotated $found salt/key define(s); $missing non-literal/missing define(s) require review"
    return 2
}

offline_delete_rogue_user() {
    local rogue_id="$1" reassign_id="$2" sql_file
    sql_file="$REPORT_DIR/.rogue-user-${rogue_id}.sql"
    [[ "$rogue_id" =~ ^[0-9]+$ && "$reassign_id" =~ ^[0-9]+$ ]] || return 2
    {
        echo 'START TRANSACTION;'
        printf 'UPDATE `%s` SET post_author=%s WHERE post_author=%s;\n' "$POSTS_TABLE" "$reassign_id" "$rogue_id"
        printf 'DELETE FROM `%s` WHERE user_id=%s;\n' "$USERMETA_TABLE" "$rogue_id"
        printf 'DELETE FROM `%s` WHERE ID=%s;\n' "$USERS_TABLE" "$rogue_id"
        echo 'COMMIT;'
        printf 'SELECT COUNT(*) FROM `%s` WHERE ID=%s;\n' "$USERS_TABLE" "$rogue_id"
    } > "$sql_file"
    if ! db_query_file "$sql_file" > "$REPORT_DIR/rogue-admin-delete-${rogue_id}.log" 2>>"$LOG_FILE"; then
        rm -f -- "$sql_file"
        return 1
    fi
    rm -f -- "$sql_file"
    [[ "$(tail -n1 "$REPORT_DIR/rogue-admin-delete-${rogue_id}.log" | tr -dc '0-9')" == 0 ]]
}

# The campaign keeps two manifests of its own in the options table, both seen in
# the captured 4.3.24 dump:
#
#   sc_own_manifest      <md5> => {p: absolute path, h: md5, g: version, t: ts}
#                        paths it CREATED - deletable, subject to the gates below
#   sc_persist_manifest  "<path>" or "line:<path>" => "size|mtime[|flag]"
#                        files it merely REPLACED or injected into (db.php, the
#                        theme functions.php, .htaccess) - verification input only
#
# They are read BEFORE the strict `^sc_` delete removes them, and an owned entry
# is never a licence to delete: containment, core/config paths and a live IOC
# match are all checked again on our side.
harvest_sc_db_manifests() {
    local owned="$REPORT_DIR/sc-manifest-owned.txt"
    local verify="$REPORT_DIR/sc-manifest-verify.tsv"
    local all="$REPORT_DIR/sc-manifest-paths.txt"
    local hex="$REPORT_DIR/.sc-manifest.hex"
    local helper="$REPORT_DIR/.offline-manifest.php"
    local bin rc=0
    : > "$owned"; : > "$verify"; : > "$all"

    bin="$(sc_php_serialization_bin)" || {
        log "REVIEW: No PHP >= 7 interpreter for the isolated manifest decoder; manifests not harvested."
        return 1
    }

    # As in the cron helper, no `}` may start a line or the test harness cuts
    # this function short at the heredoc.
    cat > "$helper" <<'PHP'
<?php
if ($argc !== 4) exit(2);
$mode = (string)$argv[1];
$hex  = trim((string)@file_get_contents($argv[2]));
if ($hex === '') exit(6);
$raw = @hex2bin($hex);
if ($raw === false) exit(3);
$v = @unserialize($raw, ['allowed_classes' => false]);
if (!is_array($v)) exit(4);
$out = [];
if ($mode === 'own') {
    foreach ($v as $e) {
        if (!is_array($e) || !isset($e['p']) || !is_string($e['p'])) continue;
        if (strpos($e['p'], "\n") !== false) continue;
        $out[] = $e['p'];
    }
 } elseif ($mode === 'persist') {
    foreach (array_keys($v) as $k) {
        $k = (string)$k;
        if (strpos($k, "\n") !== false) continue;
        if (strncmp($k, 'line:', 5) === 0) $out[] = "line\t" . substr($k, 5);
        else $out[] = "file\t" . $k;
    }
 } else {
    exit(2);
 }
file_put_contents($argv[3], implode("\n", $out) . (empty($out) ? '' : "\n"));
PHP
    chmod 600 "$helper"

    db_query "SELECT HEX(option_value) FROM ${OPTIONS_TABLE} WHERE option_name='sc_own_manifest' LIMIT 1;" > "$hex" 2>>"$LOG_FILE" || rc=1
    if [[ "$rc" -eq 0 && -s "$hex" ]]; then
        "$bin" -n -d auto_prepend_file= -d auto_append_file= "$helper" own "$hex" "$owned" 2>>"$LOG_FILE" || : > "$owned"
    fi
    db_query "SELECT HEX(option_value) FROM ${OPTIONS_TABLE} WHERE option_name='sc_persist_manifest' LIMIT 1;" > "$hex" 2>>"$LOG_FILE" || rc=1
    if [[ "$rc" -eq 0 && -s "$hex" ]]; then
        "$bin" -n -d auto_prepend_file= -d auto_append_file= "$helper" persist "$hex" "$verify" 2>>"$LOG_FILE" || : > "$verify"
    fi
    rm -f -- "$helper" "$hex"

    {
        cat "$owned" 2>/dev/null || true
        awk -F'\t' 'NF>1{print $2}' "$verify" 2>/dev/null || true
    } | sort -u > "$all"

    if [[ -s "$owned" || -s "$verify" ]]; then
        sc_mark_campaign_evidence "campaign DB manifest present (sc_own_manifest/sc_persist_manifest)"
        status_line FOUND "Campaign DB manifest harvested: $(awk 'END{print NR+0}' "$owned") owned path(s), $(awk 'END{print NR+0}' "$verify") persistence entr(y/ies)"
    else
        status_line CLEAN "No campaign DB manifest present"
    fi
    return 0
}

# Decide whether one manifest-owned path may be deleted. Refusal reasons are
# recorded rather than silently skipped, because a refused owned path is itself
# something the operator needs to look at.
sc_manifest_path_is_deletable() {
    local f="$1" real base
    [[ -n "$f" && "$f" == /* ]] || { printf 'not-an-absolute-path'; return 1; }
    real="$(realpath -m -- "$f" 2>/dev/null || printf '%s' "$f")"
    case "$real" in
        "${WP_PATH%/}"/*) ;;
        *) printf 'outside-this-wordpress-tree'; return 1 ;;
    esac
    case "$real" in
        "${WP_PATH%/}"/wp-admin/*|"${WP_PATH%/}"/wp-includes/*)
            printf 'core-directory-verify-only'; return 1 ;;
    esac
    base="${real##*/}"
    case "$base" in
        wp-config.php|wp-settings.php|wp-load.php|wp-blog-header.php|wp-cron.php|index.php|.htaccess|.user.ini)
            printf 'core-or-config-file-verify-only'; return 1 ;;
    esac
    [[ -f "$real" ]] || { printf 'not-present'; return 1; }
    if ! grep -Eq "$IOC_REGEX" "$real" 2>/dev/null; then
        printf 'no-live-IOC-match'; return 1
    fi
    printf '%s' "$real"
    return 0
}

clean_manifest_paths() {
    local owned="$REPORT_DIR/sc-manifest-owned.txt"
    local refused="$REPORT_DIR/sc-manifest-refused.tsv"
    local f verdict removed=0
    : > "$refused"
    [[ -s "$owned" ]] || { status_line CLEAN "No campaign-owned manifest paths to clean"; return 0; }
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        verdict="$(sc_manifest_path_is_deletable "$f")" || {
            printf '%s\t%s\n' "$verdict" "$f" >> "$refused"
            continue
        }
        remove_high_confidence_file "$verdict" "SC-DB-manifest-owned"
        removed=$((removed+1))
    done < "$owned"
    if [[ "$removed" -gt 0 ]]; then
        log "AUTO-FIXED: removed $removed file(s) the campaign's own manifest claimed"
    else
        status_line CLEAN "No manifest-owned file required deletion"
    fi
    [[ -s "$refused" ]] && status_line REVIEW "$(awk 'END{print NR+0}' "$refused") manifest-owned path(s) were refused; see sc-manifest-refused.tsv"
    return 0
}

# Every manifest path - owned and injected alike - is checked again after
# cleanup. Injected core files are expected to survive; what must not survive is
# a live IOC inside them.
verify_sc_manifest_paths() {
    local all="$REPORT_DIR/sc-manifest-paths.txt"
    local remaining="$REPORT_DIR/sc-manifest-remaining.tsv"
    local f
    : > "$remaining"
    [[ -s "$all" ]] || return 0
    while IFS= read -r f; do
        [[ -n "$f" && -f "$f" ]] || continue
        if grep -Eq "$IOC_REGEX" "$f" 2>/dev/null; then
            printf 'ioc-remains\t%s\n' "$f" >> "$remaining"
        fi
    done < "$all"
    if [[ -s "$remaining" ]]; then
        status_line FAILED "$(awk 'END{print NR+0}' "$remaining") manifest path(s) still contain campaign IOCs; see sc-manifest-remaining.tsv"
        return 1
    fi
    status_line CLEAN "Every campaign manifest path verified free of IOCs"
    return 0
}

# Campaign strings that only ever showed up inside option VALUES in the captured
# dump: the C2 host, the reversed-slug version marker and the campaign's own cron
# schedule name. v41 matched option NAMES only, so none of these had a detector.
# LIKE is used rather than REGEXP for client portability; `_` is a LIKE wildcard,
# which can only widen a match, and this scan never deletes anything.
SC_DB_IOC_LIKES='root-cherry|eludom-etile|sc_guard_interval|sc_cron_guard|SCV:|SCOCV:|SCD1:|sc_payload_persistent|sc_cron_fetch|a18xgj672mowjoum|--sc-cli|--sc-succ|ionic-scheduler-orb|echo-compiler-plus|elite-module-cue|unity-manager-lite|__scf_|SC_CORE_BOOT_VER|sc_boot_ver|0x9A4752cA|0x839d1cE5|0x6d2c5435'

offline_scan_db_ioc_values() {
    local out="$REPORT_DIR/db-ioc-value-hits.tsv"
    local where="" tok
    local -a toks=()
    : > "$out"
    IFS='|' read -r -a toks <<< "$SC_DB_IOC_LIKES"
    for tok in "${toks[@]}"; do
        [[ -n "$tok" ]] || continue
        where+="${where:+ OR }option_value LIKE '%${tok}%'"
    done
    [[ -n "$where" ]] || return 0
    db_query "
SELECT option_id, option_name, LENGTH(option_value), LEFT(option_value,120)
FROM ${OPTIONS_TABLE}
WHERE ${where}
ORDER BY option_id;
" > "$out" 2>>"$LOG_FILE" || return 1
    if [[ -s "$out" ]]; then
        sc_mark_campaign_evidence "SC IOC string inside a WordPress option value"
        status_line FOUND "$(awk 'END{print NR+0}' "$out") option value(s) contain high-confidence SC IOC strings; see db-ioc-value-hits.tsv"
    else
        status_line CLEAN "No SC IOC strings inside WordPress option values"
    fi
    return 0
}

# Payload-store options. Evidence first, always; deletion only where the site is
# independently campaign-proven. The ABSPATH-derived name is proof in itself, so
# it is named explicitly rather than left to the shape rule.
offline_delete_hex_options() {
    local ev="$REPORT_DIR/db-hex-options-removed-evidence.tsv"
    local derived_sql deleted=0 n_hex=0 n_derived=0
    derived_sql="$(sql_escape_literal "${ROLE_DBOPT:-}")"
    : > "$ev"
    db_query "
SELECT option_id, option_name, LENGTH(option_value), autoload, MD5(option_value), HEX(LEFT(option_value,256))
FROM ${OPTIONS_TABLE}
WHERE option_name REGEXP '${DB_HEX_OPTION_REGEXP}'
   OR option_name='${derived_sql}'
ORDER BY LENGTH(option_value) DESC;
" > "$ev" 2>>"$LOG_FILE" || return 1

    if [[ ! -s "$ev" ]]; then
        status_line CLEAN "No hex-named or path-derived payload options present"
        return 0
    fi
    if [[ "${CAMPAIGN_SITE_PROVEN:-0}" -ne 1 ]]; then
        log "WARNING: hex/path-derived payload option(s) exist but this site is not campaign-proven; left in place."
        status_line REVIEW "Payload-store option candidates recorded as evidence only; site is not campaign-proven"
        return 0
    fi

    db_query "DELETE FROM ${OPTIONS_TABLE} WHERE option_name REGEXP '${DB_HEX_OPTION_REGEXP}'; SELECT ROW_COUNT();" \
        > "$REPORT_DIR/db-hex-options-delete-result.txt" 2>>"$LOG_FILE" || return 1
    n_hex="$(tail -n 1 "$REPORT_DIR/db-hex-options-delete-result.txt" | tr -dc '0-9')"; n_hex="${n_hex:-0}"

    if [[ -n "$derived_sql" ]]; then
        db_query "DELETE FROM ${OPTIONS_TABLE} WHERE option_name='${derived_sql}'; SELECT ROW_COUNT();" \
            > "$REPORT_DIR/db-derived-option-delete-result.txt" 2>>"$LOG_FILE" || return 1
        n_derived="$(tail -n 1 "$REPORT_DIR/db-derived-option-delete-result.txt" | tr -dc '0-9')"; n_derived="${n_derived:-0}"
    fi

    deleted=$(( n_hex + n_derived ))
    if [[ "$deleted" -gt 0 ]]; then
        sc_mark_campaign_evidence "payload-store option(s) deleted after evidence capture"
        log "AUTO-FIXED: deleted $deleted payload-store option row(s) (hex=$n_hex derived=$n_derived)"
        status_line FIXED "Deleted $deleted payload-store option row(s); evidence in db-hex-options-removed-evidence.tsv"
    else
        status_line CLEAN "No payload-store option rows required deletion"
    fi
    return 0
}

# active_plugins keeps campaign slugs alive in the option even after their
# directories are gone. Same isolated-PHP pattern as the cron option: PHP only
# converts between the serialized value and JSON, Bash decides what is dropped.
offline_clean_active_plugins() {
    local in_hex="$REPORT_DIR/active-plugins-before.hex"
    local out_hex="$REPORT_DIR/active-plugins-after.hex"
    local verify="$REPORT_DIR/active-plugins-verify.hex"
    local json="$REPORT_DIR/.active-plugins.json"
    local clean="$REPORT_DIR/.active-plugins-clean.json"
    local helper="$REPORT_DIR/.offline-active-plugins.php"
    local sql_file="$REPORT_DIR/.offline-active-plugins.sql"
    local bin before after

    db_query "SELECT HEX(option_value) FROM ${OPTIONS_TABLE} WHERE option_name='active_plugins' LIMIT 1;" > "$in_hex" 2>>"$LOG_FILE" || return 1
    if [[ ! -s "$in_hex" ]]; then
        status_line CLEAN "No active_plugins option is present"
        return 0
    fi
    bin="$(sc_php_serialization_bin)" || {
        log "REVIEW: No PHP >= 7 interpreter is available for the isolated active_plugins serializer."
        return 1
    }

    # As in the cron helper, no `}` may start a line: the harness would cut the
    # function short at the heredoc.
    cat > "$helper" <<'PHP'
<?php
if ($argc !== 4) exit(2);
$mode = (string)$argv[1];
if ($mode === 'tojson') {
    $hex = trim((string)@file_get_contents($argv[2]));
    $raw = @hex2bin($hex);
    if ($raw === false) exit(3);
    $v = @unserialize($raw, ['allowed_classes' => false]);
    if (!is_array($v)) exit(4);
    foreach ($v as $e) if (!is_string($e)) exit(5);
    file_put_contents($argv[3], json_encode(array_values($v)));
    exit(0);
 }
if ($mode !== 'fromjson') exit(2);
$j = @file_get_contents($argv[2]);
if ($j === false) exit(3);
$v = json_decode($j, true);
if (!is_array($v)) exit(4);
foreach ($v as $e) if (!is_string($e)) exit(5);
file_put_contents($argv[3], strtoupper(bin2hex(serialize(array_values($v)))) . "\n");
PHP
    chmod 600 "$helper"

    if ! "$bin" -n -d auto_prepend_file= -d auto_append_file= "$helper" tojson "$in_hex" "$json" 2>>"$LOG_FILE"; then
        rm -f -- "$helper"
        status_line REVIEW "active_plugins is not a plain list of plugin files; left untouched"
        return 0
    fi
    sc_filter_active_plugins_json < "$json" > "$clean"
    before="$(tr -d ' \n' < "$json")"
    after="$(tr -d ' \n' < "$clean")"
    if [[ "$before" == "$after" ]]; then
        rm -f -- "$helper" "$json" "$clean"
        status_line CLEAN "No campaign plugin entries in active_plugins"
        return 0
    fi
    if ! "$bin" -n -d auto_prepend_file= -d auto_append_file= "$helper" fromjson "$clean" "$out_hex" 2>>"$LOG_FILE"; then
        rm -f -- "$helper"
        return 1
    fi
    rm -f -- "$helper"

    {
        printf 'UPDATE `%s` SET option_value=UNHEX(%s' "$OPTIONS_TABLE" "'"
        tr -d '\r\n' < "$out_hex"
        printf "%s\n" "') WHERE option_name='active_plugins';" "SELECT ROW_COUNT();"
    } > "$sql_file"
    if ! db_query_file "$sql_file" > "$REPORT_DIR/active-plugins-update-result.txt" 2>>"$LOG_FILE"; then
        rm -f -- "$sql_file"
        return 1
    fi
    rm -f -- "$sql_file"
    db_query "SELECT HEX(option_value) FROM ${OPTIONS_TABLE} WHERE option_name='active_plugins' LIMIT 1;" > "$verify" 2>>"$LOG_FILE" || return 1
    if ! [[ "$(tr -d '\r\n' < "$verify")" == "$(tr -d '\r\n' < "$out_hex")" ]]; then
        status_line FAILED "active_plugins rewrite did not verify; see active-plugins-verify.hex"
        return 1
    fi
    sc_mark_campaign_evidence "campaign plugin entries removed from active_plugins"
    status_line FIXED "Removed campaign plugin entries from active_plugins without loading WordPress"
    return 0
}

# Read one numeric scalar. `X="$(db_query ... | tail | tr)"` fails the whole
# script under `pipefail` when the query errors, which in v33 surfaced as a fake
# "worker command failed" ERROR instead of an orderly DB-phase skip.
DB_DEGRADED=0
db_scalar() {
    local sql="$1" out
    out="$(db_query "$sql" 2>>"$LOG_FILE" | tail -n 1 | tr -dc '0-9' || true)"
    if [[ -z "$out" ]]; then
        DB_DEGRADED=1
        printf '0\n'
        return 0
    fi
    printf '%s\n' "$out"
    return 0
}

# The direct-DB phase is best-effort by design. Filesystem cleanup has already
# completed and must never be reported as failed because direct MySQL/MariaDB access is unavailable. Exit 40 = REVIEW_DB_SKIPPED.
db_fail_skip() {
    local reason="$*"
    log "REVIEW: $reason"
    {
        echo "reason=$reason"
        echo "filesystem_cleanup=completed"
        echo "database_cleanup=partial_or_skipped"
        echo "offline_followup_steps=skipped"
    } > "$REPORT_DIR/db-phase-skipped.txt" 2>/dev/null || true
    status_line REVIEW "Direct database phase incomplete for this site; account cleanup continues. See db-phase-skipped.txt."
    print_final_summary "REVIEW - DIRECT DATABASE PHASE SKIPPED"
    exit 40
}

# ---------------------------------------------------------------------------
# PHP validation. The captured SC 4.3.24 sample proved this is not optional:
# the campaign appends a guard stub ("$_sc_done = false; die( 'SC_FAIL' ); }")
# ahead of its marked block, so removing only the marked region leaves an
# unmatched brace. The infected site had logged 1067 copies of
#   PHP Parse error: Unmatched '}' in .../themes/twentytwentyfive/functions.php
# Every in-place PHP rewrite therefore has to be validated before it is kept.
# ---------------------------------------------------------------------------
SC_PHP_BIN=""
SC_PHP_BIN_RESOLVED=0
SC_PHP_BIN_MAJOR=0
# How the batched parse check may run: with -n, with the system ini, or not at
# all. ext/tokenizer is usually a shared module, and `php -n` does not load it.
SC_PHP_PARSE_MODE="none"
# Resolving the interpreter is a probe per installed PHP, and shared
# cPanel/CloudLinux boxes carry ten or more under /opt/cpanel and /opt/alt.
# v42 did the probing inside sc_php_lint_bin, whose every caller used
# `bin="$(sc_php_lint_bin)"` - a command substitution, so the SC_PHP_BIN_RESOLVED
# cache lived and died in a subshell and every file re-probed every interpreter.
# Resolution therefore happens once, at top level, and the getter only reports.
#
# SC_PHP_BIN_CANDIDATES overrides the search list; it exists so the suite can
# count how often the probe actually runs.
sc_php_resolve_bin() {
    local c ver major minor tok score best_score=-1
    local -a candidates=()
    SC_PHP_BIN_RESOLVED=1
    SC_PHP_BIN=""
    if [[ -n "${SC_PHP_BIN_CANDIDATES:-}" ]]; then
        read -r -a candidates <<< "$SC_PHP_BIN_CANDIDATES"
    else
        candidates=(/opt/cpanel/ea-php*/root/usr/bin/php /opt/alt/php*/usr/bin/php /usr/local/bin/php /usr/bin/php)
    fi
    # Never accept the first match: it can be PHP 5.x, which would falsely
    # reject modern WordPress syntax and cannot run the isolated serializers.
    for c in "${candidates[@]}"; do
        [[ -x "$c" ]] || continue
        # One probe answers both questions: which version, and whether the
        # tokenizer is reachable with -n.
        ver="$($c -n -r 'printf("%d.%d.%d", PHP_MAJOR_VERSION, PHP_MINOR_VERSION, (int)function_exists("token_get_all"));' 2>/dev/null || true)"
        [[ "$ver" =~ ^([0-9]+)\.([0-9]+)\.([01])$ ]] || continue
        major="${BASH_REMATCH[1]}"; minor="${BASH_REMATCH[2]}"; tok="${BASH_REMATCH[3]}"
        score=$((major * 100 + minor))
        if (( score > best_score )); then
            best_score=$score
            SC_PHP_BIN="$c"
            SC_PHP_BIN_MAJOR="$major"
            SC_PHP_PARSE_MODE="none"
            [[ "$tok" == 1 ]] && SC_PHP_PARSE_MODE="isolated"
        fi
    done
    # The tokenizer is what makes one-process parse checking possible. If -n
    # cannot see it, try once with the system ini: the helper still overrides
    # auto_prepend/auto_append, and it only ever reads the target files as
    # strings, never includes them.
    if [[ -n "$SC_PHP_BIN" && "$SC_PHP_PARSE_MODE" == "none" ]]; then
        ver="$("$SC_PHP_BIN" -r 'printf("%d", (int)function_exists("token_get_all"));' 2>/dev/null || true)"
        [[ "$ver" == 1 ]] && SC_PHP_PARSE_MODE="system-ini"
    fi

    if [[ -z "$SC_PHP_BIN" && -z "${SC_PHP_BIN_CANDIDATES:-}" ]]; then
        c="$(command -v php 2>/dev/null || true)"
        if [[ -n "$c" && -x "$c" ]]; then
            SC_PHP_BIN="$c"
            ver="$($c -n -r 'printf("%d", PHP_MAJOR_VERSION);' 2>/dev/null || true)"
            [[ "$ver" =~ ^[0-9]+$ ]] && SC_PHP_BIN_MAJOR="$ver"
        fi
    fi
    return 0
}

# Pure getter. Forks nothing, so it is safe in a command substitution.
sc_php_lint_bin() {
    if [[ "${SC_PHP_BIN_RESOLVED:-0}" -ne 1 ]]; then
        sc_php_resolve_bin
    fi
    [[ -n "${SC_PHP_BIN:-}" ]] && printf '%s\n' "$SC_PHP_BIN"
    return 0
}

sc_php_serialization_bin() {
    # The isolated helpers use unserialize(..., ['allowed_classes'=>false]) and
    # need PHP >= 7.0. The version was already established when the interpreter
    # was resolved, so this costs no extra process.
    local bin
    bin="$(sc_php_lint_bin)"
    [[ -n "$bin" ]] || return 1
    [[ "${SC_PHP_BIN_MAJOR:-0}" =~ ^[0-9]+$ ]] || return 1
    (( SC_PHP_BIN_MAJOR >= 7 )) || return 1
    printf '%s\n' "$bin"
}

# `php -l` parses without executing. When no PHP binary exists at all, fall back
# to a brace-balance check: it is conservative (a legitimate file with braces
# inside string literals is merely refused, never overwritten).
sc_php_syntax_ok() {
    local f="$1" bin delta
    [[ -f "$f" ]] || return 1
    bin="$(sc_php_lint_bin)"
    if [[ -n "$bin" ]]; then
        "$bin" -n -l "$f" >/dev/null 2>&1
        return $?
    fi
    delta="$(awk '{o+=gsub(/[{]/,"{"); c+=gsub(/[}]/,"}")} END{print o-c+0}' "$f" 2>/dev/null || echo 1)"
    [[ "$delta" == "0" ]]
}

# Replace target with candidate only when the result is valid PHP. Returns 1 and
# leaves the original untouched otherwise, so a site is never left unparsable by
# this cleaner.
sc_commit_cleaned_php() {
    local target="$1" candidate="$2" label="${3:-cleanup}" flags
    if ! sc_php_syntax_ok "$candidate"; then
        status_line REVIEW "Refusing $label: cleaned candidate for $target is not valid PHP; original left untouched"
        printf '%s\t%s\n' "$target" "$label" >> "$REPORT_DIR/php-validation-failed.tsv" 2>/dev/null || true
        return 1
    fi
    flags="$(lsattr -d "$target" 2>/dev/null | awk '{print $1}' | head -n1 || true)"
    chattr -ia -- "$target" 2>/dev/null || true
    if ! cat "$candidate" > "$target" 2>/dev/null; then
        status_line FAILED "Could not write cleaned file: $target"
        return 1
    fi
    [[ "$flags" == *i* ]] && chattr +i -- "$target" 2>/dev/null || true
    [[ "$flags" == *a* ]] && chattr +a -- "$target" 2>/dev/null || true
    return 0
}

# Drop a trailing campaign guard stub left behind once the marked block is gone.
# Only removed when every line from the first `$_sc_*` assignment to EOF is
# campaign residue; otherwise the file is left alone for the IOC gate to flag.
sc_strip_trailing_sc_stub() {
    awk '
        { line[NR] = $0 }
        END {
            start = 0
            for (i = 1; i <= NR; i++) {
                if (line[i] ~ /^[[:space:]]*\$_sc_(done|lock|files|base)[[:space:]]*=/) { start = i; break }
            }
            last = NR
            if (start > 0) {
                ok = 1
                for (i = start; i <= NR; i++) {
                    l = line[i]
                    if (l ~ /^[[:space:]]*$/) continue
                    if (l ~ /^[[:space:]]*\$_sc_[A-Za-z0-9_]+[[:space:]]*=/) continue
                    if (l ~ /die[[:space:]]*\([[:space:]]*.?SC_[A-Z_]+.?[[:space:]]*\)/) continue
                    if (l ~ /^[[:space:]]*[})];?[[:space:]]*$/) continue
                    if (l ~ /^[[:space:]]*\?>[[:space:]]*$/) continue
                    ok = 0; break
                }
                if (ok) last = start - 1
            }
            for (i = 1; i <= last; i++) print line[i]
        }
    '
}

# thb_/thv_<hex>.bak are copies the campaign kept of the files it replaced. In
# the captured sample they were byte-identical to the cache plugin's db.php and
# object-cache.php drop-ins and to the theme's functions.php. They are reported
# as evidence and never restored from: the stored theme copy already contained
# the campaign's broken guard stub.
scan_sc_stored_originals() {
    local wc="$WP_PATH/wp-content"
    [[ -d "$wc" ]] || return 0
    find "$wc" -type f -regextype posix-extended \
        -regex '.*/th[bv]_[[:xdigit:]]{8,40}\.bak' -print 2>/dev/null | sort -u || true
}

report_sc_stored_originals() {
    local out="$REPORT_DIR/sc-stored-originals.tsv" f
    : > "$out"
    while IFS= read -r f; do
        [[ -n "$f" && -f "$f" ]] || continue
        printf '%s\t%s\t%s\n' "$(wc -c < "$f" 2>/dev/null || echo 0)" \
            "$(md5sum "$f" 2>/dev/null | awk '{print $1}')" "$f" >> "$out"
    done < <(scan_sc_stored_originals)
    if [[ -s "$out" ]]; then
        status_line REVIEW "Campaign kept copies of the files it replaced; listed in sc-stored-originals.tsv (evidence only, not restored automatically)"
        sc_mark_campaign_evidence "campaign stored-original archive present"
    fi
    return 0
}

# error_log is evidence, not persistence. It is deliberately excluded from the
# IOC gate, but it carries the infection timeline, so harvest it explicitly.
harvest_error_log_evidence() {
    local out="$REPORT_DIR/error-log-campaign-evidence.txt" f hits
    : > "$out"
    while IFS= read -r -d '' f; do
        grep -aHnE 'SC_FAIL|sc_cron_fetch|sc_payload|elite-module-cue|unity-manager-lite|echo-compiler-plus|ionic-scheduler-orb|SCV:4\.|SCD1:|SCOCV:|/\.sc_[[:xdigit:]]+|PHP Parse error|PHP Fatal error' \
            "$f" 2>/dev/null | tail -n 200 >> "$out" 2>/dev/null || true
    done < <(find "$WP_PATH" -maxdepth 4 -type f \( -name 'error_log' -o -name 'error_log.*' \) -print0 2>/dev/null || true)
    if [[ -s "$out" ]]; then
        hits="$(awk 'END{print NR+0}' "$out")"
        status_line REVIEW "Harvested $hits campaign/parse-error line(s) from error_log: $out"
        if grep -qE 'SC_FAIL|sc_cron_fetch|elite-module-cue|unity-manager-lite|echo-compiler-plus|SCV:4\.|SCD1:' "$out" 2>/dev/null; then
            sc_mark_campaign_evidence "campaign traces in error_log"
        fi
    fi
    return 0
}

# The campaign truncates configuration files and, in the captured sample, left
# the active theme unparsable. Report the damage so it can be restored from a
# known-good source rather than silently shipped as "clean".
# Parse-check a NUL-separated list of files in ONE interpreter, printing the
# ones that do not parse. token_get_all(..., TOKEN_PARSE) runs the real parser
# and raises ParseError on bad syntax, without executing a single line of the
# file - the same guarantee `php -l` gives, at one process instead of one per
# file. The single-file `php -l` gate in sc_php_syntax_ok is deliberately left
# alone: it decides whether a rewritten file may be committed, and that path is
# rare and safety-critical.
sc_php_parse_check_many() {
    local list="$1" bin helper
    local -a phpargs=()
    bin="$(sc_php_lint_bin)"
    [[ -n "$bin" && "${SC_PHP_BIN_MAJOR:-0}" -ge 7 ]] || return 2
    case "${SC_PHP_PARSE_MODE:-none}" in
        isolated)   phpargs=(-n -d auto_prepend_file= -d auto_append_file=) ;;
        system-ini) phpargs=(-d auto_prepend_file= -d auto_append_file=) ;;
        *)          return 2 ;;
    esac
    helper="$REPORT_DIR/.php-parse-check.php"
    cat > "$helper" <<'PHP'
<?php
$list = (string)@file_get_contents($argv[1]);
if ($list === '') exit(0);
foreach (explode("\0", $list) as $f) {
    if ($f === '') continue;
    $src = @file_get_contents($f);
    if ($src === false) continue;
    try {
        @token_get_all($src, TOKEN_PARSE);
     } catch (Throwable $e) {
        echo $f, "\n";
     }
 }
PHP
    chmod 600 "$helper"
    "$bin" "${phpargs[@]}" "$helper" "$list" 2>/dev/null
    local rc=$?
    rm -f -- "$helper"
    return "$rc"
}

report_collateral_damage() {
    local out="$REPORT_DIR/collateral-damage.txt" f sz
    : > "$out"
    for f in "$WP_PATH/.user.ini" "$WP_PATH/wp-content/.user.ini" \
             "$WP_PATH/.htaccess" "$WP_PATH/wp-content/.htaccess"; do
        [[ -f "$f" ]] || continue
        sz="$(wc -c < "$f" 2>/dev/null || echo 999)"
        [[ "$sz" -le 1 ]] || continue
        printf 'blanked-config\t%s\n' "$f" >> "$out"
    done
    # Empty files are a size test, so let find(1) answer that in the same walk
    # rather than forking wc(1) per file.
    find "$WP_PATH/wp-content/themes" "$WP_PATH/wp-content/plugins" "$WP_PATH/wp-content/mu-plugins" \
        -maxdepth 2 -type f -name '*.php' -size -2c -print 2>/dev/null \
        | sed 's/^/empty-php\t/' >> "$out" || true

    local list="$REPORT_DIR/.collateral-candidates.nul"
    find "$WP_PATH/wp-content/themes" "$WP_PATH/wp-content/plugins" "$WP_PATH/wp-content/mu-plugins" \
        -maxdepth 2 -type f -name '*.php' ! -size -2c -print0 2>/dev/null > "$list" || true
    if [[ -s "$list" ]]; then
        if sc_php_parse_check_many "$list" | sed 's/^/unparsable-php\t/' >> "$out"; then :; else
            # No usable interpreter: fall back to the per-file gate so the
            # report is never silently empty.
            while IFS= read -r -d '' f; do
                sc_php_syntax_ok "$f" || printf 'unparsable-php\t%s\n' "$f" >> "$out"
            done < "$list"
        fi
    fi
    rm -f -- "$list"
    if [[ -s "$out" ]]; then
        status_line REVIEW "Campaign collateral damage detected; see collateral-damage.txt"
        sed -n '1,10p' "$out" | sed 's/^/    /' | tee -a "$LOG_FILE" >/dev/null 2>&1 || true
    fi
    return 0
}

sql_escape_literal() {
    # Only used for locally generated values, never arbitrary DB content.
    printf '%s' "$1" | sed "s/'/''/g"
}

ABSPATH="${WP_PATH%/}/"
ROLE_LDR="$(printf '%s' "${ABSPATH}ldr" | md5sum | awk '{print substr($1,1,8)}')"
ROLE_ZIP="$(printf '%s' "${ABSPATH}zip" | md5sum | awk '{print substr($1,1,8)}')"
ROLE_INST="$(printf '%s' "${ABSPATH}inst" | md5sum | awk '{print substr($1,1,8)}')"
ROLE_SW="$(printf '%s' "${ABSPATH}sw" | md5sum | awk '{print substr($1,1,8)}')"
ROLE_DBOPT="$(printf '%s' "${ABSPATH}opt" | md5sum | awk '{print substr($1,1,10)}')"
ROLE_TH="$(printf '%s' "${ABSPATH}th_m" | md5sum | awk '{print substr($1,1,8)}')"

IOC_REGEX='SC_DB_BEGIN|SC_DB_END|SC_ADV_BEGIN|SC_ADV_END|SC_OC_BEGIN|SC_OC_END|SCOCV:|SCV:[0-9]+\.|SC_DD_BEGIN|SC_DD_END|SC_TH_BEGIN|SC_TH_END|SC_TH_LD_|SCD1:|sc_payload_persistent|sc_payload_t|sc_cron_fetch|a18xgj672mowjoum|0x3bc5de30|/\.sc_[[:xdigit:]]+|\.gr_[[:xdigit:]]{32}\.php|\.grd_[[:xdigit:]]{8,40}|--sc-cli|--sc-succ|echo-compiler-plus|elite-module-cue|unity-manager-lite|\.wp-object-cache-[[:xdigit:]]{8,32}\.dat(\.lkg)?|\.(bt|sd|rd|q)_elite-module-cue|\.kk_[[:xdigit:]]{6,40}|\$_sc_done|\$_sc_lock|\$_sc_files|goto[[:space:]]+_sc_end|SC_FAIL|_sc_(padf|ul|coreld|corep|fpc|mkdir|unp|qok|aw|any_live|phpok_src|src)[[:space:]]*\(|static[[:space:]]*\$a=null;[[:space:]]*if[[:space:]]*\([[:space:]]*\$a===null[[:space:]]*\)[[:space:]]*\{[[:space:]]*\$a=array_merge\(array\(|/th[bv]_[[:xdigit:]]{8,40}\.bak|"gen":"[[:xdigit:]]{8,16}"|root-cherry|php\.euc-eludom-etile|sc_guard_interval|__scf_[A-Za-z0-9_]{6,}|SC_CORE_BOOT_VER|sc_boot_ver|SC_COVER_HOOKS|SC_AUTO_PREPEND|SC_DP_BEGIN|SC_DP_END|sc_cron_guard|/\.(sd|bt|swm|q|rd)_[A-Za-z0-9][A-Za-z0-9._-]{5,}|/\.mu_st_[A-Za-z0-9]{4,}|\.php\.scold[0-9]{3,}|0x9A4752cAA1C15868487A0ACb691F81bfA901E063|0x839d1cE5c3F259e8d3D17114d7186EDabdbeA94b|0x6d2c5435EF70196740a48904B69377935D50abBB'

# Legitimate software that ships its own `sc_`-prefixed names. ThemeREX Addons
# (`trx_addons`) and the themes bundling it name shortcodes, files and options
# `sc_*`, which collides with the campaign's family prefix. The allowlist may
# only ever suppress WEAK signals: a file inside an allowlisted path that also
# carries a decisive campaign marker is still treated as malicious, and known
# campaign option names are never spared. Extend per run with SC_EXTRA_LEGIT_RE.
SC_LEGIT_PATH_RE='(^|/)(trx_addons|trx-addons)(/|$)'

# Markers that settle the question on their own. Anything here outweighs the
# allowlist; everything else the IOC regex matches counts as a weak signal.
SC_DECISIVE_RE='SCV:[[:space:]]*[0-9]+\.|__scf_[A-Za-z0-9_]{6,}|SC_CORE_BOOT_VER|sc_boot_ver|SC_(TH|OC|DD|ADV|DB|DP)_(BEGIN|END)|SCOCV:|SCD1:|--sc-(cli|succ)|ionic-scheduler-orb|echo-compiler-plus|elite-module-cue|unity-manager-lite'

sc_legit_path_re() {
    if [[ -n "${SC_EXTRA_LEGIT_RE:-}" ]]; then
        printf '%s|%s' "$SC_LEGIT_PATH_RE" "$SC_EXTRA_LEGIT_RE"
    else
        printf '%s' "$SC_LEGIT_PATH_RE"
    fi
}

sc_path_is_legit() {
    # Bash's own matcher, not `printf | grep -q`: an early-exit grep on the far
    # side of a pipe is exactly the SIGPIPE trap this script bans everywhere.
    local p="$1" re
    [[ -n "$p" ]] || return 1
    re="$(sc_legit_path_re)"
    [[ "$p" =~ $re ]]
}

sc_file_is_decisive() {
    local f="$1"
    [[ -f "$f" ]] || return 1
    grep -Eq --binary-files=without-match "$SC_DECISIVE_RE" "$f" 2>/dev/null
}

# Filter `path:line:text` IOC hits. A hit inside allowlisted software is dropped
# only when that file carries no decisive marker, and every drop is recorded -
# an exclusion that leaves no trace in the report is a detection hole.
sc_filter_legit_ioc_lines() {
    local line f
    local -A verdict=()
    while IFS= read -r line; do
        f="${line%%:*}"
        if [[ -n "$f" ]] && sc_path_is_legit "$f"; then
            if [[ -z "${verdict[$f]:-}" ]]; then
                if sc_file_is_decisive "$f"; then verdict[$f]=keep; else verdict[$f]=drop; fi
            fi
            if [[ "${verdict[$f]}" == "drop" ]]; then
                printf '%s\n' "$line" >> "${REPORT_DIR:-/tmp}/legit-excluded.txt" 2>/dev/null || true
                continue
            fi
        fi
        printf '%s\n' "$line"
    done
    return 0
}


# Vocabulary that appears in legitimate WordPress/plugin cron hook names. The
# campaign's randomized hooks are shapeless strings; a hook that carries any of
# these words is left alone even when its shape matches. Deliberately contains
# no token shorter than three characters and no token that occurs inside a known
# campaign hook - `wp`, for example, is a substring of `zvdcgmrr7smxjwpo_ky`.
SC_HOOK_WORDS='cron|schedul|clean|update|delete|remov|sync|check|daily|weekly|hourly|transient|session|backup|mail|queue|licen|health|sitemap|cache|import|export|admin|user|post|media|plugin|theme|event|task|heartbeat|ping|fetch|scan|report|notify|digest|summar|renew|expir|woo|commerce|jetpack|yoast|elementor|action|aioseo|wpforms|mailpoet|wpseo|sales|order|product|comment|upgrade|install|stats|analytic|newslet|subscri|payment|invoice|thumb|optimi|migrat|monitor|secur|firewall|malware|revision|autosave|draft|feed|search|index|cdn|smtp'

# Randomized WP-Cron hooks observed in captured samples. These are IOCs on their
# own; `zvdcgmrr7smxjwpo_ky` is the one the 4.3.24 sample scheduled, and it is
# why the rule cannot be a bare lowercase-alnum character class.
SC_KNOWN_CRON_HOOKS='sc_cron_guard|r1ckj5tjyx1yjm|e1pw88l550vjcok7s5pcd|zriwi3se0yfj7u8n|zvdcgmrr7smxjwpo_ky'

# Campaign plugin slugs, used both for path removal and for active_plugins.
SC_CAMPAIGN_PLUGIN_SLUGS='ionic-scheduler-orb|echo-compiler-plus|elite-module-cue|unity-manager-lite'

# Bare payload-store option names. Deleted only on a campaign-proven site and
# only after their name/length/md5/first 256 bytes are recorded as evidence.
DB_HEX_OPTION_REGEXP='^[a-f0-9]{8,12}$'

# Read hook names on stdin, print the ones that look like campaign hooks.
#
# Shape alone is not enough and never was: the captured site scheduled
# `zvdcgmrr7smxjwpo_ky`, which carries an underscore and a single digit. A pure
# `^[a-z0-9]{12,32}$` test therefore misses the real sample while still being
# broad enough to hit a legitimate hook, which is why the vocabulary check and
# the caller's orphan check both exist.
sc_filter_random_cron_hooks() {
    local hook digits letters
    while IFS= read -r hook; do
        hook="${hook%$'\r'}"
        [[ -n "$hook" ]] || continue
        if [[ "$hook" =~ ^(${SC_KNOWN_CRON_HOOKS})$ ]]; then
            printf '%s\n' "$hook"
            continue
        fi
        (( ${#hook} >= 12 && ${#hook} <= 32 )) || continue
        # At most one trailing `_<suffix>` segment; real hooks use several.
        [[ "$hook" =~ ^[a-z0-9]+(_[a-z0-9]{1,8})?$ ]] || continue
        if [[ "$hook" =~ (${SC_HOOK_WORDS}) ]]; then
            continue
        fi
        digits="${hook//[^0-9]/}"
        letters="${hook//[^a-z]/}"
        (( ${#digits} >= 1 && ${#letters} >= 4 )) || continue
        printf '%s\n' "$hook"
    done
    return 0
}

# Answer the orphan question for a whole set of hook names in ONE traversal:
# read names on stdin, print the ones that occur somewhere under the WordPress
# tree. Anything not printed is an orphan. The single-hook helper below is kept
# for one-off lookups, but the cron cleanup uses this instead of walking the
# tree once per candidate.
sc_cron_hooks_referenced_on_disk() {
    local tmp
    tmp="$(mktemp "${REPORT_DIR:-/tmp}/.cron-hook-names.XXXXXX")" || return 1
    sort -u > "$tmp"
    if [[ ! -s "$tmp" ]]; then
        rm -f -- "$tmp"
        return 0
    fi
    grep -rhoFf "$tmp" --binary-files=without-match -- "$WP_PATH" 2>/dev/null | sort -u || true
    rm -f -- "$tmp"
    return 0
}

# A hook name that still appears somewhere on disk belongs to installed code,
# however random it looks. Only an orphan - referenced by no file under the
# WordPress tree after filesystem cleanup - may be deleted from the cron option.
sc_cron_hook_is_orphaned() {
    local hook="$1"
    [[ -n "$hook" ]] || return 1
    if grep -rlF --binary-files=without-match -- "$hook" "$WP_PATH" >/dev/null 2>&1; then
        return 1
    fi
    return 0
}

# Filter a JSON array of "slug/file.php" plugin entries, dropping the campaign
# families. Input and output are the same escaped JSON form, so the caller can
# hand the result straight back to the serializer.
sc_filter_active_plugins_json() {
    local raw tok out="" first=1
    raw="$(cat)"
    while IFS= read -r tok; do
        [[ -n "$tok" ]] || continue
        if [[ "$tok" =~ (${SC_CAMPAIGN_PLUGIN_SLUGS}) ]]; then
            continue
        fi
        if (( first )); then out="$tok"; first=0; else out="${out},${tok}"; fi
    done < <(printf '%s' "$raw" | grep -o '"[^"]*"' || true)
    printf '[%s]\n' "$out"
    return 0
}

scan_g_files() {
    find "$WP_PATH" -type f -iname '.g_*.php' -print 2>/dev/null || true
}

scan_sc_runtime_paths() {
    local wc="$WP_PATH/wp-content" d f
    [[ -d "$wc" ]] || return 0
    while IFS= read -r -d '' d; do
        [[ "${d##*/}" =~ ^\.sc_[[:xdigit:]]{6,40}$ ]] || continue
        f="$(find "$d" -maxdepth 1 -type f -regextype posix-extended -regex '.*/\.gr_[[:xdigit:]]{16,64}\.php' -print -quit 2>/dev/null || true)"
        if [[ -z "$f" ]]; then
            # `break` inside the reader can SIGPIPE find(1); with `pipefail` that
            # would fail the assignment and abort the whole run.
            f="$(find "$d" -maxdepth 1 -type f \( -name 'own_*.php' -o -name 'core_*.php' -o -name '.grd_*' \) -print 2>/dev/null | {
                    while IFS= read -r candidate; do
                        if grep -Eq 'elite-module-cue|unity-manager-lite|SCOCV:|SCV:[0-9]+\.|SC_OC_|SC_DD_|SC_DP_|--sc-cli|--sc-succ|__scf_[A-Za-z0-9_]{6,}|SC_CORE_BOOT_VER' "$candidate" 2>/dev/null; then
                            printf '%s\n' "$candidate"; break
                        fi
                    done
                    cat >/dev/null
                  } || true)"
        fi
        if [[ -z "$f" ]]; then
            local state_count core_count own_count grd_count
            state_count="$(find "$d" -maxdepth 1 \( -type f -o -type d \) -regextype posix-extended -regex '.*/\.(gk|gl|gm|gp|gs|gt|gv)_[[:xdigit:]]{8,40}(\.d)?' -printf x 2>/dev/null | wc -c)"
            core_count="$(find "$d" -maxdepth 1 -type f -name 'core_*.php' -printf x 2>/dev/null | wc -c)"
            own_count="$(find "$d" -maxdepth 1 -type f -name 'own_*.php' -printf x 2>/dev/null | wc -c)"
            grd_count="$(find "$d" -maxdepth 1 -type f -name '.grd_*' -printf x 2>/dev/null | wc -c)"
            if (( state_count >= 3 && core_count >= 1 && own_count >= 1 && grd_count >= 1 )); then
                f="$d/.sc-structure-confirmed"
            fi
        fi
        [[ -n "$f" ]] || continue
        printf '%s\n%s\n' "$d" "$f"
    done < <(find "$wc" -mindepth 1 -maxdepth 1 -type d -name '.sc_*' -print0 2>/dev/null || true)
}

scan_loose_gr_runners() {
    local f bn proven=0
    if [[ "${SC_PREVIOUS_CAMPAIGN_EVIDENCE:-0}" -eq 1 || "${CAMPAIGN_EVIDENCE_RECORDED:-0}" -eq 1 ]]; then
        proven=1
    fi
    while IFS= read -r -d '' f; do
        [[ -f "$f" ]] || continue
        bn="${f##*/}"
        [[ "$bn" =~ ^\.gr_[[:xdigit:]]{32}\.php$ ]] || continue
        if grep -Fq -- '--sc-cli' "$f" 2>/dev/null && grep -Fq -- '--sc-succ' "$f" 2>/dev/null; then
            printf '%s\n' "$f"
            continue
        fi
        # The captured sample carried a 0-byte .gr_<32hex>.php runner. On a site
        # with independent campaign proof the exact name is evidence enough.
        [[ "$proven" -eq 1 ]] || continue
        printf '%s\n' "$f"
    done < <(find "$WP_PATH" -type f -name '.gr_*.php' -print0 2>/dev/null || true)
}

scan_sc_state_clusters() {
    # One directory pass, as in the account-wide scanner. The v33 worker copy
    # rescanned wp-content once per candidate token, which was O(n^2) and very
    # expensive while the account guard was also walking the tree.
    local wc="$WP_PATH/wp-content" p bn token
    [[ -d "$wc" ]] || return 0
    declare -A sc_state_count=()
    declare -A sc_state_paths=()
    while IFS= read -r -d '' p; do
        bn="${p##*/}"
        if [[ "$bn" =~ ^\.(gk|gl|gm|gp|gs|gt|gv)_([[:xdigit:]]{8,40})(\.d)?$ ]]; then
            token="${BASH_REMATCH[2]}"
            sc_state_count["$token"]=$(( ${sc_state_count["$token"]:-0} + 1 ))
            sc_state_paths["$token"]+="${p}"$'\n'
        fi
    done < <(find "$wc" -mindepth 1 -maxdepth 1 \( -type f -o -type d \) -name '.*_*' -print0 2>/dev/null || true)

    # State/lock artifacts are only high-confidence as a cluster of >=3 files
    # sharing one token; a lone .gk_<hex> is not enough to auto-delete.
    for token in "${!sc_state_count[@]}"; do
        if (( sc_state_count["$token"] >= 3 )); then
            printf '%s' "${sc_state_paths["$token"]}"
        fi
    done | sort -u
}

scan_scv_wp_content_php() {
    # One grep over the whole candidate set instead of one fork per file. This
    # scan runs in the preflight, the per-site checkpoint, the verification, the
    # reinfection watch and the guard's periodic sweep, so the per-file fork was
    # multiplied many times over on every run.
    local wc="$WP_PATH/wp-content"
    [[ -d "$wc" ]] || return 0
    find "$wc" -type f -iname '*.php' -print0 2>/dev/null \
        | xargs -0 -r grep -liE --binary-files=without-match 'SCV:[[:space:]]*[0-9]+(\.[0-9]+){1,3}' 2>/dev/null \
        | sort -u || true
}

# See the account-wide twin in the coordinator half: the 4.5.3 generation is
# detectable by its `__scf_` pointer table and boot guard, not by campaign text.
scan_obf_loader_php() {
    local wc="$WP_PATH/wp-content"
    [[ -d "$wc" ]] || return 0
    find "$wc" -type f -iname '*.php' -print0 2>/dev/null \
        | xargs -0 -r grep -lE --binary-files=without-match '__scf_[A-Za-z0-9_]{6,}|SC_CORE_BOOT_VER|sc_boot_ver|SC_COVER_HOOKS|SC_AUTO_PREPEND|SC_DP_(BEGIN|END):' 2>/dev/null \
        | sort -u || true
}

scan_ioc_lines() {
    # PHP warnings/notices may echo IOC strings into WordPress error_log files.
    # Those are evidence/logging artifacts, not executable persistence, so exclude
    # files named error_log (and rotated error_log.* files) from the filesystem gate.
    # Campaign code observed so far lives in PHP/PHTML/PHAR, .user.ini or
    # .htaccess, or in small backup-like text files. Restricting the candidate
    # set keeps this gate identical to the account-wide gate and avoids false
    # positives from security-plugin signature databases, SQL dumps and large
    # media/cache trees that merely quote an IOC string.
    find "$WP_PATH" -type f -size -32M \( \
            -iname '*.php' -o -iname '*.phtml' -o -iname '*.phar' \
            -o -iname '*.bak' -o -name '.user.ini' -o -name '.htaccess' \
        \) ! -name 'error_log' ! -name 'error_log.*' -print0 2>/dev/null \
        | xargs -0 -r grep -HnE --binary-files=without-match "$IOC_REGEX" 2>/dev/null \
        | sc_filter_legit_ioc_lines || true
}

scan_watermark() {
    find "$WP_PATH" -type f -name '*.php' -printf '%T@ %p\n' 2>/dev/null \
        | awk '{if (int($1) % 100000 == 93819) print $2}' || true
}

scan_auto_prepend() {
    # Include WordPress tree and immediate parent/home PHP config locations.
    local candidates=(
        "$WP_PATH/.user.ini"
        "$WP_PATH/.htaccess"
        "$WP_PATH/php.ini"
        "$WP_PATH/wp-content/.user.ini"
        "$WP_PATH/wp-content/.htaccess"
        "$WP_PATH/wp-content/php.ini"
        "$(dirname "$WP_PATH")/.user.ini"
        "$(dirname "$WP_PATH")/.htaccess"
        "$USER_HOME/.user.ini"
        "$USER_HOME/php.ini"
    )
    local f
    for f in "${candidates[@]}"; do
        [[ -f "$f" ]] || continue
        grep -HnEi 'auto_prepend_file' "$f" 2>/dev/null || true
    done
}

scan_malware_processes() {
    pgrep -afu "$CPUSER" '\.g_[[:xdigit:]]+\.php|/wp-content/\.sc_[[:xdigit:]]+/\.gr_[[:xdigit:]]+\.php|/\.gr_[[:xdigit:]]{32}\.php|/wp-content/(plugins|mu-plugins)/(elite-module-cue|unity-manager-lite)([^/]*/|/)' 2>/dev/null || true
}

kill_malware_processes() {
    local before
    before="$(scan_malware_processes)"
    if [[ -n "$before" ]]; then
        printf '%s\n' "$before" >> "$REPORT_DIR/g-processes-killed.txt"
        pkill -9 -u "$CPUSER" -f '/\.g_[[:xdigit:]]+\.php|/wp-content/\.sc_[[:xdigit:]]+/\.gr_[[:xdigit:]]+\.php|/\.gr_[[:xdigit:]]{32}\.php|/wp-content/(plugins|mu-plugins)/(elite-module-cue|unity-manager-lite)([^/]*/|/)' 2>/dev/null || true
        sleep 1
    fi
}

scan_ionic_paths() {
    local plugins_dir="$WP_PATH/wp-content/plugins"
    if [[ -d "$plugins_dir" ]]; then
        find "$plugins_dir" -mindepth 1 -maxdepth 1 -type d -name 'ionic-scheduler-orb*' -print 2>/dev/null || true
    fi
    [[ -f "$WP_PATH/wp-content/mu-plugins/ionic-scheduler-orb.php" ]] && printf '%s\n' "$WP_PATH/wp-content/mu-plugins/ionic-scheduler-orb.php"
    return 0
}

scan_echo_compiler_paths() {
    local p
    for p in \
        "$WP_PATH/wp-content/plugins/echo-compiler-plus" \
        "$WP_PATH/wp-content/mu-plugins/echo-compiler-plus" \
        "$WP_PATH/wp-content/mu-plugins/echo-compiler-plus.php"; do
        if [[ -e "$p" ]]; then
            printf '%s\n' "$p"
        fi
    done
    return 0
}

remove_echo_compiler_plus() {
    local p removed=0
    : > "$REPORT_DIR/echo-compiler-plus-found.txt"
    : > "$REPORT_DIR/echo-compiler-plus-removed.txt"
    : > "$REPORT_DIR/echo-compiler-plus-remaining.txt"
    while IFS= read -r p; do
        if [[ ! -e "$p" ]]; then
            continue
        fi
        printf '%s\n' "$p" >> "$REPORT_DIR/echo-compiler-plus-found.txt"
        status_line FOUND "Confirmed malicious echo-compiler-plus path: $p"
        sc_mark_campaign_evidence "echo-compiler-plus path: $p"
        preserve_evidence_path "$p" "echo-compiler-plus"
        chattr -R -ia -- "$p" 2>/dev/null || true
        if rm -rf -- "$p" 2>/dev/null; then
            printf '%s\n' "$p" >> "$REPORT_DIR/echo-compiler-plus-removed.txt"
            removed=$((removed+1))
            status_line FIXED "Removed malicious echo-compiler-plus path: $p"
        else
            status_line FAILED "Could not remove malicious echo-compiler-plus path: $p"
        fi
    done < <(scan_echo_compiler_paths)
    scan_echo_compiler_paths > "$REPORT_DIR/echo-compiler-plus-remaining.txt"
    [[ -s "$REPORT_DIR/echo-compiler-plus-remaining.txt" ]] && status_line FAILED "echo-compiler-plus remains after deletion attempt"
    [[ "$removed" -eq 0 ]] && status_line CLEAN "echo-compiler-plus plugin/MU-plugin path not present"
    return 0
}

scan_elite_module_cue_paths() {
    local p
    for p in \
        "$WP_PATH/wp-content/plugins/elite-module-cue" \
        "$WP_PATH/wp-content/mu-plugins/elite-module-cue" \
        "$WP_PATH/wp-content/mu-plugins/elite-module-cue.php" \
        "$WP_PATH/wp-content/plugins/unity-manager-lite" \
        "$WP_PATH/wp-content/mu-plugins/unity-manager-lite" \
        "$WP_PATH/wp-content/mu-plugins/unity-manager-lite.php"; do
        if [[ -e "$p" ]]; then
            printf '%s\n' "$p"
        fi
    done
}

remove_elite_module_cue() {
    local p removed=0
    : > "$REPORT_DIR/elite-module-cue-found.txt"
    : > "$REPORT_DIR/elite-module-cue-removed.txt"
    : > "$REPORT_DIR/elite-module-cue-remaining.txt"
    while IFS= read -r p; do
        if [[ ! -e "$p" ]]; then
            continue
        fi
        printf '%s\n' "$p" >> "$REPORT_DIR/elite-module-cue-found.txt"
        status_line FOUND "Confirmed malicious campaign plugin persistence: $p"
        sc_mark_campaign_evidence "campaign plugin persistence: $p"
        preserve_evidence_path "$p" "elite-module-cue"
        chattr -R -ia -- "$p" 2>/dev/null || true
        if rm -rf -- "$p" 2>/dev/null; then
            printf '%s\n' "$p" >> "$REPORT_DIR/elite-module-cue-removed.txt"
            removed=$((removed+1))
            status_line FIXED "Removed malicious campaign plugin path: $p"
        else
            status_line FAILED "Could not remove malicious campaign plugin path: $p"
        fi
    done < <(scan_elite_module_cue_paths)
    scan_elite_module_cue_paths > "$REPORT_DIR/elite-module-cue-remaining.txt"
    [[ -s "$REPORT_DIR/elite-module-cue-remaining.txt" ]] && status_line FAILED "elite-module-cue/unity-manager-lite remains after deletion attempt"
    [[ "$removed" -eq 0 ]] && status_line CLEAN "elite-module-cue/unity-manager-lite plugin/MU-plugin path not present"
    return 0
}

scan_tmp_sc_locks() {
    find /tmp -maxdepth 1 -user "$CPUSER" -type f -regextype posix-extended -regex '/tmp/\.sc_[[:xdigit:]]{32}' -print 2>/dev/null || true
}

remove_tmp_sc_locks() {
    local p removed=0
    : > "$REPORT_DIR/tmp-sc-locks-removed.txt"
    while IFS= read -r p; do
        [[ -f "$p" ]] || continue
        # Only current cPanel user's exact 32-hex .sc_ locks are eligible.
        chattr -ia -- "$p" 2>/dev/null || true
        if rm -f -- "$p" 2>/dev/null; then
            printf '%s\n' "$p" >> "$REPORT_DIR/tmp-sc-locks-removed.txt"
            removed=$((removed+1))
        fi
    done < <(scan_tmp_sc_locks)
    [[ "$removed" -gt 0 ]] && status_line FIXED "Removed $removed user-owned /tmp/.sc_<md5> lock file(s)" || true
    return 0
}

scan_ionic_processes() {
    pgrep -afu "$CPUSER" '/wp-content/plugins/ionic-scheduler-orb[^/]*/|/wp-content/mu-plugins/ionic-scheduler-orb\.php' 2>/dev/null || true
}

remove_ionic_scheduler_orb() {
    : > "$REPORT_DIR/ionic-plugin-found.txt"
    : > "$REPORT_DIR/ionic-plugin-removed.txt"
    : > "$REPORT_DIR/ionic-processes-killed.txt"
    : > "$REPORT_DIR/ionic-plugin-remaining.txt"

    local procs
    procs="$(scan_ionic_processes)"
    if [[ -n "$procs" ]]; then
        printf '%s\n' "$procs" > "$REPORT_DIR/ionic-processes-killed.txt"
        status_line FOUND "Running ionic-scheduler-orb process(es) detected"
        sc_mark_campaign_evidence "running ionic-scheduler-orb process"
        pkill -9 -u "$CPUSER" -f '/wp-content/plugins/ionic-scheduler-orb[^/]*/|/wp-content/mu-plugins/ionic-scheduler-orb\.php' 2>/dev/null || true
        sleep 1
        status_line FIXED "Stopped ionic-scheduler-orb process(es)"
    fi

    mapfile -t ionic_paths < <(scan_ionic_paths)
    if [[ ${#ionic_paths[@]} -eq 0 ]]; then
        status_line CLEAN "ionic-scheduler-orb plugin/MU-plugin path not present"
        return 0
    fi

    printf '%s\n' "${ionic_paths[@]}" > "$REPORT_DIR/ionic-plugin-found.txt"
    status_line FOUND "ionic-scheduler-orb detected in ${#ionic_paths[@]} confirmed malicious path(s)"

    local d
    for d in "${ionic_paths[@]}"; do
        case "$d" in
            "$WP_PATH/wp-content/plugins/ionic-scheduler-orb"|"$WP_PATH/wp-content/plugins/ionic-scheduler-orb-"*|"$WP_PATH/wp-content/mu-plugins/ionic-scheduler-orb.php") ;;
            *)
                status_line REVIEW "Refusing unexpected ionic path outside strict confirmed patterns: $d"
                continue
                ;;
        esac
        if [[ -f "$d" ]]; then
            preserve_evidence_file "$d" "ionic-scheduler-orb-mu-plugin"
            chattr -ia -- "$d" 2>/dev/null || true
            rm -f -- "$d" 2>/dev/null || true
        else
            chattr -R -ia -- "$d" 2>/dev/null || true
            rm -rf -- "$d" 2>/dev/null || true
        fi
        if [[ ! -e "$d" ]]; then
            printf '%s\n' "$d" >> "$REPORT_DIR/ionic-plugin-removed.txt"
            status_line FIXED "Removed malicious ionic-scheduler-orb path: $d"
        else
            status_line FAILED "Could not remove malicious ionic-scheduler-orb path: $d"
        fi
    done

    scan_ionic_paths > "$REPORT_DIR/ionic-plugin-remaining.txt"
    if [[ -s "$REPORT_DIR/ionic-plugin-remaining.txt" ]]; then
        status_line FAILED "ionic-scheduler-orb remains after deletion attempt"
    else
        status_line CLEAN "ionic-scheduler-orb verification passed: no plugin or MU-plugin path remains"
    fi
}

# Runtime quarantine state. During cleanup the site is temporarily returned as
# HTTP 503, the cPanel user's crontab is paused, and a background guard kills
# any campaign process that respawns. This closes the race where persistence
# recreates files/processes while the main cleanup is still running.
GUARD_PID=""
HTTP_QUARANTINE_ACTIVE=0
CRON_QUARANTINE_ACTIVE=0
HTACCESS="$WP_PATH/.htaccess"
HTACCESS_BACKUP="$REPORT_DIR/htaccess.original"
HTACCESS_EXISTED=0
HTACCESS_FLAGS=""
CRONTAB_BACKUP="$REPORT_DIR/crontab.before"
CRONTAB_EXISTED=0
RUNTIME_QUARANTINE_RESTORED=0

restore_htaccess_quarantine() {
    [[ "$HTTP_QUARANTINE_ACTIVE" -eq 1 ]] || return 0
    chattr -ia -- "$HTACCESS" 2>/dev/null || true
    if [[ "$HTACCESS_EXISTED" -eq 1 ]]; then
        cp -a -- "$HTACCESS_BACKUP" "$HTACCESS" 2>/dev/null || {
            status_line FAILED "Could not restore original .htaccess from $HTACCESS_BACKUP"
            return 1
        }
        # Restore original immutable/append-only flags when they existed.
        [[ "$HTACCESS_FLAGS" == *i* ]] && chattr +i -- "$HTACCESS" 2>/dev/null || true
        [[ "$HTACCESS_FLAGS" == *a* ]] && chattr +a -- "$HTACCESS" 2>/dev/null || true
    else
        rm -f -- "$HTACCESS"
    fi
    HTTP_QUARANTINE_ACTIVE=0
    status_line FIXED "HTTP quarantine removed; original .htaccess restored"
}

enable_htaccess_quarantine() {
    local tmp group
    if [[ -e "$HTACCESS" ]]; then
        HTACCESS_EXISTED=1
        cp -a -- "$HTACCESS" "$HTACCESS_BACKUP"
        HTACCESS_FLAGS="$(lsattr -d "$HTACCESS" 2>/dev/null | awk '{print $1}' | head -n1 || true)"
        chattr -ia -- "$HTACCESS" 2>/dev/null || true
    else
        HTACCESS_EXISTED=0
        : > "$HTACCESS_BACKUP"
    fi

    tmp="$(mktemp "$REPORT_DIR/htaccess.quarantine.XXXXXX")"
    cat > "$tmp" <<'EOF'
# BEGIN SC-CLEANER-QUARANTINE
ErrorDocument 503 "Temporarily unavailable during security cleanup"
RewriteEngine On
RewriteRule ^ - [R=503,L]
# END SC-CLEANER-QUARANTINE
EOF
    if [[ "$HTACCESS_EXISTED" -eq 1 ]]; then
        cat "$HTACCESS_BACKUP" >> "$tmp"
        cat "$tmp" > "$HTACCESS"
        chown --reference="$HTACCESS_BACKUP" "$HTACCESS" 2>/dev/null || true
        chmod --reference="$HTACCESS_BACKUP" "$HTACCESS" 2>/dev/null || true
    else
        cat "$tmp" > "$HTACCESS"
        group="$(id -gn "$CPUSER")"
        chown "$CPUSER:$group" "$HTACCESS" 2>/dev/null || true
        chmod 0644 "$HTACCESS" 2>/dev/null || true
    fi
    rm -f -- "$tmp"
    HTTP_QUARANTINE_ACTIVE=1
    status_line FIXED "Temporary HTTP 503 quarantine enabled for this WordPress"
}

pause_user_crontab() {
    : > "$CRONTAB_BACKUP"
    if crontab -u "$CPUSER" -l > "$CRONTAB_BACKUP" 2>/dev/null; then
        CRONTAB_EXISTED=1
        crontab -u "$CPUSER" -r 2>/dev/null || true
        CRON_QUARANTINE_ACTIVE=1
        status_line FIXED "Temporarily paused cPanel user crontab"
    else
        CRONTAB_EXISTED=0
        status_line CLEAN "No user crontab to pause"
    fi

    # System-wide cron entries are report-only. Inspect only regular files; do
    # not recurse/follow unusual entries below /etc/cron.d on hosting servers.
    : > "$REPORT_DIR/system-cron-user-references.txt"
    if [[ -f /etc/crontab ]]; then
        grep -HE "(^|[[:space:]])${CPUSER}([[:space:]]|$)" /etc/crontab \
            >> "$REPORT_DIR/system-cron-user-references.txt" 2>/dev/null || true
    fi
    if [[ -d /etc/cron.d ]]; then
        while IFS= read -r -d '' cron_file; do
            grep -HE "(^|[[:space:]])${CPUSER}([[:space:]]|$)" "$cron_file" \
                >> "$REPORT_DIR/system-cron-user-references.txt" 2>/dev/null || true
        done < <(find /etc/cron.d -maxdepth 1 -type f -print0 2>/dev/null)
    fi
    if [[ -s "$REPORT_DIR/system-cron-user-references.txt" ]]; then
        status_line REVIEW "System cron entries referencing $CPUSER exist; see system-cron-user-references.txt"
    fi
}

restore_user_crontab() {
    [[ "$CRON_QUARANTINE_ACTIVE" -eq 1 ]] || return 0
    if [[ "$CRONTAB_EXISTED" -eq 1 ]]; then
        crontab -u "$CPUSER" "$CRONTAB_BACKUP" 2>/dev/null || {
            status_line FAILED "Could not restore user crontab from $CRONTAB_BACKUP"
            return 1
        }
    fi
    CRON_QUARANTINE_ACTIVE=0
    status_line FIXED "User crontab restored"
}

kill_existing_account_php() {
    local procs pids count=0
    procs="$(pgrep -afu "$CPUSER" '(/opt/cpanel/ea-php[0-9]+/root/usr/bin/php|/usr/local/bin/php|/usr/bin/php|lsphp)' 2>/dev/null || true)"
    if [[ -z "$procs" ]]; then
        status_line CLEAN "No existing account PHP workers/CLI processes required termination"
        return 0
    fi
    printf '%s\n' "$procs" > "$REPORT_DIR/account-php-processes-killed.txt"
    pids="$(printf '%s\n' "$procs" | awk '{print $1}' | tr '\n' ' ')"
    count="$(printf '%s\n' "$procs" | awk 'END{print NR+0}')"
    kill -9 $pids 2>/dev/null || true
    sleep 1
    status_line FIXED "Terminated $count existing PHP worker/CLI process(es) for cPanel user $CPUSER"
}

inventory_account_wordpress() {
    find "$USER_HOME" -type f -name wp-config.php -print 2>/dev/null \
        | while IFS= read -r cfg; do
            local root
            root="${cfg%/wp-config.php}"
            [[ -d "$root/wp-includes" && -d "$root/wp-admin" && -d "$root/wp-content" ]] && printf '%s\n' "$root"
        done | sort -u > "$REPORT_DIR/account-wordpress-roots.txt"
    local count
    count="$(file_count "$REPORT_DIR/account-wordpress-roots.txt")"
    if [[ "$count" -gt 1 ]]; then
        status_line REVIEW "Found $count WordPress installations under $CPUSER; sibling sites can re-seed the account and should also be cleaned"
        preview_file "$REPORT_DIR/account-wordpress-roots.txt" 10
    else
        status_line CLEAN "Found a single WordPress installation under this cPanel account"
    fi
}

quarantine_guard_loop() {
    local pids d
    while :; do
        pids="$(pgrep -u "$CPUSER" -f '\.g_[[:xdigit:]]+\.php|/wp-content/plugins/ionic-scheduler-orb[^/]*/|/wp-content/mu-plugins/ionic-scheduler-orb\.php|/wp-content/(plugins|mu-plugins)/(elite-module-cue|unity-manager-lite)([^/]*/|/)' 2>/dev/null || true)"
        if [[ -n "$pids" ]]; then
            {
                printf '[%s] respawned malware PIDs: %s\n' "$(date '+%F %T')" "$(echo "$pids" | tr '\n' ' ')"
                ps -o user,pid,ppid,lstart,etime,args -p "$(echo "$pids" | paste -sd, -)" 2>/dev/null || true
            } >> "$REPORT_DIR/quarantine-guard.log"
            kill -9 $pids 2>/dev/null || true
        fi

        # ionic-scheduler-orb is a confirmed campaign artifact. If local
        # persistence recreates it while cleanup is running, remove it again.
        while IFS= read -r d; do
            [[ -n "$d" ]] || continue
            case "$d" in
                "$WP_PATH/wp-content/plugins/ionic-scheduler-orb"|"$WP_PATH/wp-content/plugins/ionic-scheduler-orb-"*|"$WP_PATH/wp-content/mu-plugins/ionic-scheduler-orb.php")
                    printf '[%s] removed respawned ionic path: %s\n' "$(date '+%F %T')" "$d" >> "$REPORT_DIR/quarantine-guard.log"
                    if [[ -d "$d" ]]; then
                        chattr -R -ia -- "$d" 2>/dev/null || true
                        rm -rf -- "$d" 2>/dev/null || true
                    else
                        chattr -ia -- "$d" 2>/dev/null || true
                        rm -f -- "$d" 2>/dev/null || true
                    fi
                    ;;
            esac
        done < <(scan_ionic_paths)
        while IFS= read -r d; do
            [[ -n "$d" ]] || continue
            printf '[%s] removed respawned campaign plugin path: %s\n' "$(date '+%F %T')" "$d" >> "$REPORT_DIR/quarantine-guard.log"
            chattr -R -ia -- "$d" 2>/dev/null || true
            rm -rf -- "$d" 2>/dev/null || true
        done < <(scan_elite_module_cue_paths)
        sleep 0.25
    done
}

start_quarantine_guard() {
    : > "$REPORT_DIR/quarantine-guard.log"
    quarantine_guard_loop &
    GUARD_PID=$!
    status_line FIXED "Continuous malware process guard started (PID $GUARD_PID)"
}

stop_quarantine_guard() {
    [[ -n "${GUARD_PID:-}" ]] || return 0
    if kill -0 "$GUARD_PID" 2>/dev/null; then
        kill "$GUARD_PID" 2>/dev/null || true
        wait "$GUARD_PID" 2>/dev/null || true
    fi
    GUARD_PID=""
    status_line FIXED "Continuous malware process guard stopped"
}

restore_runtime_quarantine() {
    [[ "$RUNTIME_QUARANTINE_RESTORED" -eq 0 ]] || return 0
    RUNTIME_QUARANTINE_RESTORED=1
    stop_quarantine_guard || true
    restore_user_crontab || true
    restore_htaccess_quarantine || true
}

preserve_evidence_file() {
    local f="$1" label="${2:-artifact}"
    [[ -f "$f" ]] || return 0
    local rel safe dst
    rel="${f#"$WP_PATH"/}"
    safe="${rel//\//__}"
    mkdir -p "$REPORT_DIR/quarantine-files"
    dst="$REPORT_DIR/quarantine-files/${label}__${safe}"
    cp -a -- "$f" "$dst" 2>/dev/null || true
    {
        printf '%s\t%s\t%s\n' "$label" "$f" "$(md5sum "$f" 2>/dev/null | awk '{print $1}')"
    } >> "$REPORT_DIR/quarantine-files.tsv"
}

remove_high_confidence_file() {
    local f="$1" label="$2"
    [[ -f "$f" ]] || return 0
    local relock=0 parent
    parent="$(dirname "$f")"
    preserve_evidence_file "$f" "$label"

    # +i on wp-includes blocks deleting direct children. Open only for the
    # individual removal window; account HTTP/cron/guard quarantine is active.
    if [[ "$parent" == "$WP_PATH/wp-includes" ]] && wp_includes_has_attr i; then
        chattr -i "$WP_PATH/wp-includes" 2>/dev/null || true
        relock=1
    fi
    chattr -ia -- "$f" 2>/dev/null || true
    if rm -f -- "$f" 2>/dev/null; then
        printf '%s\t%s\n' "$label" "$f" >> "$REPORT_DIR/high-confidence-files-removed.tsv"
        status_line FIXED "Removed $label: $f"
    else
        status_line FAILED "Could not remove $label: $f"
    fi
    if [[ "$relock" -eq 1 ]]; then
        chattr +i "$WP_PATH/wp-includes" 2>/dev/null || true
    fi
}

remove_scv_wp_content_php() {
    local f removed=0
    : > "$REPORT_DIR/scv-wp-content-found.txt"
    : > "$REPORT_DIR/scv-wp-content-removed.txt"
    : > "$REPORT_DIR/scv-wp-content-remaining.txt"
    while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        printf '%s\n' "$f" >> "$REPORT_DIR/scv-wp-content-found.txt"
        status_line FOUND "Confirmed SCV campaign marker in wp-content PHP: $f"
        sc_mark_campaign_evidence "SCV marker in wp-content PHP: $f"
        remove_high_confidence_file "$f" "SCV-wp-content-PHP"
        if [[ -f "$f" ]]; then
            printf '%s\n' "$f" >> "$REPORT_DIR/scv-wp-content-remaining.txt"
        else
            printf '%s\n' "$f" >> "$REPORT_DIR/scv-wp-content-removed.txt"
            removed=$((removed+1))
        fi
    done < <(scan_scv_wp_content_php)
    if [[ "$removed" -gt 0 ]]; then
        status_line FIXED "Removed $removed SCV-marked PHP file(s) from wp-content"
    else
        status_line CLEAN "No SCV-marked PHP files required deletion under wp-content"
    fi
    return 0
}

remove_obf_loader_php() {
    local f removed=0
    : > "$REPORT_DIR/obf-loader-found.txt"
    : > "$REPORT_DIR/obf-loader-removed.txt"
    : > "$REPORT_DIR/obf-loader-remaining.txt"
    while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        printf '%s\n' "$f" >> "$REPORT_DIR/obf-loader-found.txt"
        status_line FOUND "Confirmed obfuscated SC loader in wp-content PHP: $f"
        sc_mark_campaign_evidence "obfuscated SC loader (__scf_/boot guard): $f"
        remove_high_confidence_file "$f" "obfuscated-SC-loader"
        if [[ -f "$f" ]]; then
            printf '%s\n' "$f" >> "$REPORT_DIR/obf-loader-remaining.txt"
        else
            printf '%s\n' "$f" >> "$REPORT_DIR/obf-loader-removed.txt"
            removed=$((removed+1))
        fi
    done < <(scan_obf_loader_php)
    if [[ "$removed" -gt 0 ]]; then
        status_line FIXED "Removed $removed obfuscated SC loader file(s) from wp-content"
    else
        status_line CLEAN "No obfuscated SC loader files required deletion under wp-content"
    fi
    return 0
}

# The version marker is the campaign's own boot handshake: 4.5.3 refuses to run
# when an older core is already loaded, which is why it stamps every file it
# writes. Record the generation(s) seen before the files are deleted.
sc_detect_campaign_versions() {
    local wc="$WP_PATH/wp-content" out="$REPORT_DIR/campaign-versions.txt" v
    : > "$out"
    [[ -d "$wc" ]] || return 0
    find "$wc" -type f -iname '*.php' -print0 2>/dev/null \
        | xargs -0 -r grep -hoiE 'SCV:[[:space:]]*[0-9]+(\.[0-9]+){1,3}' 2>/dev/null \
        | sed -E 's/^[Ss][Cc][Vv]:[[:space:]]*//' | sort -u -V > "$out" 2>/dev/null || true
    [[ -s "$out" ]] || return 0
    while IFS= read -r v; do
        [[ -n "$v" ]] || continue
        status_line FOUND "SC campaign generation detected: $v"
        sc_mark_campaign_evidence "SC campaign generation: $v"
    done < "$out"
    return 0
}

# Campaign-owned option names, from both captured generations. A name matching
# this list is deleted even when allowlisted software references it, so a plugin
# that happens to mention `sc_c2_cache` cannot vouch for the campaign's own row.
SC_DB_CAMPAIGN_OPTIONS='sc_own_manifest|sc_persist_manifest|sc_own_rec|sc_payload[a-z0-9_]*|sc_c2_cache|sc_canary|sc_boot_ver|sc_ver_o|sc_seen_ver|sc_cron[a-z0-9_]*|sc_guard[a-z0-9_]*|sc_lb_mode|sc_deferred_del|sc_initialized|sc_init_src_ts|sc_last_[a-z0-9_]*|sc_sw_[a-z0-9_]*|sc_sync_bk|sc_theme_(safety|virgin_db)|sc_update_(bad|suspect)|sc_pending_invalidate|sc_oc_dat_ok|sc_pad_off_ts|sc_scrub_ts|sc_js_printed_ts|sc_reins_[a-z0-9_]*|sc_fetch_fails|sc_ht_(dead|fail)|sc_ini_(dead|fail|pending)|sc_wc_mig|sc_errors|sc_purge|sc_mu_rescue|sc_mig_fail|sc_heal_scan|sc_admin_(inflight|tick)|sc_recover_(check|throttle)|sc_spread_(interval|nr)|sc_tmp[a-z0-9_]*|sc_actp_fh|sc_lock_[a-z0-9_]*'

sc_legit_code_dirs() {
    [[ -d "$WP_PATH/wp-content" ]] || return 0
    find "$WP_PATH/wp-content" -maxdepth 4 -type d 2>/dev/null \
        | grep -E "$(sc_legit_path_re)" || true
}

# An `sc_*` option name that appears in the code of allowlisted software belongs
# to that software - the same reasoning the randomized cron hooks already use,
# with the search restricted to allowlisted paths so the campaign's own files
# cannot vouch for their own rows.
sc_db_legit_option_names() {
    local name
    local -a dirs=()
    mapfile -t dirs < <(sc_legit_code_dirs)
    if (( ${#dirs[@]} == 0 )); then
        cat >/dev/null
        return 0
    fi
    while IFS= read -r name; do
        name="${name%$'\r'}"
        [[ -n "$name" ]] || continue
        [[ "$name" =~ ^[A-Za-z0-9_.:-]+$ ]] || continue
        [[ "$name" =~ ^(${SC_DB_CAMPAIGN_OPTIONS})$ ]] && continue
        if grep -rqF --binary-files=without-match -- "$name" "${dirs[@]}" 2>/dev/null; then
            printf '%s\n' "$name"
        fi
    done
    return 0
}


preserve_evidence_path() {
    local p="$1" label="${2:-artifact}" rel safe dst
    if [[ ! -e "$p" ]]; then
        return 0
    fi
    rel="${p#"$WP_PATH"/}"
    safe="${rel//\//__}"
    mkdir -p "$REPORT_DIR/quarantine-files"
    dst="$REPORT_DIR/quarantine-files/${label}__${safe}"
    cp -a -- "$p" "$dst" 2>/dev/null || true
    printf '%s\t%s\t%s\n' "$label" "$p" "path-copy" >> "$REPORT_DIR/quarantine-files.tsv"
}

remove_sc_runtime_variant() {
    local p removed_runtime=0 removed_state=0 removed_loose_gr=0
    : > "$REPORT_DIR/sc-runtime-removed.tsv"
    : > "$REPORT_DIR/sc-state-removed.tsv"
    : > "$REPORT_DIR/sc-loose-gr-removed.tsv"

    # Kill the .sc_/.gr_ runner first to close the recreation race.
    kill_malware_processes

    while IFS= read -r p; do
        [[ -d "$p" ]] || continue
        status_line FOUND "SC hidden runtime directory with .gr_ runner: $p"
        sc_mark_campaign_evidence "SC hidden runtime directory: $p"
        preserve_evidence_path "$p" "SC-runtime-dir"
        chattr -R -ia -- "$p" 2>/dev/null || true
        if rm -rf -- "$p" 2>/dev/null; then
            printf '%s\n' "$p" >> "$REPORT_DIR/sc-runtime-removed.tsv"
            removed_runtime=$((removed_runtime+1))
            status_line FIXED "Removed SC hidden runtime directory: $p"
        else
            status_line FAILED "Could not remove SC hidden runtime directory: $p"
        fi
    done < <(scan_sc_runtime_paths)

    # v24: high-confidence loose .gr_<32hex>.php runner. Filename alone is
    # insufficient; both --sc-cli and --sc-succ must be present in content.
    while IFS= read -r p; do
        [[ -f "$p" ]] || continue
        status_line FOUND "Loose SC .gr runner with --sc-cli/--sc-succ: $p"
        sc_mark_campaign_evidence "loose SC .gr runner: $p"
        preserve_evidence_file "$p" "SC-loose-gr-runner"
        chattr -ia -- "$p" 2>/dev/null || true
        if rm -f -- "$p" 2>/dev/null; then
            printf '%s\n' "$p" >> "$REPORT_DIR/sc-loose-gr-removed.tsv"
            removed_loose_gr=$((removed_loose_gr+1))
            status_line FIXED "Removed loose SC .gr runner: $p"
        else
            status_line FAILED "Could not remove loose SC .gr runner: $p"
        fi
    done < <(scan_loose_gr_runners)

    # State/lock files are auto-removed only as a cluster (>=3 artifacts sharing
    # the same token), which is much safer than deleting any .g?._<hex> by name.
    while IFS= read -r p; do
        if [[ ! -e "$p" ]]; then
            continue
        fi
        status_line FOUND "Clustered SC state/lock artifact: $p"
        preserve_evidence_path "$p" "SC-state-artifact"
        chattr -R -ia -- "$p" 2>/dev/null || true
        if rm -rf -- "$p" 2>/dev/null; then
            printf '%s\n' "$p" >> "$REPORT_DIR/sc-state-removed.tsv"
            removed_state=$((removed_state+1))
        else
            status_line FAILED "Could not remove SC state/lock artifact: $p"
        fi
    done < <(scan_sc_state_clusters)

    [[ "$removed_runtime" -gt 0 ]] && status_line FIXED "Removed $removed_runtime SC runtime director$( [[ $removed_runtime -eq 1 ]] && echo y || echo ies )" || status_line CLEAN "No confirmed .sc_/.gr_ runtime directory required deletion"
    [[ "$removed_loose_gr" -gt 0 ]] && status_line FIXED "Removed $removed_loose_gr loose SC .gr_<32hex>.php runner(s)" || status_line CLEAN "No loose high-confidence SC .gr runner required deletion"
    [[ "$removed_state" -gt 0 ]] && status_line FIXED "Removed $removed_state clustered SC state/lock artifact(s)" || status_line CLEAN "No clustered SC state/lock artifacts required deletion"
    return 0
}

remove_random_hex_sc_ioc_files() {
    local f bn removed=0
    : > "$REPORT_DIR/random-hex-sc-ioc-removed.tsv"

    # v20: A campaign-style PHP basename by itself is only a hunting clue.
    # Auto-delete only when the file content also contains a campaign-specific
    # SC IOC. This catches site-specific loaders such as 3d5a583f.php while
    # avoiding deletion of arbitrary short-named PHP files.
    while IFS= read -r -d '' f; do
        [[ -f "$f" ]] || continue
        bn="${f##*/}"
        if [[ "$bn" =~ ^\.?[[:xdigit:]]{6,40}\.php$ ]] || [[ "$bn" =~ ^(core|own)_[[:xdigit:]]{8,40}\.php$ ]]; then
            :
        else
            continue
        fi
        grep -Eq "$IOC_REGEX" "$f" 2>/dev/null || continue

        status_line FOUND "Campaign-named PHP file contains SC runtime/IOC evidence: $f"
        sc_mark_campaign_evidence "campaign-named PHP file with SC IOC: $f"
        remove_high_confidence_file "$f" "campaign-named-SC-IOC"
        printf '%s\n' "$f" >> "$REPORT_DIR/random-hex-sc-ioc-removed.tsv"
        removed=$((removed+1))
    done < <(find "$WP_PATH" -type f -name '*.php' -print0 2>/dev/null || true)

    if [[ "$removed" -eq 0 ]]; then
        status_line CLEAN "No campaign-named PHP files containing SC runtime/IOC evidence found"
    else
        status_line FIXED "Removed $removed campaign-named PHP file(s) containing SC runtime/IOC evidence"
    fi
    return 0
}

scan_elite_state_artifacts() {
    local wc="$WP_PATH/wp-content" f
    [[ -d "$wc" ]] || return 0
    for f in \
        "$wc/.rd_elite-module-cue" \
        "$wc/.q_elite-module-cue" \
        "$wc/plugins/elite-module-cue/.bt_elite-module-cue" \
        "$wc/plugins/elite-module-cue/.sd_elite-module-cue" \
        "$wc/mu-plugins/.bt_elite-module-cue" \
        "$wc/mu-plugins/.sd_elite-module-cue"; do
        if [[ -e "$f" ]]; then
            printf '%s\n' "$f"
        fi
    done
}

remove_elite_state_artifacts() {
    local f removed=0
    : > "$REPORT_DIR/elite-state-removed.tsv"
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        if [[ ! -e "$f" ]]; then
            continue
        fi
        status_line FOUND "Confirmed elite-module-cue state artifact: $f"
        sc_mark_campaign_evidence "elite-module-cue state artifact: $f"
        preserve_evidence_path "$f" "elite-state"
        chattr -R -ia -- "$f" 2>/dev/null || true
        rm -rf -- "$f" 2>/dev/null || true
        printf '%s\n' "$f" >> "$REPORT_DIR/elite-state-removed.tsv"
        removed=$((removed+1))
    done < <(scan_elite_state_artifacts)
    if [[ "$removed" -gt 0 ]]; then
        status_line FIXED "Removed $removed elite-module-cue state artifact(s)"
    fi
    return 0
}

scan_campaign_extensionless_payloads() {
    local f
    for f in "$WP_PATH/wp-admin/__PATH__" "$WP_PATH/__PATH__" "$WP_PATH/wp-content/__PATH__"; do
        [[ -f "$f" ]] || continue
        # 64 bytes and a case-insensitive tag: payloads have been seen with a
        # shebang, a BOM or an uppercase `<?PHP` ahead of the opening tag.
        head -c 64 -- "$f" 2>/dev/null | matches_stdin '<\?php' || continue
        grep -Eqi 'elite-module-cue|unity-manager-lite|SCOCV:|SCV:[0-9]+\.|SC_OC_|SC_DD_|SC_DP_|SCD1:|__scf_[A-Za-z0-9_]{6,}|SC_CORE_BOOT_VER' "$f" 2>/dev/null || continue
        printf '%s\n' "$f"
    done
}

remove_campaign_extensionless_payloads() {
    local f removed=0
    : > "$REPORT_DIR/extensionless-payloads-removed.tsv"
    while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        status_line FOUND "Confirmed extensionless SC PHP payload: $f"
        sc_mark_campaign_evidence "extensionless SC PHP payload: $f"
        remove_high_confidence_file "$f" "extensionless-SC-payload"
        printf '%s\n' "$f" >> "$REPORT_DIR/extensionless-payloads-removed.tsv"
        removed=$((removed+1))
    done < <(scan_campaign_extensionless_payloads)
    [[ "$removed" -gt 0 ]] && status_line FIXED "Removed $removed extensionless SC PHP payload(s)" || true
    return 0
}

scan_campaign_marker_files() {
    local wc="$WP_PATH/wp-content" f
    [[ -d "$wc" ]] || return 0
    while IFS= read -r -d '' f; do
        printf '%s\n' "$f"
    done < <(find "$wc" -mindepth 1 -maxdepth 1 -type f -regextype posix-extended \
        \( -regex '.*/\.sc_[[:xdigit:]]{6,40}' -o -regex '.*/\.kk_[[:xdigit:]]{6,40}' \) -print0 2>/dev/null || true)
}

remove_campaign_marker_files() {
    local f removed=0
    # Filename-only .sc_/.kk_ marker files are removed only on a site that has
    # independent campaign evidence from preflight/current cleanup.
    [[ "${SC_PREVIOUS_CAMPAIGN_EVIDENCE:-0}" -eq 1 || -s "$REPORT_DIR/elite-module-cue-found.txt" || -s "$REPORT_DIR/wp-object-cache-ioc-removed.tsv" ]] || return 0
    : > "$REPORT_DIR/campaign-marker-files-removed.tsv"
    while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        status_line FOUND "Correlated SC marker/state file: $f"
        remove_high_confidence_file "$f" "SC-marker-state"
        printf '%s\n' "$f" >> "$REPORT_DIR/campaign-marker-files-removed.tsv"
        removed=$((removed+1))
    done < <(scan_campaign_marker_files)
    [[ "$removed" -gt 0 ]] && status_line FIXED "Removed $removed correlated .sc_/.kk_ marker file(s)" || true
    return 0
}

scan_wp_object_cache_candidates() {
    [[ -d "$WP_PATH/wp-content" ]] || return 0
    find "$WP_PATH/wp-content" -type f \( -name '.wp-object-cache-*.dat' -o -name '.wp-object-cache-*.dat.lkg' \) -size -8M -print 2>/dev/null \
        | while IFS= read -r f; do
            local bn
            bn="${f##*/}"
            [[ "$bn" =~ ^\.wp-object-cache-[[:xdigit:]]{8,32}\.dat(\.lkg)?$ ]] || continue
            printf '%s\n' "$f"
          done
}

scan_wp_object_cache_ioc() {
    local f
    while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        if head -c 16 -- "$f" 2>/dev/null | matches_stdin 'SCD1:'; then
            printf '%s\n' "$f"
            continue
        fi
        grep -Eq "$IOC_REGEX" "$f" 2>/dev/null || continue
        printf '%s\n' "$f"
    done < <(scan_wp_object_cache_candidates)
}

remove_malicious_wp_object_cache_dat() {
    local f removed=0
    : > "$REPORT_DIR/wp-object-cache-candidates.txt"
    : > "$REPORT_DIR/wp-object-cache-ioc-removed.tsv"
    scan_wp_object_cache_candidates > "$REPORT_DIR/wp-object-cache-candidates.txt"
    while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        status_line FOUND "Confirmed SC IOC inside .wp-object-cache artifact: $f"
        sc_mark_campaign_evidence "SC IOC inside .wp-object-cache artifact: $f"
        remove_high_confidence_file "$f" "malicious-wp-object-cache-dat"
        printf '%s\n' "$f" >> "$REPORT_DIR/wp-object-cache-ioc-removed.tsv"
        removed=$((removed+1))
    done < <(scan_wp_object_cache_ioc)
    if [[ "$removed" -gt 0 ]]; then
        status_line FIXED "Removed $removed confirmed malicious .wp-object-cache-<hex>.dat/.dat.lkg file(s)"
    elif [[ -s "$REPORT_DIR/wp-object-cache-candidates.txt" ]]; then
        status_line REVIEW "Filename-only .wp-object-cache-<hex>.dat/.dat.lkg candidate(s) found without internal SC IOC; left for review"
    else
        status_line CLEAN "No .wp-object-cache-<hex>.dat/.dat.lkg candidates found"
    fi
    return 0
}

remove_derived_campaign_artifacts() {
    local f removed=0
    : > "$REPORT_DIR/derived-artifacts-removed.txt"
    while IFS= read -r f; do
        [[ -n "$f" && -f "$f" ]] || continue
        remove_high_confidence_file "$f" "SC-derived-artifact"
        printf '%s\n' "$f" >> "$REPORT_DIR/derived-artifacts-removed.txt"
        removed=$((removed+1))
    done < <(
        find "$WP_PATH" -type f \( \
          -name "${ROLE_LDR}.php" -o -name ".${ROLE_LDR}.php" \
          -o -name "${ROLE_ZIP}.zip" -o -name ".${ROLE_ZIP}.zip" \
          -o -name "${ROLE_INST}.php" -o -name ".${ROLE_INST}.php" \
          -o -name "${ROLE_SW}.php" -o -name ".${ROLE_SW}.php" \
        \) -print 2>/dev/null || true
    )
    if [[ "$removed" -eq 0 ]]; then
        status_line CLEAN "No exact ABSPATH-derived SC loader/ZIP/installer/SW artifacts found"
    else
        status_line FIXED "Removed $removed exact ABSPATH-derived SC artifact(s)"
    fi
}

remove_malicious_dropins() {
    local f marker removed=0
    : > "$REPORT_DIR/dropins-removed.txt"
    for f in "$WP_PATH/wp-content/advanced-cache.php" "$WP_PATH/wp-content/db.php" "$WP_PATH/wp-content/object-cache.php"; do
        [[ -f "$f" ]] || continue
        marker=''
        case "${f##*/}" in
            advanced-cache.php)
                grep -Eq 'SC_ADV_BEGIN|SC_ADV_END|SC_DD_BEGIN|SC_DD_END|sc_payload_persistent|elite-module-cue|unity-manager-lite|a18xgj672mowjoum|0x3bc5de30' "$f" 2>/dev/null && marker='SC_ADV'
                ;;
            db.php)
                grep -Eq 'SC_DB_BEGIN|SC_DB_END|SC_DD_BEGIN|SC_DD_END|sc_payload_persistent|elite-module-cue|unity-manager-lite|a18xgj672mowjoum|0x3bc5de30' "$f" 2>/dev/null && marker='SC_DB'
                ;;
            object-cache.php)
                grep -Eq 'SC_OC_BEGIN|SC_OC_END|SCOCV:|SCD1:|elite-module-cue|\.wp-object-cache-[[:xdigit:]]{8,32}([^[:xdigit:]]|$)|\.wp-object-cache-[[:xdigit:]]{8,32}\.dat(\.lkg)?' "$f" 2>/dev/null && marker='SC_OC'
                ;;
        esac
        [[ -n "$marker" ]] || continue
        remove_high_confidence_file "$f" "malicious-${f##*/}"
        printf '%s\n' "$f" >> "$REPORT_DIR/dropins-removed.txt"
        removed=$((removed+1))
    done
    if [[ "$removed" -eq 0 ]]; then
        status_line CLEAN "No marker-confirmed malicious advanced-cache.php/db.php/object-cache.php required deletion"
    else
        status_line FIXED "Removed $removed marker-confirmed malicious WordPress drop-in(s)"
        # These are cache-plugin drop-ins. They are intentionally not recreated:
        # the campaign's own stored copies must not be trusted as a source.
        status_line REVIEW "wp-content/{db,object-cache,advanced-cache}.php were deleted and are NOT recreated; re-save the cache plugin's settings (e.g. W3 Total Cache) to regenerate them"
    fi
    return 0
}


scan_theme_function_markers() {
    local themes="$WP_PATH/wp-content/themes"
    [[ -d "$themes" ]] || return 0
    find "$themes" -type f -name 'functions.php' -print0 2>/dev/null \
        | while IFS= read -r -d '' f; do
            grep -HnE 'SC_TH_BEGIN|SC_TH_END|SC_TH_LD_|a18xgj672mowjoum|0x3bc5de30|sc_payload_persistent|echo-compiler-plus|\$_sc_done|\$_sc_lock|\$_sc_files|goto[[:space:]]+_sc_end|SC_FAIL|_sc_(padf|ul|coreld|corep|fpc|mkdir|unp|qok|aw|any_live|phpok_src|src)[[:space:]]*\(|static[[:space:]]*\$a=null;[[:space:]]*if[[:space:]]*\([[:space:]]*\$a===null[[:space:]]*\)[[:space:]]*\{[[:space:]]*\$a=array_merge\(array\(|/th[bv]_[[:xdigit:]]{8,40}\.bak|"gen":"[[:xdigit:]]{8,16}"' "$f" 2>/dev/null || true
          done
    return 0
}

clean_markerless_echo_theme_injection() {
    local themes="$WP_PATH/wp-content/themes" f tmp flags removed=0 review=0 start_count
    : > "$REPORT_DIR/theme-markerless-echo-found.txt"
    : > "$REPORT_DIR/theme-markerless-echo-cleaned.txt"
    : > "$REPORT_DIR/theme-markerless-echo-review.txt"
    [[ -d "$themes" ]] || return 0

    while IFS= read -r -d '' f; do
        [[ -f "$f" ]] || continue
        # Require the characteristic downloader tuple, not a lone string match.
        grep -Fq "echo-compiler-plus" "$f" 2>/dev/null || continue
        grep -Eq '\$_sc_done[[:space:]]*=[[:space:]]*false' "$f" 2>/dev/null || continue
        grep -Eq '\$_sc_lock[[:space:]]*=' "$f" 2>/dev/null || continue
        grep -Eq '\$_sc_files[[:space:]]*=' "$f" 2>/dev/null || continue
        if ! grep -Eq 'wp_remote_get|\$_sc_base[[:space:]]*=|goto[[:space:]]+_sc_end' "$f" 2>/dev/null; then
            continue
        fi

        printf '%s\n' "$f" >> "$REPORT_DIR/theme-markerless-echo-found.txt"
        preserve_evidence_file "$f" "markerless-echo-theme-functions"
        status_line FOUND "Markerless echo-compiler-plus downloader detected in theme functions.php: $f"
        sc_mark_campaign_evidence "markerless echo-compiler-plus theme injection: $f"

        start_count="$(grep -Ec '\$_sc_done[[:space:]]*=[[:space:]]*false' "$f" 2>/dev/null || true)"
        if [[ "$start_count" -ne 1 ]]; then
            printf '%s\n' "$f" >> "$REPORT_DIR/theme-markerless-echo-review.txt"
            status_line REVIEW "Markerless downloader start is not unique; refusing automatic truncation: $f"
            review=$((review+1))
            continue
        fi

        # Current campaign appends the downloader to the child-theme functions.php.
        # Truncate from the unique $_sc_done=false start to EOF, preserving all
        # legitimate theme code before it. This is intentionally gated by the
        # complete high-confidence tuple above.
        tmp="$REPORT_DIR/.theme-markerless-echo.$$.tmp"
        if ! awk '
            BEGIN { cut=0 }
            {
                if (!cut && $0 ~ /\$_sc_done[[:space:]]*=[[:space:]]*false/) { cut=1; next }
                if (!cut) print
            }
            END { if (!cut) exit 42 }
        ' "$f" > "$tmp"; then
            rm -f -- "$tmp"
            printf '%s\n' "$f" >> "$REPORT_DIR/theme-markerless-echo-review.txt"
            status_line REVIEW "Could not safely isolate markerless downloader; original preserved: $f"
            review=$((review+1))
            continue
        fi
        if grep -Eq 'echo-compiler-plus|SC_FAIL|\$_sc_done|\$_sc_lock|\$_sc_files' "$tmp" 2>/dev/null; then
            rm -f -- "$tmp"
            printf '%s\n' "$f" >> "$REPORT_DIR/theme-markerless-echo-review.txt"
            status_line REVIEW "Markerless downloader IOC remains in cleaned candidate; original preserved: $f"
            review=$((review+1))
            continue
        fi

        if ! sc_commit_cleaned_php "$f" "$tmp" "markerless theme downloader cleanup"; then
            rm -f -- "$tmp"
            printf '%s\n' "$f" >> "$REPORT_DIR/theme-markerless-echo-review.txt"
            review=$((review+1))
            continue
        fi
        rm -f -- "$tmp"
        printf '%s\n' "$f" >> "$REPORT_DIR/theme-markerless-echo-cleaned.txt"
        status_line FIXED "Removed appended markerless echo-compiler-plus downloader from: $f"
        removed=$((removed+1))
    done < <(find "$themes" -type f -name 'functions.php' -print0 2>/dev/null)

    [[ "$review" -gt 0 ]] && status_line REVIEW "$review markerless echo-compiler-plus theme injection(s) require manual review"
    return 0
}

clean_malicious_theme_functions() {
    local themes="$WP_PATH/wp-content/themes" f begin_count end_count tmp removed=0 review=0 flags
    : > "$REPORT_DIR/theme-functions-found.txt"
    : > "$REPORT_DIR/theme-functions-cleaned.txt"
    : > "$REPORT_DIR/theme-functions-review.txt"
    [[ -d "$themes" ]] || { status_line CLEAN "No wp-content/themes directory present"; return 0; }

    while IFS= read -r -d '' f; do
        begin_count="$(grep -c 'SC_TH_BEGIN' "$f" 2>/dev/null || true)"
        end_count="$(grep -c 'SC_TH_END' "$f" 2>/dev/null || true)"
        begin_count="${begin_count:-0}"; end_count="${end_count:-0}"
        if [[ "$begin_count" -eq 0 && "$end_count" -eq 0 ]]; then
            continue
        fi

        printf '%s\tbegin=%s\tend=%s\n' "$f" "$begin_count" "$end_count" >> "$REPORT_DIR/theme-functions-found.txt"
        status_line FOUND "SC_TH marker(s) detected in theme functions.php: $f (begin=$begin_count end=$end_count)"
        sc_mark_campaign_evidence "SC_TH theme injection: $f"
        preserve_evidence_file "$f" "SC-TH-theme-functions"

        # Auto-remove balanced SC_TH block-comment regions even when the BEGIN
        # marker shares a line with <?php, e.g.:
        #   <?php /* SC_TH_BEGIN:4.0.3:hash */
        # The prefix before BEGIN (notably <?php) and any suffix after END are kept.
        if [[ "$begin_count" -ne "$end_count" || "$begin_count" -eq 0 ]] \
           || ! grep -Eq '/\*[[:space:]]*SC_TH_BEGIN:' "$f" 2>/dev/null \
           || ! grep -Eq '/\*[[:space:]]*SC_TH_END:' "$f" 2>/dev/null; then
            printf '%s\n' "$f" >> "$REPORT_DIR/theme-functions-review.txt"
            status_line REVIEW "Unbalanced/non-block-comment SC_TH markers; not modifying automatically: $f"
            review=$((review+1))
            continue
        fi

        tmp="$REPORT_DIR/.theme-functions.$$.tmp"
        if ! awk '
            BEGIN { in_sc=0 }
            {
                if (!in_sc) {
                    b=index($0,"/* SC_TH_BEGIN")
                    if (b) {
                        prefix=substr($0,1,b-1)
                        if (prefix ~ /[^[:space:]]/) print prefix
                        in_sc=1
                        next
                    }
                    print
                    next
                }

                e=index($0,"/* SC_TH_END")
                if (e) {
                    tail=substr($0,e)
                    c=index(tail,"*/")
                    if (!c) exit 43
                    suffix=substr(tail,c+2)
                    if (suffix ~ /[^[:space:]]/) print suffix
                    in_sc=0
                }
            }
            END { if (in_sc) exit 42 }
        ' "$f" > "$tmp"; then
            rm -f -- "$tmp"
            printf '%s\n' "$f" >> "$REPORT_DIR/theme-functions-review.txt"
            status_line REVIEW "Could not safely isolate complete SC_TH block; original preserved: $f"
            review=$((review+1))
            continue
        fi

        # The campaign writes a guard stub ahead of its marked block:
        #     $_sc_done = false;
        #      die( 'SC_FAIL' ); }
        # Removing only the marked region leaves an unmatched brace and a die()
        # on every request. Strip the stub as part of the same injection.
        sc_strip_trailing_sc_stub < "$tmp" > "$tmp.stub" 2>/dev/null || cp -a -- "$tmp" "$tmp.stub"
        mv -f -- "$tmp.stub" "$tmp"

        if grep -Eq 'SC_TH_BEGIN|SC_TH_END|SC_FAIL|\$_sc_(done|lock|files|base)' "$tmp" 2>/dev/null; then
            rm -f -- "$tmp"
            printf '%s\n' "$f" >> "$REPORT_DIR/theme-functions-review.txt"
            status_line REVIEW "Campaign residue remains in cleaned candidate; original preserved: $f"
            review=$((review+1))
            continue
        fi

        # Never leave an unparsable theme behind.
        if ! sc_commit_cleaned_php "$f" "$tmp" "SC_TH theme cleanup"; then
            rm -f -- "$tmp"
            printf '%s\n' "$f" >> "$REPORT_DIR/theme-functions-review.txt"
            review=$((review+1))
            continue
        fi
        rm -f -- "$tmp"
        printf '%s\n' "$f" >> "$REPORT_DIR/theme-functions-cleaned.txt"
        status_line FIXED "Removed SC_TH injection block and campaign guard stub from: $f"
        removed=$((removed+1))
    done < <(find "$themes" -type f -name 'functions.php' -print0 2>/dev/null)

    if [[ "$removed" -eq 0 && "$review" -eq 0 ]]; then
        status_line CLEAN "No SC_TH injection markers found in theme functions.php files"
    elif [[ "$review" -gt 0 ]]; then
        status_line REVIEW "$review theme functions.php file(s) still require manual review"
    fi
    return 0
}

# Remove the exact orphan SC guard stub wherever it appears under wp-content.
# This residue has been observed outside theme functions.php (for example in
# theme 404.php files) and otherwise causes the generic IOC gate to remain dirty:
#
#     $_sc_done = false;
#      die( 'SC_FAIL' ); }
#
# Safety rules:
#   * only the exact high-confidence two-line/same-line guard form is removed;
#   * the original file is preserved in the evidence quarantine first;
#   * the candidate must pass PHP syntax validation before it replaces the file;
#   * if the pair is embedded in larger code and removal would break syntax, the
#     original is left untouched and the normal IOC gate keeps the site REVIEW.
clean_orphan_sc_guard_stubs_wp_content() {
    local wc="$WP_PATH/wp-content" f tmp removed=0 review=0
    : > "$REPORT_DIR/orphan-sc-guard-found.txt"
    : > "$REPORT_DIR/orphan-sc-guard-cleaned.txt"
    : > "$REPORT_DIR/orphan-sc-guard-review.txt"
    [[ -d "$wc" ]] || return 0

    # The prefilter used to be two greps per candidate file under wp-content.
    # One batched grep produces the candidate set instead, and the exact pair
    # detector below then runs only on the handful of files that can match.
    local cand="$REPORT_DIR/.orphan-stub-candidates.txt"
    find "$wc" -type f -size -32M \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.phar' -o -iname '*.bak' \) -print0 2>/dev/null \
        | xargs -0 -r grep -lE --binary-files=without-match '\$_sc_done[[:space:]]*=[[:space:]]*false' 2>/dev/null \
        | sort -u > "$cand" || true

    while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        grep -Fq 'SC_FAIL' "$f" 2>/dev/null || continue

        # Require at least one exact orphan pair. Blank lines between the two
        # statements are tolerated. A same-line form is accepted as well.
        if ! awk '
            function is_start(s) {
                return s ~ /^[[:space:]]*\$_sc_done[[:space:]]*=[[:space:]]*false[[:space:]]*;[[:space:]]*$/
            }
            function is_end(s) {
                return s ~ /^[[:space:]]*die[[:space:]]*\([^)]*SC_FAIL[^)]*\)[[:space:]]*;[[:space:]]*}[[:space:]]*$/
            }
            function is_same(s) {
                return s ~ /^[[:space:]]*\$_sc_done[[:space:]]*=[[:space:]]*false[[:space:]]*;[[:space:]]*die[[:space:]]*\([^)]*SC_FAIL[^)]*\)[[:space:]]*;[[:space:]]*}[[:space:]]*$/
            }
            BEGIN { pending=0; found=0 }
            {
                if (is_same($0)) { found=1; next }
                if (pending) {
                    if ($0 ~ /^[[:space:]]*$/) next
                    if (is_end($0)) { found=1; pending=0; next }
                    pending=0
                }
                if (is_start($0)) { pending=1; next }
            }
            END { exit(found ? 0 : 1) }
        ' "$f"; then
            continue
        fi

        printf '%s\n' "$f" >> "$REPORT_DIR/orphan-sc-guard-found.txt"
        status_line FOUND "Orphan SC guard stub detected under wp-content: $f"
        sc_mark_campaign_evidence "orphan SC guard stub: $f"
        preserve_evidence_file "$f" "orphan-SC-guard-stub"

        tmp="$REPORT_DIR/.orphan-sc-guard.$$.tmp"
        if ! awk '
            function is_start(s) {
                return s ~ /^[[:space:]]*\$_sc_done[[:space:]]*=[[:space:]]*false[[:space:]]*;[[:space:]]*$/
            }
            function is_end(s) {
                return s ~ /^[[:space:]]*die[[:space:]]*\([^)]*SC_FAIL[^)]*\)[[:space:]]*;[[:space:]]*}[[:space:]]*$/
            }
            function is_same(s) {
                return s ~ /^[[:space:]]*\$_sc_done[[:space:]]*=[[:space:]]*false[[:space:]]*;[[:space:]]*die[[:space:]]*\([^)]*SC_FAIL[^)]*\)[[:space:]]*;[[:space:]]*}[[:space:]]*$/
            }
            BEGIN { pending=0; nblank=0; removed=0 }
            {
                if (is_same($0)) { removed++; next }

                if (pending) {
                    if ($0 ~ /^[[:space:]]*$/) { blanks[++nblank]=$0; next }
                    if (is_end($0)) {
                        removed++
                        pending=0; nblank=0
                        delete blanks
                        next
                    }
                    print pending_line
                    for (i=1; i<=nblank; i++) print blanks[i]
                    pending=0; nblank=0
                    delete blanks
                }

                if (is_start($0)) {
                    pending=1
                    pending_line=$0
                    next
                }
                print
            }
            END {
                if (pending) {
                    print pending_line
                    for (i=1; i<=nblank; i++) print blanks[i]
                }
                if (removed == 0) exit 42
            }
        ' "$f" > "$tmp"; then
            rm -f -- "$tmp"
            printf '%s\n' "$f" >> "$REPORT_DIR/orphan-sc-guard-review.txt"
            status_line REVIEW "Could not safely isolate orphan SC guard stub; original preserved: $f"
            review=$((review+1))
            continue
        fi

        if grep -Eq '\$_sc_done[[:space:]]*=[[:space:]]*false|SC_FAIL' "$tmp" 2>/dev/null; then
            # Do not reject merely because another unrelated SC marker exists;
            # specifically ensure the orphan guard strings are gone. If they
            # remain, another form needs manual handling rather than guessing.
            rm -f -- "$tmp"
            printf '%s\n' "$f" >> "$REPORT_DIR/orphan-sc-guard-review.txt"
            status_line REVIEW "SC guard residue remains after exact-pair cleanup; original preserved: $f"
            review=$((review+1))
            continue
        fi

        if ! sc_commit_cleaned_php "$f" "$tmp" "orphan SC guard stub cleanup"; then
            rm -f -- "$tmp"
            printf '%s\n' "$f" >> "$REPORT_DIR/orphan-sc-guard-review.txt"
            review=$((review+1))
            continue
        fi
        rm -f -- "$tmp"
        printf '%s\n' "$f" >> "$REPORT_DIR/orphan-sc-guard-cleaned.txt"
        status_line FIXED "Removed orphan SC guard stub from: $f"
        removed=$((removed+1))
    done < "$cand"
    rm -f -- "$cand"

    if [[ "$removed" -eq 0 && "$review" -eq 0 ]]; then
        status_line CLEAN "No orphan SC guard stubs found under wp-content"
    elif [[ "$review" -gt 0 ]]; then
        status_line REVIEW "$review orphan SC guard stub file(s) require manual review"
    fi
    return 0
}

clean_malicious_user_ini() {
    local f line target resolved base hidden tmp changed=0 removed_loaders=0
    local bn counterpart
    local candidates=(
        "$WP_PATH/.user.ini"
        "$WP_PATH/wp-content/.user.ini"
        "$(dirname "$WP_PATH")/.user.ini"
        "$USER_HOME/.user.ini"
    )
    : > "$REPORT_DIR/user-ini-cleaned.txt"
    for f in "${candidates[@]}"; do
        [[ -f "$f" ]] || continue

        # Do not require a particular hash length/name. Extract every
        # auto_prepend_file directive and decide from the referenced target.
        mapfile -t _ap_lines < <(grep -Ei '^[[:space:]]*auto_prepend_file[[:space:]]*=' "$f" 2>/dev/null || true)
        [[ ${#_ap_lines[@]} -gt 0 ]] || continue

        local malicious_directive=0
        for line in "${_ap_lines[@]}"; do
            target="$(sc_auto_prepend_target "$line")"
            [[ -n "$target" ]] || continue
            base="$(dirname "$f")"
            if [[ "$target" = /* ]]; then
                resolved="$(realpath -m "$target" 2>/dev/null || true)"
            else
                resolved="$(realpath -m "$base/$target" 2>/dev/null || true)"
            fi
            [[ -n "$resolved" ]] || continue
            case "$resolved" in
                "$WP_PATH"/*)
                    bn="${resolved##*/}"
                    # High-confidence campaign-style loader:
                    #   .g_*.php OR an otherwise meaningless alphanumeric PHP
                    #   filename (hidden or visible), regardless of exact length.
                    # Also accept a file containing a known SC marker.
                    if [[ "$bn" =~ ^\.g_[A-Za-z0-9_-]+\.php$ || "$bn" =~ ^\.?[A-Za-z0-9]{6,40}\.php$ ]] \
                       || { [[ -f "$resolved" ]] && grep -Eqi 'SC_(DB|ADV|TH)_BEGIN|sc_payload_persistent|sc_cron_fetch|a18xgj672mowjoum|0x3bc5de30' "$resolved" 2>/dev/null; }; then
                        malicious_directive=1
                        [[ -f "$resolved" ]] && { remove_high_confidence_file "$resolved" "auto-prepend-loader"; removed_loaders=$((removed_loaders+1)); }

                        # Campaign samples often keep hidden+visible twins. Remove
                        # the sibling twin only when its basename is identical.
                        if [[ "$bn" == .* ]]; then
                            counterpart="$(dirname "$resolved")/${bn#.}"
                        else
                            counterpart="$(dirname "$resolved")/.${bn}"
                        fi
                        if [[ -f "$counterpart" ]]; then
                            remove_high_confidence_file "$counterpart" "auto-prepend-loader-twin"
                            removed_loaders=$((removed_loaders+1))
                        fi
                    fi
                    ;;
            esac
        done

        [[ "$malicious_directive" -eq 1 ]] || continue
        status_line FOUND "Malicious auto_prepend_file persistence detected: $f"
        sc_mark_campaign_evidence "malicious .user.ini auto_prepend_file: $f"
        preserve_evidence_file "$f" "malicious-user-ini"
        chattr -ia -- "$f" 2>/dev/null || true

        tmp="$REPORT_DIR/.userini.$$.tmp"
        # In an SC-positive .user.ini, remove all auto_prepend_file directives.
        grep -Evi '^[[:space:]]*auto_prepend_file[[:space:]]*=' "$f" > "$tmp" 2>/dev/null || true
        if grep -Eqv '^[[:space:]]*($|;|#)' "$tmp" 2>/dev/null; then
            cat "$tmp" > "$f"
            status_line FIXED "Removed malicious auto_prepend_file directive(s) from $f"
        else
            rm -f -- "$f"
            status_line FIXED "Removed malware-only .user.ini: $f"
        fi
        rm -f -- "$tmp"
        printf '%s\n' "$f" >> "$REPORT_DIR/user-ini-cleaned.txt"
        changed=$((changed+1))
    done
    if [[ "$changed" -eq 0 ]]; then
        status_line CLEAN "No malicious auto_prepend_file .user.ini persistence found"
    fi
    if [[ "$removed_loaders" -gt 0 ]]; then
        status_line FIXED "Removed $removed_loaders loader/twin file(s) referenced by .user.ini"
    fi
    return 0
}

clean_malicious_htaccess_auto_prepend() {
    local f line target resolved base bn tmp changed=0
    # auto_prepend_file persistence has been observed above the document root
    # and one level down as well, not only in the two WordPress .htaccess files.
    local candidates=(
        "$WP_PATH/.htaccess"
        "$WP_PATH/wp-content/.htaccess"
        "$WP_PATH/wp-admin/.htaccess"
        "$WP_PATH/wp-includes/.htaccess"
        "$(dirname "$WP_PATH")/.htaccess"
        "$USER_HOME/.htaccess"
    )
    : > "$REPORT_DIR/htaccess-auto-prepend-cleaned.txt"
    for f in "${candidates[@]}"; do
        [[ -f "$f" ]] || continue
        local malicious=0
        while IFS= read -r line; do
            target="$(sc_auto_prepend_target "$line")"
            [[ -n "$target" ]] || continue
            base="$(dirname "$f")"
            if [[ "$target" = /* ]]; then resolved="$(realpath -m "$target" 2>/dev/null || true)"; else resolved="$(realpath -m "$base/$target" 2>/dev/null || true)"; fi
            [[ -n "$resolved" ]] || continue
            case "$resolved" in "$WP_PATH"/*|"$USER_HOME"/*) ;; *) continue ;; esac
            bn="${resolved##*/}"
            if [[ "$bn" =~ ^\.?[A-Za-z0-9]{6,40}\.php$ ]] || { [[ -f "$resolved" ]] && grep -Eqi 'SC_(ADV|DB|OC|DD|TH|DP)|SCOCV:|SCV:[0-9]+\.|elite-module-cue|SCD1:|--sc-cli|--sc-succ|__scf_[A-Za-z0-9_]{6,}|SC_CORE_BOOT_VER' "$resolved" 2>/dev/null; }; then
                malicious=1
                [[ -f "$resolved" ]] && remove_high_confidence_file "$resolved" "htaccess-auto-prepend-loader"
            fi
        done < <(grep -Ei 'php(_admin)?_value[[:space:]]+auto_prepend_file|auto_prepend_file' "$f" 2>/dev/null || true)
        [[ "$malicious" -eq 1 ]] || continue
        status_line FOUND "Malicious .htaccess auto_prepend_file persistence detected: $f"
        sc_mark_campaign_evidence "malicious .htaccess auto_prepend_file: $f"
        preserve_evidence_file "$f" "malicious-htaccess-auto-prepend"
        chattr -ia -- "$f" 2>/dev/null || true
        tmp="$REPORT_DIR/htaccess-ap.$$.tmp"
        grep -Evi 'php(_admin)?_value[[:space:]]+auto_prepend_file|^[[:space:]]*auto_prepend_file[[:space:]]*=' "$f" > "$tmp" 2>/dev/null || true
        cat "$tmp" > "$f"
        rm -f -- "$tmp"
        printf '%s\n' "$f" >> "$REPORT_DIR/htaccess-auto-prepend-cleaned.txt"
        changed=$((changed+1))
        status_line FIXED "Removed malicious auto_prepend_file directive from $f"
    done
    [[ "$changed" -eq 0 ]] && status_line CLEAN "No malicious .htaccess auto_prepend_file persistence found" || true
    return 0
}

remove_random_loader_pairs() {
    local dir visible hidden bn stem removed=0
    : > "$REPORT_DIR/random-loader-pairs-removed.tsv"
    : > "$REPORT_DIR/random-loader-pairs-review.tsv"
    # Restrict automatic pair deletion to campaign-relevant locations and require
    # both hidden+visible twins with the same alphanumeric basename.
    for dir in "$WP_PATH" "$WP_PATH/wp-content" "$WP_PATH/wp-includes"; do
        [[ -d "$dir" ]] || continue
        while IFS= read -r visible; do
            [[ -f "$visible" ]] || continue
            bn="${visible##*/}"
            stem="${bn%.php}"
            [[ "$stem" =~ ^[A-Za-z0-9]{6,40}$ ]] || continue
            hidden="$dir/.${bn}"
            [[ -f "$hidden" ]] || continue

            # A matching hidden/visible random loader pair is abnormal, but the
            # shape alone also matches legitimate names (wp-includes/functions.php
            # plus an editor backup). Require SC content in one of the twins, or a
            # site that is already campaign-proven, before deleting both.
            if ! grep -Eq "$IOC_REGEX" "$visible" 2>/dev/null \
               && ! grep -Eq "$IOC_REGEX" "$hidden" 2>/dev/null \
               && [[ "${CAMPAIGN_EVIDENCE_RECORDED:-0}" -ne 1 && "${SC_PREVIOUS_CAMPAIGN_EVIDENCE:-0}" -ne 1 ]]; then
                printf '%s\t%s\n' "$visible" "$hidden" >> "$REPORT_DIR/random-loader-pairs-review.tsv"
                status_line REVIEW "Hidden/visible PHP loader pair without SC content; left for review: $visible"
                continue
            fi
            status_line FOUND "Random hidden/visible PHP loader pair: $visible + $hidden"
            sc_mark_campaign_evidence "random hidden/visible loader pair: $visible"
            remove_high_confidence_file "$visible" "random-loader-visible"
            remove_high_confidence_file "$hidden" "random-loader-hidden"
            printf '%s\t%s\n' "$visible" "$hidden" >> "$REPORT_DIR/random-loader-pairs-removed.tsv"
            removed=$((removed+1))
        done < <(find "$dir" -maxdepth 1 -type f -name '*.php' -print 2>/dev/null || true)
    done
    if [[ "$removed" -eq 0 ]]; then
        status_line CLEAN "No random hidden/visible PHP loader pairs found"
    else
        status_line FIXED "Removed $removed random hidden/visible loader pair(s)"
    fi
    return 0
}

SC_CAMPAIGN_ZIP_RE='(^|/)(ionic-scheduler-orb[^/]*|elite-module-cue|unity-manager-lite)/|(^|/)(ionic-scheduler-orb[^/]*|elite-module-cue|unity-manager-lite)\.php$'

scan_campaign_zip_ioc() {
    local z listing
    while IFS= read -r -d '' z; do
        [[ -f "$z" ]] || continue
        listing="$(unzip -Z1 "$z" 2>/dev/null || true)"
        [[ -n "$listing" ]] || continue
        if printf '%s\n' "$listing" | matches_stdin "$SC_CAMPAIGN_ZIP_RE"; then
            printf '%s\n' "$z"
        fi
    # The captured sample carried the same payload archive in wp-content/, in a
    # theme directory and under uploads/YYYY/MM. Scan the whole tree: the verdict
    # comes from the archive contents, so the false-positive risk stays nil.
    done < <(find "$WP_PATH" -type f -iname '*.zip' -size -64M -print0 2>/dev/null || true)
}

remove_campaign_zip_artifacts() {
    local z bn removed=0 listing
    : > "$REPORT_DIR/campaign-zips-removed.tsv"
    while IFS= read -r z; do
        [[ -f "$z" ]] || continue
        bn="${z##*/}"
        listing=''
        if command -v unzip >/dev/null 2>&1; then
            listing="$(unzip -Z1 "$z" 2>/dev/null || true)"
        elif command -v zipinfo >/dev/null 2>&1; then
            listing="$(zipinfo -1 "$z" 2>/dev/null || true)"
        fi

        # Filename is intentionally NOT trusted. Auto-delete when archive
        # contents identify the campaign plugin. Exact ABSPATH-derived archives
        # are already handled by remove_derived_campaign_artifacts().
        if [[ -n "$listing" ]] && printf '%s\n' "$listing" | matches_stdin "$SC_CAMPAIGN_ZIP_RE"; then
            status_line FOUND "Campaign ZIP contains ionic-scheduler-orb/elite-module-cue/unity-manager-lite payload: $z"
            sc_mark_campaign_evidence "campaign ZIP payload: $z"
            remove_high_confidence_file "$z" "campaign-plugin-zip"
            printf '%s\n' "$z" >> "$REPORT_DIR/campaign-zips-removed.tsv"
            removed=$((removed+1))
        fi
    done < <(scan_campaign_zip_ioc)
    if [[ "$removed" -eq 0 ]]; then
        status_line CLEAN "No content-confirmed ionic-scheduler-orb/elite-module-cue ZIP archive found"
    else
        status_line FIXED "Removed $removed content-confirmed campaign ZIP archive(s)"
    fi
    return 0
}

remove_campaign_g_files() {
    local relock=0 f removed=0
    # Deleting a direct child of immutable wp-includes requires a brief unlock.
    # HTTP is already 503, cron is paused, and the guard is active before this
    # function is called, so this window is contained.
    if wp_includes_has_attr i; then
        chattr -i "$WP_PATH/wp-includes" 2>/dev/null || true
        relock=1
    fi
    while IFS= read -r f; do
        [[ -n "$f" && -f "$f" ]] || continue
        # Evidence always precedes destruction, on every cleanup path.
        preserve_evidence_file "$f" "campaign-g-file"
        sc_mark_campaign_evidence "campaign .g_* PHP file: $f"
        chattr -ia -- "$f" 2>/dev/null || true
        if rm -f -- "$f" 2>/dev/null; then
            printf '%s\n' "$f" >> "$REPORT_DIR/g-files-removed.txt"
            removed=$((removed+1))
        else
            status_line FAILED "Could not remove campaign .g_* PHP file: $f"
        fi
    done < <(scan_g_files)
    if [[ "$relock" -eq 1 ]]; then
        chattr +i "$WP_PATH/wp-includes" 2>/dev/null || true
    fi
    if [[ "$removed" -gt 0 ]]; then
        status_line FIXED "Removed $removed campaign .g_* PHP file(s)"
    else
        status_line CLEAN "No campaign .g_* PHP files required deletion"
    fi
}

wp_includes_attr_flags() {
    # lsattr is unavailable/unsupported on some shared-hosting filesystems. An
    # unguarded pipeline here aborted the worker with a fake ERROR.
    lsattr -d "$WP_PATH/wp-includes" 2>/dev/null | awk '{print $1}' | head -n 1 || true
}

wp_includes_has_attr() {
    local attr="$1"
    local flags
    flags="$(wp_includes_attr_flags)"
    [[ "$flags" == *"$attr"* ]]
}

WP_INCLUDES_LOCK_AVAILABLE=1
lock_wp_includes() {
    # Idempotent: chattr can behave differently across filesystems when the
    # immutable flag is already present. Do not call it if +i is already set.
    if wp_includes_has_attr i; then
        log "wp-includes is already immutable; keeping existing +i lock"
        return 0
    fi
    # A filesystem without chattr support degrades to "no temporary lock"; the
    # HTTP 503, the paused crontab and the HARD PHP guard still contain the site.
    if chattr +i "$WP_PATH/wp-includes" 2>/dev/null; then
        return 0
    fi
    WP_INCLUDES_LOCK_AVAILABLE=0
    status_line REVIEW "Filesystem does not support the temporary wp-includes lock; continuing without it"
    return 0
}

unlock_wp_includes() {
    # Remove only the containment flags added/used by this workflow. This helper
    # is not called when the directory was already immutable before the script.
    chattr -ia "$WP_PATH/wp-includes"
}

# Resolve the interpreter once here, at top level. Doing it lazily from inside
# a command substitution is what made v42 re-probe every installed PHP per file.
sc_php_resolve_bin
log "SC WordPress cleanup/verification v43-offline started"
log "User: $CPUSER"
log "WordPress: $WP_PATH"
log "Report directory: $REPORT_DIR"
term_line ""
term_line "Terminal status colors: CLEAN=green, FIXED=blue, REVIEW=yellow, FOUND/FAILED=red"
log "Derived artifact candidates: ldr=$ROLE_LDR zip=$ROLE_ZIP inst=$ROLE_INST sw=$ROLE_SW dbopt=$ROLE_DBOPT theme=$ROLE_TH"

{
    echo "ABSPATH=$ABSPATH"
    echo "loader_hash=$ROLE_LDR"
    echo "zip_hash=$ROLE_ZIP"
    echo "installer_hash=$ROLE_INST"
    echo "service_worker_hash=$ROLE_SW"
    echo "db_option_hash=$ROLE_DBOPT"
    echo "theme_marker_hash=$ROLE_TH"
} > "$REPORT_DIR/derived-artifact-names.txt"

lsattr -d "$WP_PATH/wp-includes" > "$REPORT_DIR/wp-includes-attributes-before.txt" 2>&1 || true
ORIGINAL_WP_INCLUDES_IMMUTABLE=0
ORIGINAL_WP_INCLUDES_APPEND_ONLY=0
wp_includes_has_attr i && ORIGINAL_WP_INCLUDES_IMMUTABLE=1 || true
wp_includes_has_attr a && ORIGINAL_WP_INCLUDES_APPEND_ONLY=1 || true
{
    echo "original_immutable=$ORIGINAL_WP_INCLUDES_IMMUTABLE"
    echo "original_append_only=$ORIGINAL_WP_INCLUDES_APPEND_ONLY"
} > "$REPORT_DIR/wp-includes-original-flags.txt"
# Defaults so print_final_summary is safe from any early exit path.
PLUGIN_OK=1
CORE_OK=0
CORE_CHECK_STATUS="NOT_RUN"
PLUGIN_CHECK_STATUS="NOT_RUN"
STRICT_DB_REMAIN=0
FS_DIRTY=0

worker_exit_cleanup() {
    local rc=$?
    # EXIT may be entered with an intentional non-zero status (10/20/30/40).
    # Disable ERR handling inside cleanup so normal false tests and the preserved
    # exit status are not logged as spurious worker failures.
    trap - ERR
    set +e
    rm -f -- "${DB_DEFAULTS_FILE:-}" 2>/dev/null || true
    DB_DEFAULTS_FILE=""
    restore_runtime_quarantine || true
    # In account mode the coordinator owns the temporary lock and guarantees
    # account-wide release. Standalone mode must never leave WordPress core locked.
    if [[ "${SC_ACCOUNT_MODE:-0}" -ne 1 && -n "${WP_PATH:-}" && -d "$WP_PATH/wp-includes" ]]; then
        if chattr -ia -- "$WP_PATH/wp-includes" 2>/dev/null; then
            status_line FIXED "Exit cleanup cleared immutable/append-only flags from wp-includes" || true
        else
            status_line FAILED "Exit cleanup could not clear immutable/append-only flags from wp-includes" || true
        fi
    fi
    return "$rc"
}

# The EXIT trap is installed BEFORE the wp-includes lock is taken. In v33 the
# lock came first, leaving a window in which a signal could leave core immutable.
trap worker_exit_cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

log "Locking wp-includes during inspection"
lock_wp_includes


if [[ "$SC_ACCOUNT_MODE" -eq 1 ]]; then
    log "Account coordinator quarantine already active; skipping per-site HTTP 503, cron pause and local process guard"
    status_line CLEAN "Using account-wide quarantine/guard from coordinator"
else
    log "Enabling standalone runtime quarantine before cleanup"
    enable_htaccess_quarantine
    pause_user_crontab
    inventory_account_wordpress
    kill_existing_account_php
    start_quarantine_guard
fi

# The campaign keeps thb_/thv_ copies of the files it replaced inside its
# runtime directory. Inventory them before that directory is deleted.
report_sc_stored_originals

log "Checking and removing known ionic-scheduler-orb campaign plugin"
remove_ionic_scheduler_orb
log "Checking and removing confirmed echo-compiler-plus persistence"
remove_echo_compiler_plus
log "Checking and removing confirmed elite-module-cue persistence"
remove_elite_module_cue
log "Removing elite-module-cue state/coordination artifacts"
remove_elite_state_artifacts
log "Removing current-user /tmp/.sc_<md5> campaign lock files"
remove_tmp_sc_locks

log "Killing known running .g_* and .sc_/.gr_ malware processes"
kill_malware_processes
log "Removing confirmed .sc_/.gr_ runtime and clustered state artifacts"
remove_sc_runtime_variant
log "Removing known campaign .g_* PHP files while quarantine guard is active"
remove_campaign_g_files

log "Removing exact ABSPATH-derived SC loader/ZIP/installer/service-worker artifacts"
remove_derived_campaign_artifacts
log "Removing campaign-named PHP files that contain high-confidence SC runtime/IOC evidence"
remove_random_hex_sc_ioc_files
log "Inspecting .wp-object-cache-<hex>.dat/.dat.lkg candidates and removing IOC-confirmed campaign artifacts"
remove_malicious_wp_object_cache_dat
log "Recording the SC campaign generation(s) marking this site"
sc_detect_campaign_versions
log "Scanning every PHP file under wp-content for SCV campaign markers"
remove_scv_wp_content_php
log "Scanning every PHP file under wp-content for obfuscated SC loaders (__scf_/boot guard)"
remove_obf_loader_php
log "Removing extensionless SC payloads and correlated .sc_/.kk_ marker files"
remove_campaign_extensionless_payloads
remove_campaign_marker_files

log "Cleaning malicious .user.ini and .htaccess auto_prepend_file persistence"
clean_malicious_user_ini
clean_malicious_htaccess_auto_prepend
log "Looking for random hidden/visible PHP loader pairs"
remove_random_loader_pairs
log "Inspecting ZIP archives for ionic-scheduler-orb/elite-module-cue campaign content"
remove_campaign_zip_artifacts

log "Removing marker-confirmed malicious advanced-cache.php and db.php drop-ins"
remove_malicious_dropins
log "Checking theme functions.php files for SC_TH and markerless echo-compiler-plus injections"
clean_malicious_theme_functions
clean_markerless_echo_theme_injection
log "Removing exact orphan SC guard stubs anywhere under wp-content"
clean_orphan_sc_guard_stubs_wp_content

###############################################################################
# Phase A: filesystem inspection - never aborts before DB inspection.
###############################################################################
status_line INFO "Starting complete filesystem verification"
log "Filesystem: collecting SC campaign indicators"
scan_g_files > "$REPORT_DIR/fs-g-files.txt"
scan_echo_compiler_paths > "$REPORT_DIR/fs-echo-compiler.txt"
scan_elite_module_cue_paths > "$REPORT_DIR/fs-elite-module-cue.txt"
scan_elite_state_artifacts > "$REPORT_DIR/fs-elite-state.txt"
scan_campaign_extensionless_payloads > "$REPORT_DIR/fs-extensionless-payloads.txt"
scan_campaign_marker_files > "$REPORT_DIR/fs-campaign-marker-files.txt"
scan_tmp_sc_locks > "$REPORT_DIR/fs-tmp-sc-locks.txt"
scan_sc_runtime_paths > "$REPORT_DIR/fs-sc-runtime.txt"
scan_loose_gr_runners > "$REPORT_DIR/fs-loose-gr-runners.txt"
scan_wp_object_cache_candidates > "$REPORT_DIR/fs-wp-object-cache-candidates.txt"
scan_wp_object_cache_ioc > "$REPORT_DIR/fs-wp-object-cache-ioc.txt"
scan_scv_wp_content_php > "$REPORT_DIR/fs-scv-php.txt"
scan_obf_loader_php > "$REPORT_DIR/fs-obf-loaders.txt"
scan_campaign_zip_ioc > "$REPORT_DIR/fs-campaign-zips.txt"
scan_sc_state_clusters > "$REPORT_DIR/fs-sc-state.txt"
scan_ioc_lines > "$REPORT_DIR/fs-ioc-lines.txt"
scan_watermark > "$REPORT_DIR/fs-watermark-files.txt"
scan_auto_prepend > "$REPORT_DIR/fs-auto-prepend.txt"
scan_malware_processes > "$REPORT_DIR/fs-g-processes.txt"
scan_theme_function_markers > "$REPORT_DIR/fs-theme-function-markers.txt"
scan_sc_stored_originals > "$REPORT_DIR/fs-sc-stored-originals.txt"

# Forensics that never gate the cleanup, but must not be lost: the error_log
# timeline. (The stored-original inventory was taken before the runtime
# directory holding it was removed.)
harvest_error_log_evidence

find "$WP_PATH" -type f -name '.*.php' -print 2>/dev/null \
    > "$REPORT_DIR/fs-hidden-php.txt" || true

find "$WP_PATH/wp-content/cache" -type f -name '*.php' -print 2>/dev/null \
    > "$REPORT_DIR/fs-cache-php.txt" || true
find "$WP_PATH/wp-content/uploads" -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' \) -print 2>/dev/null \
    > "$REPORT_DIR/fs-uploads-php.txt" || true

find "$WP_PATH/wp-content" -type f -iname '*.zip' -print 2>/dev/null \
    > "$REPORT_DIR/fs-zip-files.txt" || true

# Short-hex/core_/own_ PHP names remain report-only unless content also contains high-confidence SC runtime/IOC evidence;
# those PHP files are auto-removed by remove_random_hex_sc_ioc_files().
find "$WP_PATH" -type f -regextype posix-extended \
    -regex '.*/\.?[A-Za-z0-9]{6,40}\.(php|zip)$' -print 2>/dev/null \
    > "$REPORT_DIR/fs-short-hex-artifacts.txt" || true

# Explicitly search derived filenames from the recovered SC 4.0.3 variant.
find "$WP_PATH" -type f \( \
      -name "${ROLE_LDR}.php" -o -name ".${ROLE_LDR}.php" \
      -o -name "${ROLE_ZIP}.zip" -o -name ".${ROLE_ZIP}.zip" \
      -o -name "${ROLE_INST}.php" -o -name ".${ROLE_INST}.php" \
      -o -name "${ROLE_SW}.php" -o -name ".${ROLE_SW}.php" \
    \) -print 2>/dev/null > "$REPORT_DIR/fs-derived-artifacts.txt" || true

# MU plugins: size is only a hunting clue, not automatic proof.
if [[ -d "$WP_PATH/wp-content/mu-plugins" ]]; then
    find "$WP_PATH/wp-content/mu-plugins" -type f -name '*.php' ! -name 'ionic-scheduler-orb.php' ! -name 'elite-module-cue.php' -size +5k \
        -printf '%s\t%p\n' 2>/dev/null | sort -nr \
        > "$REPORT_DIR/fs-mu-plugins-over-5k.tsv" || true
else
    : > "$REPORT_DIR/fs-mu-plugins-over-5k.tsv"
fi

# Known drop-in/theme marker checks with line context.
for f in \
    "$WP_PATH/wp-content/db.php" \
    "$WP_PATH/wp-content/advanced-cache.php" \
    "$WP_PATH/wp-content/object-cache.php"; do
    [[ -f "$f" ]] || continue
    grep -HnE 'SC_DB_|SC_ADV_|SC_OC_|SCOCV:|SC_DD_|SC_TH_LD_|SCD1:|elite-module-cue|\.wp-object-cache-|a18xgj672mowjoum|0x3bc5de30|sc_payload' "$f" 2>/dev/null || true
done > "$REPORT_DIR/fs-dropin-markers.txt"

# Shared memory is report-only. Do not ipcrm automatically on a shared host.
ipcs -m 2>/dev/null | awk -v u="$CPUSER" 'NR <= 3 || $3 == u' \
    > "$REPORT_DIR/systemv-shm-user.txt" || true

FS_DIRTY=0
[[ -s "$REPORT_DIR/ionic-plugin-remaining.txt" ]] && FS_DIRTY=1
[[ -s "$REPORT_DIR/fs-g-files.txt" ]] && FS_DIRTY=1
[[ -s "$REPORT_DIR/fs-echo-compiler.txt" ]] && FS_DIRTY=1
[[ -s "$REPORT_DIR/fs-elite-module-cue.txt" ]] && FS_DIRTY=1
[[ -s "$REPORT_DIR/fs-elite-state.txt" ]] && FS_DIRTY=1
[[ -s "$REPORT_DIR/fs-extensionless-payloads.txt" ]] && FS_DIRTY=1
[[ -s "$REPORT_DIR/fs-tmp-sc-locks.txt" ]] && FS_DIRTY=1
[[ -s "$REPORT_DIR/fs-sc-runtime.txt" ]] && FS_DIRTY=1
[[ -s "$REPORT_DIR/fs-loose-gr-runners.txt" ]] && FS_DIRTY=1
[[ -s "$REPORT_DIR/fs-wp-object-cache-ioc.txt" ]] && FS_DIRTY=1
[[ -s "$REPORT_DIR/fs-scv-php.txt" ]] && FS_DIRTY=1
[[ -s "$REPORT_DIR/fs-obf-loaders.txt" ]] && FS_DIRTY=1
[[ -s "$REPORT_DIR/fs-campaign-zips.txt" ]] && FS_DIRTY=1
[[ -s "$REPORT_DIR/fs-sc-state.txt" ]] && FS_DIRTY=1
[[ -s "$REPORT_DIR/fs-ioc-lines.txt" ]] && FS_DIRTY=1
[[ -s "$REPORT_DIR/fs-g-processes.txt" ]] && FS_DIRTY=1
[[ -s "$REPORT_DIR/fs-dropin-markers.txt" ]] && FS_DIRTY=1
[[ -s "$REPORT_DIR/fs-theme-function-markers.txt" ]] && FS_DIRTY=1
[[ -s "$REPORT_DIR/fs-derived-artifacts.txt" ]] && FS_DIRTY=1
# auto_prepend_file itself can be legitimate, but a directive pointing at the
# campaign-style guard/short-hex loader is a high-confidence containment hit.
if grep -Eqi '/\.g_[A-Za-z0-9_-]+\.php|/\.?[A-Za-z0-9]{6,40}\.php' "$REPORT_DIR/fs-auto-prepend.txt" 2>/dev/null; then
    FS_DIRTY=1
fi

report_collateral_damage

if [[ "$SC_PREFLIGHT_ONLY" -eq 1 ]]; then
    if [[ "$FS_DIRTY" -eq 0 ]]; then
        status_line CLEAN "Preflight-only high-confidence filesystem cleanup verified clean"
        log "Preflight-only mode complete; no WordPress bootstrap or database operation was executed."
        exit 0
    fi
    status_line REVIEW "Preflight-only mode: high-confidence filesystem persistence remains after automatic cleanup"
    log "Preflight-only mode stopped before every WordPress/database operation. Review filesystem reports under $REPORT_DIR."
    exit 10
fi

###############################################################################
# Phase B: database inspection. This ALWAYS runs, even if FS_DIRTY=1.
###############################################################################
status_line INFO "Starting direct database inspection (no WP-CLI / no WordPress bootstrap)"
log "Database: parsing literal DB settings from wp-config.php as plain text (no PHP / no WP-CLI)"

if ! offline_config_load; then
    db_fail_skip "Could not safely parse wp-config.php as literal text: ${OFFLINE_CONFIG_ERROR:-unknown parser error}. Dynamic/env/concatenated config requires manual DB cleanup."
fi
[[ "$PREFIX" =~ ^[A-Za-z0-9_]+$ ]] || db_fail_skip "Could not determine a safe WordPress DB prefix (got '$PREFIX')."
select_db_client || db_fail_skip "Neither mariadb nor mysql client is available for direct database cleanup."
parse_db_host
prepare_db_defaults || db_fail_skip "Could not create root-only MariaDB client credentials file."

OPTIONS_TABLE="${PREFIX}options"
USERS_TABLE="${PREFIX}users"
USERMETA_TABLE="${PREFIX}usermeta"
POSTS_TABLE="${PREFIX}posts"

{
    echo "table_prefix=$PREFIX"
    echo "DB_NAME=$DB_NAME_CFG"
    echo "DB_USER=$DB_USER_CFG"
    echo "DB_HOST=$DB_HOST_CFG"
    echo "db_client=$DB_CLIENT"
    echo "mode=direct-mysql-no-wp-cli"
} > "$REPORT_DIR/db-config.txt"

log "Database: prefix=$PREFIX db=$DB_NAME_CFG user=$DB_USER_CFG host=$DB_HOST_CFG client=$DB_CLIENT"
log "Database: checking direct client connectivity with prefix-independent SELECT 1"
DB_CONNECT_ERR="$REPORT_DIR/db-connectivity-error.txt"
if ! db_query 'SELECT 1;' > "$REPORT_DIR/db-connectivity.txt" 2>"$DB_CONNECT_ERR"; then
    log "REVIEW: Direct database query phase unavailable; filesystem cleanup already completed for this site."
    if [[ -s "$DB_CONNECT_ERR" ]]; then
        DB_FIRST_ERR="$(head -n 1 "$DB_CONNECT_ERR" | tr '\n' ' ')"
        log "Direct database diagnostic: $DB_FIRST_ERR"
    fi
    log "Diagnostics: $REPORT_DIR/db-config.txt"
    log "Diagnostics: $DB_CONNECT_ERR"
    {
        echo "reason=db_query_unavailable"
        echo "filesystem_cleanup=completed"
        echo "database_cleanup=skipped"
        echo "offline_followup_steps=not_started"
    } > "$REPORT_DIR/db-phase-skipped.txt"
    status_line REVIEW "Direct database phase skipped for this site; continuing account cleanup. See db-connectivity-error.txt."
    print_final_summary "REVIEW - DIRECT DATABASE PHASE SKIPPED"
    exit 40
fi

log "Database: validating direct access to expected WordPress tables for prefix '$PREFIX'"
# Do not use information_schema for this gate. On some shared-hosting MariaDB
# setups metadata visibility can produce a false 0/3 result even though the
# WordPress DB credentials can query the actual tables. Direct SELECTs are the
# authoritative test and keep this phase before normal WordPress bootstrap.
DB_TABLE_VALIDATION_ERR="$REPORT_DIR/db-table-validation-errors.txt"
DB_TABLE_VALIDATION_FAILED="$REPORT_DIR/db-table-validation-failed.txt"
: > "$DB_TABLE_VALIDATION_ERR"
: > "$DB_TABLE_VALIDATION_FAILED"

for EXPECTED_TABLE in "$OPTIONS_TABLE" "$USERS_TABLE" "$USERMETA_TABLE" "$POSTS_TABLE"; do
    TABLE_ERR="$REPORT_DIR/.db-table-${EXPECTED_TABLE}.err"
    : > "$TABLE_ERR"
    if db_query "SELECT 1 FROM ${EXPECTED_TABLE} LIMIT 1;" >/dev/null 2>"$TABLE_ERR"; then
        log "Database: table access OK: $EXPECTED_TABLE"
    else
        printf '%s\n' "$EXPECTED_TABLE" >> "$DB_TABLE_VALIDATION_FAILED"
        {
            printf '%s: ' "$EXPECTED_TABLE"
            if [[ -s "$TABLE_ERR" ]]; then
                head -n 3 "$TABLE_ERR" | tr '\n' ' '
            else
                printf 'query failed without mysql error output'
            fi
            printf '\n'
        } >> "$DB_TABLE_VALIDATION_ERR"
    fi
    rm -f -- "$TABLE_ERR"
done

if [[ -s "$DB_TABLE_VALIDATION_FAILED" ]]; then
    log "ERROR: Expected WordPress table access failed for prefix '$PREFIX' in DB '$DB_NAME_CFG'."
    while IFS= read -r EXPECTED_TABLE; do
        [[ -n "$EXPECTED_TABLE" ]] || continue
        log "ERROR: Missing or inaccessible table: $EXPECTED_TABLE"
    done < "$DB_TABLE_VALIDATION_FAILED"
    [[ -s "$DB_TABLE_VALIDATION_ERR" ]] && log "Database client diagnostics: $DB_TABLE_VALIDATION_ERR"
    {
        echo "reason=expected_tables_unavailable"
        echo "filesystem_cleanup=completed"
        echo "database_cleanup=skipped"
        echo "offline_followup_steps=skipped"
    } > "$REPORT_DIR/db-phase-skipped.txt"
    status_line REVIEW "Expected WordPress tables are unavailable; direct DB phase skipped for this site and account cleanup will continue."
    print_final_summary "REVIEW - DIRECT DATABASE PHASE SKIPPED"
    exit 40
fi
log "Database: connectivity and direct table validation passed"

# Broad SC-family option inventory. This intentionally includes short generic
# names, but those are not automatically deleted unless the SC family is
# independently corroborated.
DB_SCAN_WHERE="
    option_name REGEXP '^sc_'
 OR option_name REGEXP '^_transient_(timeout_)?sc_'
 OR option_name REGEXP '^_site_transient_(timeout_)?sc_'
 OR option_name IN (
      'bu','bp','ic','src',
      'sw_url','sw_cached','sw_config','sw_config_sig'
    )
"

log "Database: inventorying known SC options/transients"
db_query "
SELECT option_id, option_name, LENGTH(option_value), autoload, MD5(option_value)
FROM ${OPTIONS_TABLE}
WHERE ${DB_SCAN_WHERE}
ORDER BY option_name, option_id;
" > "$REPORT_DIR/db-sc-options.tsv" 2>>"$LOG_FILE" || true

# Options that belong to allowlisted software (see sc_db_legit_option_names)
# are subtracted from every strict rule below: the delete, the evidence count
# and the post-clean verification. Anything kept is reported, never silent.
: > "$REPORT_DIR/db-legit-sc-options.txt"
if [[ -s "$REPORT_DIR/db-sc-options.tsv" ]]; then
    cut -f2 "$REPORT_DIR/db-sc-options.tsv" \
        | sed -E 's/^_(site_)?transient_(timeout_)?//' \
        | sort -u \
        | sc_db_legit_option_names > "$REPORT_DIR/db-legit-sc-options.txt" 2>/dev/null || true
fi
DB_LEGIT_KEEP_CLAUSE=""
DB_LEGIT_KEEP_LIST=""
while IFS= read -r legit_name; do
    [[ -n "$legit_name" ]] || continue
    for legit_variant in "$legit_name" "_transient_$legit_name" "_transient_timeout_$legit_name" \
                         "_site_transient_$legit_name" "_site_transient_timeout_$legit_name"; do
        DB_LEGIT_KEEP_LIST+="${DB_LEGIT_KEEP_LIST:+,}'${legit_variant}'"
    done
done < "$REPORT_DIR/db-legit-sc-options.txt"
if [[ -n "$DB_LEGIT_KEEP_LIST" ]]; then
    DB_LEGIT_KEEP_CLAUSE=" AND option_name NOT IN ($DB_LEGIT_KEEP_LIST)"
    status_line REVIEW "Kept $(awk 'END{print NR+0}' "$REPORT_DIR/db-legit-sc-options.txt") sc_* DB option(s) owned by allowlisted software: $(tr '\n' ' ' < "$REPORT_DIR/db-legit-sc-options.txt")"
fi

# High-confidence SC evidence excludes the collision-prone short keys.
SC_DB_EVIDENCE_COUNT="$(db_scalar "
SELECT COUNT(*)
FROM ${OPTIONS_TABLE}
WHERE (option_name REGEXP '^sc_'
   OR option_name REGEXP '^_transient_(timeout_)?sc_'
   OR option_name REGEXP '^_site_transient_(timeout_)?sc_')${DB_LEGIT_KEEP_CLAUSE};
")"
SC_DB_EVIDENCE_COUNT="${SC_DB_EVIDENCE_COUNT:-0}"

log "Database: checking large options (top 100, >=20 KiB)"
db_query "
SELECT option_id, option_name, LENGTH(option_value), autoload, MD5(option_value)
FROM ${OPTIONS_TABLE}
WHERE LENGTH(option_value) >= 20480
ORDER BY LENGTH(option_value) DESC
LIMIT 100;
" > "$REPORT_DIR/db-large-options.tsv" 2>>"$LOG_FILE" || true

log "Database: checking 8-12 char lowercase-hex option names"
db_query "
SELECT option_id, option_name, LENGTH(option_value), autoload, MD5(option_value),
       HEX(LEFT(option_value,16)),
       IF(LEFT(option_value,4)='H4sI',1,0)
FROM ${OPTIONS_TABLE}
WHERE option_name REGEXP '^[a-f0-9]{8,12}$'
ORDER BY LENGTH(option_value) DESC;
" > "$REPORT_DIR/db-hex-options.tsv" 2>>"$LOG_FILE" || true

log "Database: checking path-derived option candidate $ROLE_DBOPT"
ROLE_DBOPT_SQL="$(sql_escape_literal "$ROLE_DBOPT")"
db_query "
SELECT option_id, option_name, LENGTH(option_value), autoload, MD5(option_value)
FROM ${OPTIONS_TABLE}
WHERE option_name='${ROLE_DBOPT_SQL}';
" > "$REPORT_DIR/db-derived-option.tsv" 2>>"$LOG_FILE" || true

log "Database: scanning option values for campaign IOC strings"
offline_scan_db_ioc_values || status_line REVIEW "Option-value IOC scan could not be completed"

# Search raw serialized cron option without unserializing or loading WordPress.
log "Database: checking raw cron option for known campaign hooks"
db_query "
SELECT option_id,
       LENGTH(option_value),
       MD5(option_value),
       IF(LOCATE('sc_cron_fetch', option_value) > 0, 1, 0),
       IF(LOCATE('r1ckj5tjyx1yjm', option_value) > 0, 1, 0),
       IF(LOCATE('sc_', option_value) > 0, 1, 0)
FROM ${OPTIONS_TABLE}
WHERE option_name='cron';
" > "$REPORT_DIR/db-cron-indicators.tsv" 2>>"$LOG_FILE" || true

# Dump the raw cron value to a root-only report for later offline inspection.
# This file may be large but does not load/execute the serialized content.
db_query "SELECT option_value FROM ${OPTIONS_TABLE} WHERE option_name='cron';" \
    > "$REPORT_DIR/db-cron-raw.txt" 2>>"$LOG_FILE" || true

# `sc_cron_fetch` is a high-confidence SC campaign marker on its own. Persist
# that fact in this run even when an earlier cleaner execution has already
# deleted the strict sc_* options and filesystem artifacts. Without this, a
# rerun can incorrectly downgrade a still-present backup_<hex> rogue admin to
# review-only merely because the first run successfully removed other evidence.
CRON_SC_FETCH_EVIDENCE=0
if [[ -s "$REPORT_DIR/db-cron-indicators.tsv" ]]; then
    read -r _cron_id _cron_len _cron_md5 _cron_sc_fetch _cron_random _cron_any_sc < "$REPORT_DIR/db-cron-indicators.tsv" || true
    [[ "${_cron_sc_fetch:-0}" == 1 ]] && CRON_SC_FETCH_EVIDENCE=1
fi
if [[ "$CRON_SC_FETCH_EVIDENCE" -eq 1 ]]; then
    sc_mark_campaign_evidence "sc_cron_fetch marker in raw WordPress cron option"
    status_line FOUND "High-confidence SC cron marker remains in database: sc_cron_fetch"
fi

log "Database: listing direct database-level administrators"
db_query "
SELECT u.ID, u.user_login, u.user_email, u.user_registered
FROM ${USERS_TABLE} u
JOIN ${USERMETA_TABLE} um ON um.user_id=u.ID
WHERE um.meta_key='${PREFIX}capabilities'
  AND um.meta_value LIKE '%administrator%'
ORDER BY u.ID;
" > "$REPORT_DIR/db-admins.tsv" 2>>"$LOG_FILE" || true

SITEURL="$(db_query "SELECT option_value FROM ${OPTIONS_TABLE} WHERE option_name='siteurl' LIMIT 1;" 2>>"$LOG_FILE" | head -n 1 || true)"
SITE_HOST="${SITEURL#*://}"
SITE_HOST="${SITE_HOST%%/*}"
SITE_HOST="${SITE_HOST%%:*}"
if [[ ! "$SITE_HOST" =~ ^[A-Za-z0-9.-]+$ ]]; then
    SITE_HOST=""
fi

log "Database: checking suspicious administrator/user naming patterns"
SUSP_USER_WHERE="u.user_login REGEXP '^(admin_|adm_|administrator_|backup_)[a-f0-9]{6,16}$'"
if [[ -n "$SITE_HOST" ]]; then
    HOST_SQL="$(sql_escape_literal "$SITE_HOST")"
    SUSP_USER_WHERE="${SUSP_USER_WHERE} OR LOWER(u.user_email)=LOWER(CONCAT(u.user_login,'@','${HOST_SQL}'))"
fi

db_query "
SELECT u.ID, u.user_login, u.user_email, u.user_registered,
       IF(um.meta_value LIKE '%administrator%',1,0)
FROM ${USERS_TABLE} u
LEFT JOIN ${USERMETA_TABLE} um
  ON um.user_id=u.ID AND um.meta_key='${PREFIX}capabilities'
WHERE ${SUSP_USER_WHERE}
ORDER BY u.ID;
" > "$REPORT_DIR/db-suspicious-users.tsv" 2>>"$LOG_FILE" || true

# High-confidence rogue admins for this campaign. v25 no longer requires the
# email domain to equal siteurl (www/alias/migration differences caused misses).
# Auto-delete is enabled only when this site has independent SC campaign evidence,
# and the generated login is also the email local-part.
CAMPAIGN_SITE_PROVEN="$SC_PREVIOUS_CAMPAIGN_EVIDENCE"
for _evidence in \
    "$REPORT_DIR/sc-runtime-removed.tsv" \
    "$REPORT_DIR/sc-loose-gr-removed.tsv" \
    "$REPORT_DIR/random-hex-sc-ioc-removed.tsv" \
    "$REPORT_DIR/wp-object-cache-ioc-removed.tsv" \
    "$REPORT_DIR/scv-wp-content-removed.txt" \
    "$REPORT_DIR/dropins-removed.txt" \
    "$REPORT_DIR/fs-dropin-markers.txt" \
    "$REPORT_DIR/theme-functions-cleaned.txt" \
    "$REPORT_DIR/theme-markerless-echo-cleaned.txt" \
    "$REPORT_DIR/ionic-plugin-removed.txt" \
    "$REPORT_DIR/echo-compiler-plus-removed.txt" \
    "$REPORT_DIR/elite-module-cue-removed.txt" \
    "$REPORT_DIR/sc-stored-originals.tsv" \
    "$REPORT_DIR/campaign-evidence.txt"; do
    [[ -s "$_evidence" ]] && CAMPAIGN_SITE_PROVEN=1
done
[[ "${SC_DB_EVIDENCE_COUNT:-0}" -gt 0 ]] && CAMPAIGN_SITE_PROVEN=1
[[ "${CRON_SC_FETCH_EVIDENCE:-0}" -eq 1 ]] && CAMPAIGN_SITE_PROVEN=1
printf 'previous_preflight_evidence=%s\nsc_db_evidence_count=%s\ncron_sc_fetch_evidence=%s\nsite_campaign_proven=%s\n' \
    "$SC_PREVIOUS_CAMPAIGN_EVIDENCE" "${SC_DB_EVIDENCE_COUNT:-0}" "${CRON_SC_FETCH_EVIDENCE:-0}" "$CAMPAIGN_SITE_PROVEN" \
    > "$REPORT_DIR/campaign-site-proof.txt"

: > "$REPORT_DIR/db-auto-rogue-admins.tsv"
: > "$REPORT_DIR/db-auto-reassign-target.tsv"
if [[ "$CAMPAIGN_SITE_PROVEN" -eq 1 ]]; then
    db_query "
SELECT u.ID, u.user_login, u.user_email, u.user_registered
FROM ${USERS_TABLE} u
JOIN ${USERMETA_TABLE} um
  ON um.user_id=u.ID AND um.meta_key='${PREFIX}capabilities'
WHERE um.meta_value LIKE '%administrator%'
  AND u.user_login REGEXP '^(admin_|adm_|administrator_|backup_)[a-f0-9]{6,16}$'
  AND LOWER(SUBSTRING_INDEX(u.user_email,'@',1))=LOWER(u.user_login)
ORDER BY u.ID;
" > "$REPORT_DIR/db-auto-rogue-admins.tsv" 2>>"$LOG_FILE" || true

    db_query "
SELECT u.ID, u.user_login, u.user_email, u.user_registered
FROM ${USERS_TABLE} u
JOIN ${USERMETA_TABLE} um
  ON um.user_id=u.ID AND um.meta_key='${PREFIX}capabilities'
WHERE um.meta_value LIKE '%administrator%'
  AND NOT (
      u.user_login REGEXP '^(admin_|adm_|administrator_|backup_)[a-f0-9]{6,16}$'
      AND LOWER(SUBSTRING_INDEX(u.user_email,'@',1))=LOWER(u.user_login)
  )
ORDER BY u.ID ASC
LIMIT 1;
" > "$REPORT_DIR/db-auto-reassign-target.tsv" 2>>"$LOG_FILE" || true
else
    log "No independent SC campaign evidence for this site; generated-name admins remain review-only, not auto-deleted."
fi

log "Database: checking stored WordPress sessions"
db_query "
SELECT COUNT(*), COALESCE(SUM(LENGTH(meta_value)),0)
FROM ${USERMETA_TABLE}
WHERE meta_key='session_tokens' AND meta_value<>'';
" > "$REPORT_DIR/db-session-summary-before.tsv" 2>>"$LOG_FILE" || true

db_query "
SELECT user_id, LENGTH(meta_value), MD5(meta_value)
FROM ${USERMETA_TABLE}
WHERE meta_key='session_tokens' AND meta_value<>''
ORDER BY user_id;
" > "$REPORT_DIR/db-sessions-before.tsv" 2>>"$LOG_FILE" || true

log "Database: recording active_plugins option fingerprint"
db_query "
SELECT option_id, LENGTH(option_value), MD5(option_value), option_value
FROM ${OPTIONS_TABLE}
WHERE option_name='active_plugins';
" > "$REPORT_DIR/db-active-plugins.txt" 2>>"$LOG_FILE" || true

# Summarize inspection before any mutation.
{
    echo "filesystem_dirty=$FS_DIRTY"
    echo "sc_db_evidence_count=$SC_DB_EVIDENCE_COUNT"
    echo "siteurl=$SITEURL"
    echo "site_host=$SITE_HOST"
    echo "table_prefix=$PREFIX"
} > "$REPORT_DIR/inspection-summary.txt"

# Show the operator what was found before any destructive mutation.
print_inspection_summary

###############################################################################
# Phase C: direct database cleanup. This runs even if filesystem IOC remains,
# because it operates through mysql/mariadb directly and never bootstraps WordPress.
###############################################################################
# The strict `^sc_` delete below removes sc_own_manifest/sc_persist_manifest, so
# the campaign's own bookkeeping has to be read and acted on first.
log "Database: harvesting the campaign's own manifests before they are deleted"
if harvest_sc_db_manifests; then
    log "Removing files the campaign's own manifest claims to own"
    clean_manifest_paths
else
    status_line REVIEW "Campaign DB manifests could not be harvested; manifest-driven cleanup skipped"
fi

log "Starting direct database cleanup of strict SC persistence"
PLUGIN_OK=1
STRICT_DB_REMAIN=0
CORE_OK=0


# Always-safe family-specific keys/prefixes.
DB_DELETE_STRICT_WHERE="
    (option_name REGEXP '^sc_'
 OR option_name REGEXP '^_transient_(timeout_)?sc_'
 OR option_name REGEXP '^_site_transient_(timeout_)?sc_')${DB_LEGIT_KEEP_CLAUSE}
"

db_query "DELETE FROM ${OPTIONS_TABLE} WHERE ${DB_DELETE_STRICT_WHERE}; SELECT ROW_COUNT();" \
    > "$REPORT_DIR/db-delete-strict-result.txt" 2>>"$LOG_FILE" || db_fail_skip "Strict SC DB cleanup could not be executed."
STRICT_DELETED="$(tail -n 1 "$REPORT_DIR/db-delete-strict-result.txt" | tr -dc '0-9')"
STRICT_DELETED="${STRICT_DELETED:-0}"
log "AUTO-FIXED: deleted $STRICT_DELETED strict SC option/transient row(s)"
if [[ "$STRICT_DELETED" -gt 0 ]]; then status_line FIXED "Deleted $STRICT_DELETED strict SC DB row(s)"; else status_line CLEAN "No strict SC DB rows required deletion"; fi

# Short names can collide with legitimate plugins. Delete them only when SC was
# independently present in the DB before cleanup.
if [[ "$SC_DB_EVIDENCE_COUNT" -gt 0 ]]; then
    log "SC database evidence was present; deleting correlated bu/bp/ic/src and sw_* persistence keys"
    db_query "DELETE FROM ${OPTIONS_TABLE} WHERE option_name IN ('bu','bp','ic','src','sw_url','sw_cached','sw_config','sw_config_sig'); SELECT ROW_COUNT();" \
        > "$REPORT_DIR/db-delete-correlated-result.txt" 2>>"$LOG_FILE" || db_fail_skip "Correlated SC key cleanup could not be executed."
    CORRELATED_DELETED="$(tail -n 1 "$REPORT_DIR/db-delete-correlated-result.txt" | tr -dc '0-9')"
    CORRELATED_DELETED="${CORRELATED_DELETED:-0}"
    log "AUTO-FIXED: deleted $CORRELATED_DELETED correlated SC key row(s)"
if [[ "$CORRELATED_DELETED" -gt 0 ]]; then status_line FIXED "Deleted $CORRELATED_DELETED correlated SC DB key row(s)"; else status_line CLEAN "No correlated SC DB keys required deletion"; fi
else
    log "No independent SC DB evidence remained; bu/bp/ic/src and sw_* keys are report-only to avoid collisions."
fi

# Payload-store options: evidence is captured first, then they are deleted on a
# campaign-proven site. The captured 4.3.24 dump held 14 such rows (~977 KB);
# leaving them behind kept the campaign's own payload store on a "cleaned" site.
log "Database: deleting payload-store options after capturing evidence"
offline_delete_hex_options || db_fail_skip "Payload-store option cleanup could not be executed."

# Prepare post-clean user report files. If filesystem persistence remains,
# automatic rogue-admin deletion is deferred until the filesystem gate is clean;
# in that case the pre-clean suspicious list remains the review list.
: > "$REPORT_DIR/db-auto-rogue-admins-deleted.tsv"
: > "$REPORT_DIR/db-auto-rogue-admins-failed.tsv"
cp -a "$REPORT_DIR/db-suspicious-users.tsv" "$REPORT_DIR/db-suspicious-users-after.tsv" 2>/dev/null || : > "$REPORT_DIR/db-suspicious-users-after.tsv"

# Sessions can be removed directly, without WordPress bootstrap.
log "Destroying all WordPress sessions directly in usermeta"
db_query "DELETE FROM ${USERMETA_TABLE} WHERE meta_key='session_tokens'; SELECT ROW_COUNT();" \
    > "$REPORT_DIR/db-session-delete-result.txt" 2>>"$LOG_FILE" || db_fail_skip "Stored WordPress session tokens could not be deleted."
SESSIONS_DELETED="$(tail -n 1 "$REPORT_DIR/db-session-delete-result.txt" | tr -dc '0-9')"
SESSIONS_DELETED="${SESSIONS_DELETED:-0}"
log "AUTO-FIXED: deleted session_tokens for $SESSIONS_DELETED user(s)"
if [[ "$SESSIONS_DELETED" -gt 0 ]]; then status_line FIXED "Destroyed stored WordPress sessions for $SESSIONS_DELETED user(s)"; else status_line CLEAN "No stored WordPress session_tokens found"; fi

# Post-clean direct DB verification happens before later offline cron/salt/user mutations.
log "Rechecking SC database persistence after direct SQL cleanup"
db_query "
SELECT option_id, option_name, LENGTH(option_value), autoload, MD5(option_value)
FROM ${OPTIONS_TABLE}
WHERE ${DB_SCAN_WHERE}
ORDER BY option_name, option_id;
" > "$REPORT_DIR/db-sc-options-after.tsv" 2>>"$LOG_FILE" || true

db_query "
SELECT COUNT(*), COALESCE(SUM(LENGTH(meta_value)),0)
FROM ${USERMETA_TABLE}
WHERE meta_key='session_tokens' AND meta_value<>'';
" > "$REPORT_DIR/db-session-summary-after.tsv" 2>>"$LOG_FILE" || true

STRICT_DB_REMAIN="$(db_scalar "SELECT COUNT(*) FROM ${OPTIONS_TABLE} WHERE ${DB_DELETE_STRICT_WHERE};")"
STRICT_DB_REMAIN="${STRICT_DB_REMAIN:-0}"
if [[ "$STRICT_DB_REMAIN" -ne 0 ]]; then
    log "ERROR: Strict SC database persistence remains after cleanup: $STRICT_DB_REMAIN row(s)."
fi

if [[ "$FS_DIRTY" -eq 1 ]]; then
    log "Known filesystem IOCs are still present. Strict DB cleanup and session cleanup WERE performed; later offline cron/salt/user cleanup is intentionally deferred."
    log "Review filesystem: $REPORT_DIR/fs-ioc-lines.txt and $REPORT_DIR/fs-g-files.txt"
    log "Review database after cleanup: $REPORT_DIR/db-sc-options-after.tsv, db-large-options.tsv, db-hex-options.tsv, db-cron-indicators.tsv"
    log "Review users/sessions: $REPORT_DIR/db-admins.tsv, db-suspicious-users.tsv, db-sessions-before.tsv"
    log "wp-includes is temporarily immutable during cleanup and will be released by exit cleanup; clean remaining filesystem persistence, then rerun."
    term_section "FINAL STATUS"
    term_line "Status: PARTIAL CLEAN - DATABASE CLEANED, FILESYSTEM PERSISTENCE STILL PRESENT"
    term_line "Automatic DB cleanup WAS performed."
    term_line "Deferred/skipped steps: rogue-admin deletion/reassignment, offline WP-Cron rewrite, salt rotation, integrity checksum verification, unlock."
    term_line "Runtime quarantine will be restored on exit; standalone wp-includes -i/-a flags will also be cleared."
    term_line "Follow the WHAT TO DO NEXT section above, then rerun the script."
    term_line "Report: $REPORT_DIR"
    exit 10
fi

# Auto-delete high-confidence campaign rogue administrators without WordPress
# bootstrap. Reassign core post/page/CPT ownership directly in wp_posts, then
# delete usermeta + user inside a transaction. This intentionally does NOT fire
# plugin/user-delete hooks: during incident cleanup, executing those hooks would
# recreate the same bootstrap/reinfection risk this offline variant removes.
if [[ -s "$REPORT_DIR/db-auto-rogue-admins.tsv" ]]; then
    if [[ -s "$REPORT_DIR/db-auto-reassign-target.tsv" ]]; then
        read -r REASSIGN_ADMIN_ID REASSIGN_ADMIN_LOGIN REASSIGN_ADMIN_EMAIL REASSIGN_ADMIN_REGISTERED < "$REPORT_DIR/db-auto-reassign-target.tsv" || true
        if [[ "$REASSIGN_ADMIN_ID" =~ ^[0-9]+$ ]]; then
            status_line FIXED "Rogue-admin content reassign target: ID $REASSIGN_ADMIN_ID ($REASSIGN_ADMIN_LOGIN)"
            while IFS=$'\t' read -r ROGUE_ID ROGUE_LOGIN ROGUE_EMAIL ROGUE_REGISTERED; do
                [[ "$ROGUE_ID" =~ ^[0-9]+$ ]] || continue
                [[ "$ROGUE_ID" != "$REASSIGN_ADMIN_ID" ]] || continue
                status_line FOUND "High-confidence campaign rogue admin: ID $ROGUE_ID $ROGUE_LOGIN <$ROGUE_EMAIL>"
                if offline_delete_rogue_user "$ROGUE_ID" "$REASSIGN_ADMIN_ID"; then
                    printf '%s\t%s\t%s\t%s\t%s\n' "$ROGUE_ID" "$ROGUE_LOGIN" "$ROGUE_EMAIL" "$ROGUE_REGISTERED" "$REASSIGN_ADMIN_ID" >> "$REPORT_DIR/db-auto-rogue-admins-deleted.tsv"
                    status_line FIXED "Deleted rogue admin $ROGUE_LOGIN (ID $ROGUE_ID) by direct SQL; core post ownership reassigned to $REASSIGN_ADMIN_LOGIN (ID $REASSIGN_ADMIN_ID)"
                else
                    printf '%s\t%s\t%s\t%s\n' "$ROGUE_ID" "$ROGUE_LOGIN" "$ROGUE_EMAIL" "$ROGUE_REGISTERED" >> "$REPORT_DIR/db-auto-rogue-admins-failed.tsv"
                    status_line REVIEW "Could not direct-delete rogue admin $ROGUE_LOGIN (ID $ROGUE_ID); see rogue-admin-delete-${ROGUE_ID}.log"
                fi
            done < "$REPORT_DIR/db-auto-rogue-admins.tsv"
        else
            status_line REVIEW "High-confidence rogue admin(s) found, but no valid legitimate administrator ID is available for content reassignment"
            cp -a "$REPORT_DIR/db-auto-rogue-admins.tsv" "$REPORT_DIR/db-auto-rogue-admins-failed.tsv"
        fi
    else
        status_line REVIEW "High-confidence rogue admin(s) found, but no legitimate administrator remains for content reassignment"
        cp -a "$REPORT_DIR/db-auto-rogue-admins.tsv" "$REPORT_DIR/db-auto-rogue-admins-failed.tsv"
    fi
else
    status_line CLEAN "No high-confidence campaign rogue administrator accounts found"
fi

# Refresh suspicious-user inventory after automatic deletion so FINAL/REVIEW only
# reports users that still exist.
: > "$REPORT_DIR/db-suspicious-users-after.tsv"
db_query "
SELECT u.ID, u.user_login, u.user_email, u.user_registered,
       IF(um.meta_value LIKE '%administrator%',1,0)
FROM ${USERS_TABLE} u
LEFT JOIN ${USERMETA_TABLE} um
  ON um.user_id=u.ID AND um.meta_key='${PREFIX}capabilities'
WHERE ${SUSP_USER_WHERE}
ORDER BY u.ID;
" > "$REPORT_DIR/db-suspicious-users-after.tsv" 2>>"$LOG_FILE" || true

# SC campaign cron cleanup without WordPress bootstrap. The raw serialized cron
# option is read as HEX, decoded/unserialized under root-owned `php -n` with
# allowed_classes=false, filtered, reserialized, and written back with UNHEX().
log "Cleaning campaign WP-Cron hooks offline from the serialized cron option"
CRON_CLEAN_OK=1
if ! offline_clean_cron_option; then
    CRON_CLEAN_OK=0
    status_line REVIEW "Offline WP-Cron cleanup could not safely rewrite the cron option; see db-cron-raw.txt/wp-cron-before.hex"
    printf '%s\n' "offline cron rewrite failed" > "$REPORT_DIR/wp-cron-offline-review.txt"
fi

# Removing the plugin directory does not remove its entry from active_plugins.
log "Cleaning campaign plugin entries from active_plugins offline"
if ! offline_clean_active_plugins; then
    status_line REVIEW "Offline active_plugins cleanup could not safely rewrite the option; see active-plugins-before.hex"
    printf '%s\n' "offline active_plugins rewrite failed" > "$REPORT_DIR/active-plugins-offline-review.txt"
fi

log "Rotating WordPress authentication salts without WP-CLI"
SALT_ROTATE_RC=0
offline_rotate_salts || SALT_ROTATE_RC=$?
case "$SALT_ROTATE_RC" in
    0) printf '%s\n' "rotated_offline=1" > "$REPORT_DIR/salts.txt" ;;
    2) printf '%s\n' "rotated_offline=partial_or_skipped_nonliteral" > "$REPORT_DIR/salts.txt" ;;
    *) printf '%s\n' "rotated_offline=failed" > "$REPORT_DIR/salts.txt"; status_line REVIEW "Offline salt rotation failed; original wp-config backup is in the report directory" ;;
esac

###############################################################################
# Phase D: integrity verification.
###############################################################################
# v43-offline intentionally performs no WP-CLI checksum commands. `wp core` and
# `wp plugin` are PHP entry points and defeat the strongest containment property:
# no account-owned PHP is allowed to execute during cleanup. Filesystem/DB IOC
# verification remains a hard release gate; package integrity is explicitly
# reported as NOT RUN so the operator can reinstall from trusted packages later.
CORE_OK=1
PLUGIN_OK=1
CORE_CHECK_STATUS="SKIPPED_NO_WPCLI"
PLUGIN_CHECK_STATUS="SKIPPED_NO_WPCLI"
printf '%s\n' "SKIPPED: no WP-CLI is executed by v43-offline. Reinstall/verify WordPress core from a trusted package after containment." > "$REPORT_DIR/core-checksums.txt"
printf '%s\n' "SKIPPED: no WP-CLI is executed by v43-offline. Reinstall/verify plugins from trusted sources after containment." > "$REPORT_DIR/plugin-checksums.txt"
status_line REVIEW "Core/plugin checksum verification skipped by no-WP-CLI policy; filesystem + direct-DB IOC verification remains enforced"

log "Running final filesystem/process IOC scan while wp-includes remains locked"
remove_ionic_scheduler_orb
remove_echo_compiler_plus
remove_tmp_sc_locks
kill_malware_processes
remove_sc_runtime_variant
remove_campaign_g_files
remove_derived_campaign_artifacts
remove_random_hex_sc_ioc_files
remove_malicious_wp_object_cache_dat
remove_scv_wp_content_php
clean_malicious_user_ini
remove_malicious_dropins
clean_malicious_theme_functions
clean_markerless_echo_theme_injection
clean_orphan_sc_guard_stubs_wp_content
scan_g_files > "$REPORT_DIR/fs-g-files-after.txt"
scan_echo_compiler_paths > "$REPORT_DIR/fs-echo-compiler-after.txt"
scan_elite_module_cue_paths > "$REPORT_DIR/fs-elite-module-cue-after.txt"
scan_elite_state_artifacts > "$REPORT_DIR/fs-elite-state-after.txt"
scan_campaign_extensionless_payloads > "$REPORT_DIR/fs-extensionless-payloads-after.txt"
scan_tmp_sc_locks > "$REPORT_DIR/fs-tmp-sc-locks-after.txt"
scan_sc_runtime_paths > "$REPORT_DIR/fs-sc-runtime-after.txt"
scan_loose_gr_runners > "$REPORT_DIR/fs-loose-gr-runners-after.txt"
scan_wp_object_cache_candidates > "$REPORT_DIR/fs-wp-object-cache-candidates-after.txt"
scan_wp_object_cache_ioc > "$REPORT_DIR/fs-wp-object-cache-ioc-after.txt"
scan_scv_wp_content_php > "$REPORT_DIR/fs-scv-php-after.txt"
scan_obf_loader_php > "$REPORT_DIR/fs-obf-loaders-after.txt"
scan_campaign_zip_ioc > "$REPORT_DIR/fs-campaign-zips-after.txt"
scan_sc_state_clusters > "$REPORT_DIR/fs-sc-state-after.txt"
scan_ioc_lines > "$REPORT_DIR/fs-ioc-lines-after.txt"
scan_malware_processes > "$REPORT_DIR/fs-g-processes-after.txt"
report_collateral_damage
harvest_error_log_evidence

FINAL_IOC_OK=1
[[ -s "$REPORT_DIR/ionic-plugin-remaining.txt" ]] && FINAL_IOC_OK=0
[[ -s "$REPORT_DIR/fs-g-files-after.txt" ]] && FINAL_IOC_OK=0
[[ -s "$REPORT_DIR/fs-echo-compiler-after.txt" ]] && FINAL_IOC_OK=0
[[ -s "$REPORT_DIR/fs-elite-module-cue-after.txt" ]] && FINAL_IOC_OK=0
[[ -s "$REPORT_DIR/fs-elite-state-after.txt" ]] && FINAL_IOC_OK=0
[[ -s "$REPORT_DIR/fs-extensionless-payloads-after.txt" ]] && FINAL_IOC_OK=0
[[ -s "$REPORT_DIR/fs-tmp-sc-locks-after.txt" ]] && FINAL_IOC_OK=0
[[ -s "$REPORT_DIR/fs-sc-runtime-after.txt" ]] && FINAL_IOC_OK=0
[[ -s "$REPORT_DIR/fs-wp-object-cache-ioc-after.txt" ]] && FINAL_IOC_OK=0
verify_sc_manifest_paths || FINAL_IOC_OK=0
[[ -s "$REPORT_DIR/fs-scv-php-after.txt" ]] && FINAL_IOC_OK=0
[[ -s "$REPORT_DIR/fs-obf-loaders-after.txt" ]] && FINAL_IOC_OK=0
[[ -s "$REPORT_DIR/fs-campaign-zips-after.txt" ]] && FINAL_IOC_OK=0
[[ -s "$REPORT_DIR/fs-sc-state-after.txt" ]] && FINAL_IOC_OK=0
[[ -s "$REPORT_DIR/fs-ioc-lines-after.txt" ]] && FINAL_IOC_OK=0
[[ -s "$REPORT_DIR/fs-g-processes-after.txt" ]] && FINAL_IOC_OK=0
if [[ -s "$REPORT_DIR/php-validation-failed.tsv" ]]; then
    FINAL_IOC_OK=0
    log "ERROR: one or more PHP files could not be cleaned into a valid state; see php-validation-failed.tsv"
fi
if [[ -s "$REPORT_DIR/db-auto-rogue-admins-failed.tsv" ]]; then
    FINAL_IOC_OK=0
    log "ERROR: One or more high-confidence campaign rogue admins could not be auto-deleted/reassigned."
fi
if [[ "${CRON_CLEAN_OK:-1}" -ne 1 ]]; then
    FINAL_IOC_OK=0
    log "ERROR: Offline WP-Cron cleanup could not be verified; refusing clean status."
fi

# Post-clean DB file should contain no strict SC keys. Collision-prone short keys
# may remain when there was no independent SC DB evidence.
STRICT_DB_REMAIN="$(db_scalar "SELECT COUNT(*) FROM ${OPTIONS_TABLE} WHERE ${DB_DELETE_STRICT_WHERE};")"
STRICT_DB_REMAIN="${STRICT_DB_REMAIN:-0}"
if [[ "$STRICT_DB_REMAIN" -ne 0 ]]; then
    FINAL_IOC_OK=0
    log "ERROR: Strict SC database persistence remains after cleanup: $STRICT_DB_REMAIN row(s)."
fi

if [[ "$CORE_OK" -ne 1 || "$FINAL_IOC_OK" -ne 1 ]]; then
    log "Verification failed. wp-includes will be released by exit cleanup; no persistent immutable/append-only lock will be left."
    log "Review all reports under: $REPORT_DIR"
    print_final_summary "FAILED - MANUAL REVIEW REQUIRED"
    exit 20
fi

if [[ "$SC_ACCOUNT_MODE" -eq 1 ]]; then
    log "Verification passed under account coordinator; wp-includes remains temporarily locked only until the coordinator releases the account."
    print_final_summary "CLEAN / TEMPORARY ACCOUNT LOCK"
    exit 0
fi

###############################################################################
# Phase E: unlock and immediate reinfection watch.
###############################################################################
log "Verification passed. Clearing immutable/append-only flags from wp-includes"
unlock_wp_includes
lsattr -d "$WP_PATH/wp-includes" > "$REPORT_DIR/wp-includes-attributes-after-unlock.txt" 2>&1 || true

watch_reinfection() {
    local label="$1"
    local gfiles ionic runtime state scv obf ioc procs
    gfiles="$(scan_g_files)"
    ionic="$(scan_ionic_paths)"
    runtime="$(scan_sc_runtime_paths)"
    state="$(scan_sc_state_clusters)"
    scv="$(scan_scv_wp_content_php)"
    obf="$(scan_obf_loader_php)"
    ioc="$(scan_ioc_lines)"
    procs="$(scan_malware_processes)"

    if [[ -n "$gfiles" || -n "$ionic" || -n "$runtime" || -n "$state" || -n "$scv" || -n "$obf" || -n "$ioc" || -n "$procs" ]]; then
        {
            echo "[$label]"
            [[ -n "$gfiles" ]] && printf 'FILES:\n%s\n' "$gfiles"
            [[ -n "$ionic" ]] && printf 'IONIC:\n%s\n' "$ionic"
            [[ -n "$runtime" ]] && printf 'SC_RUNTIME:\n%s\n' "$runtime"
            [[ -n "$state" ]] && printf 'SC_STATE:\n%s\n' "$state"
            [[ -n "$scv" ]] && printf 'SCV_WP_CONTENT_PHP:\n%s\n' "$scv"
            [[ -n "$obf" ]] && printf 'OBF_SC_LOADERS:\n%s\n' "$obf"
            [[ -n "$ioc" ]] && printf 'SC_IOC:\n%s\n' "$ioc"
            [[ -n "$procs" ]] && printf 'PROCESSES:\n%s\n' "$procs"
        } >> "$REPORT_DIR/reinfection.txt"
        kill_malware_processes
        chattr -ia -- "$WP_PATH/wp-includes" 2>/dev/null || true
        log "REINFECTION DETECTED. wp-includes was left updateable; immutable/append-only flags were cleared."
        log "Review: $REPORT_DIR/reinfection.txt"
        print_final_summary "REINFECTION DETECTED / UNLOCKED"
        exit 30
    fi
}

# Both checkpoints are kept; only the waits got shorter. In account mode the
# coordinator re-scans the whole account after every site and runs its own
# longer watch at the end, so 40 s here bought little and cost 40 s x N of the
# window in which the account is 503'd and its crontab is paused.
log "Watching for immediate high-confidence filesystem/process reinfection"
sleep 5
watch_reinfection "after-5-seconds"
sleep 10
watch_reinfection "after-additional-10-seconds"

log "No immediate high-confidence reinfection detected"
log "Final status: CLEAN"
log "Reports: $REPORT_DIR"
print_final_summary "CLEAN"
exit 0
