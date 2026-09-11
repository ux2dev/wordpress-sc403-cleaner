#!/usr/bin/env bash
# sc403-vaccinate.sh - stop SC 4.3.24 from spreading to the sites it has not
# reached yet, by making them look like sites it has already taken.
#
# ===========================================================================
# WHY THIS WORKS
# ===========================================================================
# Before copying itself into a sibling WordPress root, the implant asks
# whether that root is already owned (deobfuscated core, sc_target_already_infected).
# The test is deliberately cheap, because it runs against every candidate on
# every spread cycle, and it is purely structural:
#
#     for dir in <root>/wp-content/mu-plugins, <root>/wp-content/plugins:
#         for each *.php directly in dir, and in each of dir's subdirectories:
#             if mtime % 100000 == 93819 and size >= 5000:  ALREADY INFECTED
#
# (sc_has_forged_mtime_and_size, core L372; the 93819 residue is
# sc_timestomp_offset, core L271.) There is no content check, no signature, no
# version handshake - the implant trusts its own timestomp watermark as proof
# of ownership. A root that answers yes is skipped outright:
#
#     foreach ($wordpress_roots as $target_root) {
#         if (sc_target_already_infected($target_root)) { continue; }
#
# So a single inert file with the right size and the right mtime removes a site
# from the spread entirely - both the mu-plugin write and the plugin-directory
# write, and therefore also sc_remote_activate_plugin(), which only runs after
# a successful plugin-directory write.
#
# ===========================================================================
# WHAT THIS IS AND IS NOT
# ===========================================================================
# IS:     containment. It stops sites from becoming infected. It is the single
#         highest-value thing you can do in the first five minutes of this
#         incident, because it is fast, reversible, and does not require the
#         infected sites to be cleaned first.
# IS NOT: cleanup. On an already-infected site it changes nothing. Run
#         sc403-killchain.sh or sc403-superclean.sh for that.
# IS NOT: permanent. It exploits a check the next build can trivially change.
#         The durable fix is one OS user per site, so the PHP process cannot
#         write to a neighbour at all. Treat this as the thing that holds the
#         line while you do that.
#
# The vaccine file is plain, inert, commented PHP: `return;` on the third line
# and nothing executable after it. It is padded with random hex inside a
# comment purely to clear the 5000-byte threshold. It contains no implant
# strings, so cleanup engines and host-side scanners will not flag it.
#
# ===========================================================================
# USAGE
# ===========================================================================
#   ./sc403-vaccinate.sh                       # DRY RUN - report only
#   ./sc403-vaccinate.sh --execute             # plant on every clean root found
#   ./sc403-vaccinate.sh --execute --all       # plant on infected roots too
#   ./sc403-vaccinate.sh --verify              # re-check; exit 1 if any lapsed
#   ./sc403-vaccinate.sh --execute --remove    # take it all back out
#   ./sc403-vaccinate.sh --root /home/u/site --execute      # explicit roots
#   ./sc403-vaccinate.sh --search /home --execute           # explicit search base
#   ./sc403-vaccinate.sh --cron                # print a crontab line for --verify
#
# Run as root to cover every account, or as the account user for one account.
# Files are created owned by whoever runs it; as root, ownership is copied from
# the site's own wp-content directory so nothing ends up root-owned inside a
# user's tree.
#
# License: GPL-2.0-or-later. No warranty. Read it before you run it.

set -uo pipefail

VERSION=1.0.0
EXECUTE=0
REMOVE=0
VERIFY_ONLY=0
INCLUDE_INFECTED=0
ROOTS=()
SEARCH=()
VACCINE_NAME="sc403-vaccine.php"
RESIDUE=93819
MIN_SIZE=5000

usage() { sed -n '2,68p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --execute)  EXECUTE=1; shift ;;
    --remove)   REMOVE=1; shift ;;
    --verify)   VERIFY_ONLY=1; shift ;;
    --all)      INCLUDE_INFECTED=1; shift ;;
    --root)     ROOTS+=("${2:?--root needs a path}"); shift 2 ;;
    --search)   SEARCH+=("${2:?--search needs a path}"); shift 2 ;;
    --cron)     printf '17 4 * * * %s --verify >> /var/log/sc403-vaccine.log 2>&1\n' "$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"; exit 0 ;;
    -h|--help)  usage; exit 0 ;;
    *)          echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done

# --verify implies a read-only run whatever else was passed.
[ "$VERIFY_ONLY" -eq 1 ] && EXECUTE=0

say()  { printf '%s\n' "$*"; }
warn() { printf '%s\n' "$*" >&2; }

# ---------------------------------------------------------------------------
# Discovery. These are the same candidate roots the implant's own
# sc_build_candidate_roots() walks (core L4535), plus the search bases you
# pass, so the sweep covers everything its spread routine can reach. The
# implant scans each candidate to a depth of 2; we go deeper, because being
# broader than the malware is free and being narrower is not.
# ---------------------------------------------------------------------------
discover() {
  local bases=() b
  if [ ${#SEARCH[@]} -gt 0 ]; then
    bases=("${SEARCH[@]}")
  else
    bases=(/home /var/www /var/www/vhosts /var/www/html /srv/www /srv/users /usr/local/www)
    # Whatever tree we are standing in, plus its neighbours - this is the
    # dirname chain the implant walks up from its own ABSPATH.
    b=$(pwd); bases+=("$b" "$(dirname "$b")")
    [ -n "${HOME:-}" ] && bases+=("$HOME")
  fi
  for b in "${bases[@]}"; do
    [ -d "$b" ] && [ -r "$b" ] || continue
    find "$b" -maxdepth 6 -type d -name wp-admin 2>/dev/null | sed 's|/wp-admin$||'
  done | sort -u
}

# ---------------------------------------------------------------------------
# Is this root already carrying the implant? Structural probe only - the same
# shape the report documents, not a content scan. Used to decide whether
# vaccinating is meaningful (on an infected root it is not) and to label the
# output honestly.
# ---------------------------------------------------------------------------
is_infected() {
  local root="$1" wc="$1/wp-content" f
  [ -d "$wc" ] || return 1
  # Derived staging directory - exact, from md5(ABSPATH.'dir').
  local dirh
  dirh=$(derive "$root" dir 8)
  [ -d "$wc/.sc_$dirh" ] && return 0
  for f in db.php advanced-cache.php object-cache.php; do
    [ -f "$wc/$f" ] && grep -qE 'SC_DB_BEGIN|SC_ADV_BEGIN|SC_OC_BEGIN' "$wc/$f" 2>/dev/null && return 0
  done
  # A watermarked PHP file that is not ours.
  while IFS= read -r f; do
    [ "$(basename "$f")" = "$VACCINE_NAME" ] && continue
    return 0
  done < <(find "$wc/mu-plugins" "$wc/plugins" -maxdepth 2 -type f -name '*.php' \
             2>/dev/null | while IFS= read -r p; do
               m=$(mtime_of "$p"); [ -n "$m" ] && [ $((m % 100000)) -eq "$RESIDUE" ] && printf '%s\n' "$p"
             done)
  return 1
}

md5s() {
  if command -v md5sum >/dev/null 2>&1; then printf '%s' "$1" | md5sum | cut -d' ' -f1
  elif command -v md5 >/dev/null 2>&1;    then printf '%s' "$1" | md5 -q
  else printf ''; fi
}
derive() { # $1 root, $2 role, $3 length
  md5s "${1%/}/$2" | cut -c1-"$3"
}

# Portable stat. GNU stat, BSD stat, then perl, which is on every cPanel box.
mtime_of() {
  stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null \
    || perl -e 'print((stat($ARGV[0]))[9])' "$1" 2>/dev/null
}
size_of() {
  stat -c %s "$1" 2>/dev/null || stat -f %z "$1" 2>/dev/null \
    || perl -e 'print((stat($ARGV[0]))[7])' "$1" 2>/dev/null
}

# Set mtime to the most recent past timestamp whose 100000-residue is 93819.
# `touch -d @epoch` is GNU-only and `touch -t` needs a formatted string that
# BSD and GNU date disagree about, so perl's utime is the portable primary.
set_watermark() { # $1 = path
  local now wm
  now=$(date +%s)
  wm=$(( now - now % 100000 + RESIDUE ))
  [ "$wm" -gt "$now" ] && wm=$(( wm - 100000 ))
  if command -v perl >/dev/null 2>&1; then
    perl -e 'utime $ARGV[0], $ARGV[0], $ARGV[1] or exit 1' "$wm" "$1" && return 0
  fi
  touch -d "@$wm" "$1" 2>/dev/null && return 0
  warn "  ! could not set mtime on $1 - install perl or GNU coreutils"
  return 1
}

# ---------------------------------------------------------------------------
# The vaccine file itself.
#
# Deliberately contains no implant strings: no version marker, no option
# names, no contract addresses, no dotted staging-directory spelling. A file
# that trips the cleanup engine's IOC scan would make every future
# verification run report the site as dirty.
# ---------------------------------------------------------------------------
write_vaccine() { # $1 = path
  local f="$1" tmp
  tmp="$f.tmp.$$"
  {
    cat <<'PHP'
<?php
/**
 * SC 4.x spread vaccine - inert. Planted by sc403-vaccinate.sh.
 *
 * This file exists to be counted, not to run. The 4.x implant decides whether
 * a WordPress root is already infected by looking for any PHP file of at
 * least 5000 bytes, in mu-plugins or plugins, whose modification time has a
 * particular fixed residue. It does not look at the contents. This file has
 * that size and that mtime, so the implant's spread routine treats this site
 * as already taken and skips it - which is the entire point.
 *
 * There is no executable logic below: the `return` on the next statement ends
 * the include, and everything after it is one comment holding random hex used
 * only as padding to clear the size threshold.
 *
 * DO NOT "fix" the modification time. Restoring it from a backup, rsyncing
 * with -t, or letting a plugin touch it removes the protection silently.
 * Re-run `sc403-vaccinate.sh --verify` after any restore.
 *
 * Remove this file once every site in this hosting account runs as its own OS
 * user, which makes cross-site writes impossible and makes this unnecessary.
 */
return;
/* padding - random hex, no meaning
PHP
    # 3000 bytes of urandom -> 6000 hex characters, comfortably over the
    # 5000-byte threshold once the header above is counted.
    if command -v od >/dev/null 2>&1; then
      head -c 3000 /dev/urandom | od -An -tx1 | tr -d ' \n'
    elif command -v xxd >/dev/null 2>&1; then
      head -c 3000 /dev/urandom | xxd -p | tr -d '\n'
    else
      perl -e 'open(my $r, "<", "/dev/urandom"); read($r, my $b, 3000); print unpack("H*", $b);'
    fi
    printf '\n*/\n'
  } > "$tmp" || { warn "  ! cannot write $tmp"; return 1; }

  local sz
  sz=$(size_of "$tmp")
  if [ -z "$sz" ] || [ "$sz" -lt "$MIN_SIZE" ]; then
    warn "  ! vaccine only ${sz:-0} bytes, need >= $MIN_SIZE - not installing"
    rm -f "$tmp"; return 1
  fi

  # Match the surrounding tree's ownership, so running this as root does not
  # leave a root-owned file inside a user's wp-content.
  if [ "$(id -u)" -eq 0 ]; then
    local ref owner
    ref=$(dirname "$(dirname "$f")")   # .../wp-content
    if [ -d "$ref" ]; then
      if ! chown --reference="$ref" "$tmp" 2>/dev/null; then
        # BSD chown has no --reference.
        owner=$(stat -f '%u:%g' "$ref" 2>/dev/null)
        [ -n "$owner" ] && chown "$owner" "$tmp" 2>/dev/null
      fi
    fi
  fi
  chmod 0444 "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$f" || { warn "  ! cannot move into place: $f"; rm -f "$tmp"; return 1; }
  set_watermark "$f"
}

# Does the vaccine at this root currently satisfy the implant's own test?
check_vaccine() { # $1 = root -> 0 effective, 1 lapsed, 2 absent
  local f="$1/wp-content/mu-plugins/$VACCINE_NAME" m s
  [ -f "$f" ] || return 2
  m=$(mtime_of "$f"); s=$(size_of "$f")
  [ -n "$m" ] && [ -n "$s" ] || return 1
  [ "$s" -ge "$MIN_SIZE" ] || return 1
  [ $((m % 100000)) -eq "$RESIDUE" ] || return 1
  return 0
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

say "sc403-vaccinate $VERSION  mode=$(
  if [ "$VERIFY_ONLY" -eq 1 ]; then echo VERIFY
  elif [ "$EXECUTE" -eq 1 ] && [ "$REMOVE" -eq 1 ]; then echo REMOVE
  elif [ "$EXECUTE" -eq 1 ]; then echo EXECUTE
  else echo DRY-RUN; fi)"

if [ ${#ROOTS[@]} -eq 0 ]; then
  say "discovering WordPress roots..."
  while IFS= read -r r; do [ -n "$r" ] && ROOTS+=("$r"); done < <(discover)
fi
[ ${#ROOTS[@]} -gt 0 ] || { warn "no WordPress roots found - pass --root or --search"; exit 1; }
say "roots: ${#ROOTS[@]}"
say ""

PLANTED=0; SKIPPED=0; LAPSED=0; OK=0; FAILED=0; INFECTED=0

for root in "${ROOTS[@]}"; do
  mu="$root/wp-content/mu-plugins"
  f="$mu/$VACCINE_NAME"

  if [ "$REMOVE" -eq 1 ]; then
    if [ -f "$f" ]; then
      if [ "$EXECUTE" -eq 1 ]; then
        chmod 0644 "$f" 2>/dev/null; rm -f "$f" && say "[removed] $f" || { warn "[FAIL   ] cannot remove $f"; FAILED=$((FAILED+1)); }
      else
        say "[dry    ] would remove $f"
      fi
    fi
    continue
  fi

  check_vaccine "$root"; state=$?

  if [ "$VERIFY_ONLY" -eq 1 ]; then
    case $state in
      0) say "[ok     ] $root"; OK=$((OK+1)) ;;
      1) say "[LAPSED ] $root - vaccine present but no longer counts (mtime or size changed)"; LAPSED=$((LAPSED+1)) ;;
      2) say "[MISSING] $root - no vaccine"; LAPSED=$((LAPSED+1)) ;;
    esac
    continue
  fi

  if [ $state -eq 0 ]; then
    say "[ok     ] $root - already vaccinated"; OK=$((OK+1)); continue
  fi

  if [ "$INCLUDE_INFECTED" -eq 0 ] && is_infected "$root"; then
    say "[skip   ] $root - ALREADY INFECTED; clean it first (vaccine changes nothing here)"
    INFECTED=$((INFECTED+1)); SKIPPED=$((SKIPPED+1)); continue
  fi

  if [ "$EXECUTE" -eq 0 ]; then
    say "[dry    ] would vaccinate $root"; continue
  fi

  if [ ! -d "$mu" ]; then
    mkdir -p "$mu" 2>/dev/null || { warn "[FAIL   ] cannot create $mu"; FAILED=$((FAILED+1)); continue; }
    if [ "$(id -u)" -eq 0 ]; then
      chown --reference="$root/wp-content" "$mu" 2>/dev/null || true
    fi
  fi
  if [ ! -w "$mu" ]; then
    warn "[FAIL   ] not writable: $mu"; FAILED=$((FAILED+1)); continue
  fi

  if write_vaccine "$f" && check_vaccine "$root"; then
    say "[planted] $root"; PLANTED=$((PLANTED+1))
  else
    warn "[FAIL   ] $root - vaccine written but does not satisfy the check; inspect $f"
    FAILED=$((FAILED+1))
  fi
done

say ""
if [ "$VERIFY_ONLY" -eq 1 ]; then
  say "verify: $OK effective, $LAPSED lapsed or missing, of ${#ROOTS[@]} roots"
  [ "$LAPSED" -gt 0 ] && {
    say "re-arm with: $0 --execute"
    exit 1
  }
  exit 0
fi

if [ "$REMOVE" -eq 1 ]; then
  say "remove pass complete ($FAILED failures)"
  exit $([ "$FAILED" -gt 0 ] && echo 2 || echo 0)
fi

say "planted $PLANTED, already effective $OK, skipped $SKIPPED (infected: $INFECTED), failed $FAILED"
[ "$EXECUTE" -eq 0 ] && say "DRY RUN - nothing was written. Re-run with --execute."
say ""
say "Next:"
say "  - infected roots are NOT contained by this. Clean them: sc403-killchain.sh --execute"
say "  - re-verify after any backup restore or rsync:  $0 --verify"
say "  - install a daily check:                        $0 --cron"
say "  - the permanent fix is one OS user per site; then remove with --remove"
exit $([ "$FAILED" -gt 0 ] && echo 2 || echo 0)
