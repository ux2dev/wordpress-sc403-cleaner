# SC 4.x for hosting providers

A runbook for the people with root on the box. It assumes you are dealing with
more than one infected account, that your customers cannot fix this themselves,
and that you have to keep the rest of the server running while you work.

If you are a site owner rather than a provider, read the [README](README.md)
instead - this document tells your host what to do, not you.

---

## Why this one is your problem and not the customer's

Two of the three things that actually stop SC 4.x are outside a customer's
reach, and one of them is not optional:

1. **Restarting the PHP workers.** The payload keeps a copy of itself in System V
   shared memory and runs a detached CLI PHP daemon. Neither lives in a file.
   A customer deleting files through File Manager cannot touch either, so their
   cleanup is undone on the next request, every time. Only you can restart the
   pool.
2. **One OS user per site.** The malware spreads to every WordPress install the
   PHP user can write to. On a shared account, cleaning one site and leaving its
   neighbour infected means you have cleaned nothing. Only you can change the
   account layout.
3. `auto_prepend_file` at the vhost level, `disable_functions`, and denying PHP
   execution in `uploads/` are also yours.

Everything a customer *can* do - delete plugins, change passwords, reinstall
WordPress from the dashboard - this malware survives.

---

## The one rule

> **The unit of infection is the OS user, not the site.**

Clean an entire account in one pass or do not start. A single missed sibling
reinfects everything you just cleaned, typically within the hour. This is why
`sc403-superclean.sh` quarantines every WordPress tree under the account before
it cleans the first one.

---

## Stage 1 - find them all, fleet-wide

Run as root. Read-only, nothing is modified.

```bash
./sc403-scan.sh -q                 # discovers /home, /var/www, /var/www/vhosts, /srv
```

Exit codes: `0` nothing found, `1` warnings only, `2` critical. So for a per-account
sweep that you can drop into a cron or a ticketing hook:

```bash
for home in /home/*; do
    [ -d "$home" ] || continue
    if ! ./sc403-scan.sh -q -p "$home" >/dev/null 2>&1; then
        echo "$(basename "$home") : NEEDS REVIEW"
    fi
done
```

### The log sweep - the one detection only you can run

Every infected site serves its malicious service worker from a URL derived from
its own install path, and the result is always an eight-digit post ID beginning
with 9. **Nobody has ninety-one million posts.** Your access logs therefore
contain a near-zero-false-positive record of which sites served the worker and
which client IPs fetched it - including sites that were "cleaned" months ago and
whose administrators are still carrying it.

```bash
# any site on the box, any time period, one pattern:
zgrep -lE '[?&]p=9[0-9]{7}' /var/log/nginx/*access.log* 2>/dev/null

# or exact, per docroot - derive the two real endpoint IDs first:
./sc403-derive.sh --find /home --tsv | awk -F'\t' '$2=="endpoint"{print $1, $4}'
```

Each hit is an administrator's browser that is still a persistence node. That
list is what Stage 5 is for.

### Reading the result

Treat as **actively spreading, handle today**:

- `auto_prepend_file` found anywhere, or `SC_WC` in `wp-config.php`
- a twin MU-plugin / ordinary-plugin pair with the same slug
- any predicted derived artefact present
- more than one account on the box hitting on the same day

Treat as **infected, schedule**: markers in drop-ins or theme, watermarked
mtimes, padded multi-megabyte PHP, derived option rows.

Treat as **evidence, not infection**: orphaned 12-hex option rows on their own
(the site was moved while infected), `?p=` hits in old logs with a clean
filesystem today. Both mean somebody's browser still needs cleaning.

---

## Stage 2 - contain before you clean

Per account, in this order:

```bash
# 1. suspend or serve a static maintenance page for every domain on the account
# 2. pause the account's crontab
crontab -u "$USER" -l > /root/sc403/crontab-"$USER".bak && crontab -u "$USER" -r
# 3. snapshot BEFORE touching anything - files and databases
```

Your snapshot is the only trustworthy evidence, because the malware backdates
what it writes: file timestamps on the account are falsified by design, and
`db.php` is routinely stamped to 2020.

**Capture the database rows now**, while they still exist:

```bash
./sc403-dbdump.sh /home/<user>/public_html --out /root/sc403/<user>
```

That writes `sc_c2_cache` and `sc_last_c2` (the live C2 URLs, in cleartext), the
service-worker URL and the JavaScript it was serving, and the list of
administrators holding forged sessions. **None of those rows are named `sc_*`**,
so the cleanup destroys them. Once they are gone you cannot tell the customer
which of their staff need to clean a browser.

---

## Stage 3 - clean the account

```bash
# dry run first, always - prints the whole plan, changes nothing
./sc403-killchain.sh -p /home/<user>/public_html

# then, for the whole account:
./sc403-superclean.sh <user>
```

`sc403-superclean.sh` requires root, derives each site's artefact names and feeds
them to the engine as exact per-account IoCs, captures the worker evidence before
the database pass destroys it, runs `wp-sc-account-cleaner-v45.sh` across every
site, installs the browser neutralizer on each one afterwards, and bundles the
whole thing with a sha256 manifest.

For a single site, `sc403-killchain.sh --execute` walks K0-K8 in order. Two
arguments decide whether it works:

```bash
./sc403-killchain.sh -p /home/<user>/public_html --execute \
    --pool-cmd 'systemctl restart php8.2-fpm' \
    --evidence /root/sc403/<user>
```

- **`--pool-cmd` must genuinely restart that account's PHP workers.** If it fails
  silently, K2 did not happen: shared memory and the CLI daemon survive, and
  every later step is undone within a request. Verify by hand, per PHP version,
  per pool. On LiteSpeed it is `lswsctrl restart` or a per-user `lsphp` kill;
  on CloudLinux with mod_lsapi, restarting the account's processes is not the
  same as restarting Apache.
- **`--evidence` should point outside the compromised account**, ideally onto a
  different filesystem.

### K2 targets the site's owner, not you

The guard daemon, the shared-memory segment and the PHP workers belong to the
**site's OS user**. Running as root, the killchain reads the owner off the site
root and goes after that user's processes - not root's. If it is run as neither
root nor the owner it stops the chain before any file is deleted, on purpose: a
half-completed K2 followed by K4 is precisely what makes this malware look
immortal.

---

## Stage 4 - verify, and mind the trap

**The malware counts your deletions.** Before rewriting a drop-in it checks
`sc_reins_<key>`, which holds `"<day>|<count>"`, and refuses to rewrite once the
count reaches three for the current UTC day. Delete the same file a fourth time
and it does not come back - **until midnight UTC**, when the day rolls over and
the file returns.

So a site that has been fought with three times today will pass any verification
you run today. The scanner reads those counters and says so explicitly:

```
  [CRITICAL] THIS SITE IS IN BACKOFF. A clean result right now proves nothing.
```

**Do not close the ticket on the same UTC day you cleaned.** Re-verify after
00:00 UTC:

```bash
./sc403-scan.sh -p /home/<user>/public_html
```

Those same counters also answer a question you often cannot otherwise answer:
`sc_reins_*` tells you how many times somebody has already been round this loop
on this site, and `sc_ini_dead` means the implant's own canary refused the
`auto_prepend_file` write because the site was fataling - which usually lines up
with WordPress's `recovery_mode_email_last_sent` in the same table.

---

## Stage 5 - the customer's half, which you cannot do for them

Server-side cleanup does not end the incident, and saying so plainly up front
saves you the second ticket. Until the customer acts, their browser can still
re-upload the payload through your freshly cleaned filesystem using their own
authenticated session.

They must:

1. **Unregister the service worker** in every browser and profile used to
   administer the site (`chrome://serviceworker-internals`, or DevTools →
   Application → Service Workers → Unregister), then clear cookies, Cache Storage
   and IndexedDB for the domain.
2. **Rotate all eight salts in `wp-config.php`.** Forged sessions are valid for
   fourteen days and **survive password changes**. Only new salts kill them.
3. Change every administrator password, from a cleaned device.
4. Rotate anything that was readable on the account: database password, FTP/SSH,
   control panel, SMTP and API keys.

Installing `00-sc403-sw-neutralizer.php` into `wp-content/mu-plugins/` on every
cleaned site handles step 1 passively - it serves a self-destructing worker at
the derived endpoint, so infected browsers clean themselves on the next visit.
`sc403-superclean.sh` installs it for you. Leave it in place for about 30 days,
until its counters have been flat.

A template you can adapt:

> Your site was infected with self-healing malware that also installs itself into
> the browsers of anyone who logs into wp-admin. We have cleaned the server side.
> **Three things only you can do**, and the infection is not over until they are
> done: (1) in every browser you use to manage the site, unregister the service
> worker for your domain and clear the site's cookies and storage; (2) ask us to
> rotate the eight security salts in your `wp-config.php` - your existing login
> sessions were forged and password changes alone do not end them; (3) change all
> administrator passwords from a device you have already cleaned. We have a list
> of the IP addresses that fetched the malicious component from your site, which
> tells us how many browsers are affected.

---

## What not to do

- **Do not restore from backup without checking the backup.** Anything taken
  after the infection date contains it, and the file timestamps are forged, so
  you cannot date it from the filesystem. Scan the restored tree before you put
  it live.
- **Do not delete files before restarting the pool.** This is the single mistake
  that produces "we cleaned it four times and it keeps coming back".
- **Do not run `DELETE FROM wp_options WHERE option_name LIKE 'sc\_%'`.** It
  misses the fourteen derived rows entirely - which are the implant's actual
  state - while destroying `sc_c2_cache` and `sc_last_c2`, your only record of
  the live C2.
- **Do not rely on file hashes.** Every write is padded with megabytes of random
  hex; no two infections share one. This also means AV and integrity monitoring
  tuned to hashes will not see it.
- **Do not clean one site on a multi-site account.** See The one rule.
- **Do not treat a quiet site as a clean site on the same day.** See Stage 4.

---

## Stage 6 - stop it coming back

In descending order of how much they buy you:

| Control | Effect |
|---|---|
| **One OS user and one PHP-FPM pool per site** | Ends lateral spread outright. This is the only control that turns an account-wide compromise into a single-site one. |
| **Code directories not writable by the PHP user** | `chmod` alone is not enough: `chmod()` needs ownership, not write permission, and the malware chmods around read-only directories. The owner must be a different user from the PHP worker. |
| `disable_functions = shmop_open,shmop_read,shmop_write,ftok,popen,proc_open` | Removes the shared-memory node and the CLI guard daemon. Note `exec`/`shell_exec`/`system` are **not** how it spawns the daemon, so blocking only those does nothing. |
| Deny PHP execution in `wp-content/uploads/` | `uploads/` must stay writable, so it is the landing zone. Denying execution makes a dropped payload inert. |
| Forbid `auto_prepend_file` at the vhost/pool level | Removes the pre-WordPress execution path the whole persistence chain depends on. |
| Fleet log alerting on `[?&]p=9[0-9]{7}` | Catches reinfection and stale browsers across every account, cheaply. |

Worth knowing when a customer asks: **`DISALLOW_FILE_MODS` does not stop this.**
It gates WordPress's own admin routes, and the payload never asks WordPress for
permission - it writes with `file_put_contents()` from a drop-in that loads
before plugins. It closes exactly two doors: the browser worker's
plugin-upload path, and stolen-admin-password-to-backdoor-plugin. It also
disables background security updates, so on an unmaintained site it is often a
net loss.

---

## One-page checklist

```
[ ] 1  Scan the whole box as root, list affected accounts        ./sc403-scan.sh -q
[ ] 2  Log sweep for ?p=9XXXXXXX across all vhost logs
[ ] 3  Per account: suspend domains, pause crontab
[ ] 4  Snapshot files + databases to somewhere off the account
[ ] 5  Capture DB evidence                                       ./sc403-dbdump.sh
[ ] 6  Dry run                                                   ./sc403-killchain.sh -p ...
[ ] 7  Clean the WHOLE account                                   ./sc403-superclean.sh <user>
[ ] 8  Confirm the pool restart actually restarted the workers
[ ] 9  Neutralizer installed in mu-plugins on every cleaned site
[ ] 10 Rotate salts + DB password + panel/FTP/SSH
[ ] 11 Tell the customer about their browsers (template above)
[ ] 12 RE-VERIFY AFTER 00:00 UTC                                 ./sc403-scan.sh -p ...
[ ] 13 Sweep the neighbours: every account on the same box
[ ] 14 Platform fixes from Stage 6, so this account cannot do it again
```

---

## When to stop cleaning and rebuild instead

Cleaning is the right call for most sites. Rebuild from known-good sources if:

- the account has been reinfected after a completed, verified pass;
- you find the implant in more than one account on a box and cannot establish
  which was first;
- the customer cannot or will not rotate credentials and clean browsers;
- there is evidence of hands-on-keyboard activity beyond the implant.

In those cases: fresh WordPress core and vendor plugin packages, migrate content
only, and treat every credential the account ever held as public.

---

GPL-2.0-or-later, like the rest of this repo. If you run this at scale and find
something the tooling misses - a derived role, a new C2 host, a build that
behaves differently - please open an issue. Providers see patterns nobody else
can.
