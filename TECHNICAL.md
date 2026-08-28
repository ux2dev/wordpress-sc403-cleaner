# SC 4.0.3 - technical notes for defenders

Why this infection behaves the way it does, written for people who are trying to
stop it rather than run it. It explains the mechanism only as far as needed to
justify the defenses. If you want the operational checklist, that is in the
[README](README.md); this document is the reasoning underneath it.

Everything here is drawn from public analysis (MD Pabel, Monarx, Seven Labs,
Jump.BG, August 2026) and from PHP and WordPress core source. Code shown is
deobfuscated, simplified and inert - it illustrates a shape, it is not a payload.

---

## The one root cause

Strip away the nine hiding places and the Ethereum C2 and the browser worker, and
the reason this malware is hard to kill reduces to a single sentence:

> In this deployment model, "can execute code" and "can rewrite the code that
> executes" are the same privilege.

A conventional application is protected by a separation the operating system
enforces for free: the process runs as an unprivileged user, but the program on
disk is owned by root and is read-only to that user. Compromising the *process*
does not let you rewrite the *program*.

The typical WordPress shared-hosting setup collapses that separation. The PHP
worker runs as the **same OS user that owns the PHP files**. So any code execution
is also code *rewrite* permission. The attacker does not merely get to run inside
your site; they get to become part of it, permanently, using nothing more exotic
than `file_put_contents()`.

Persistence, then, is not something the malware *adds*. It is a privilege the
environment *grants*, and the malware simply spends it. Every behavior below is
this one privilege exercised in a different location.

---

## Two stages, and why only one of them matters

```
Stage 0  attacker obtains PHP execution, or a single arbitrary file write
            |   (the entry bug; interchangeable; never recovered in any analysis)
            v
Stage 1  that code writes the payload with file_put_contents() / copy() / rename()
            |   (no capability is checked - nothing asks WordPress for anything)
            v
Stage 2  .user.ini and .htaccess set auto_prepend_file
            |   the payload now runs before WordPress loads, on every request
            v
         self-healing persistence mesh is live
```

Stage 0 is the part people fixate on ("which plugin let them in?"). It is the
least important part, for two reasons:

1. **Every entry route ends in the same state** - arbitrary PHP as the web user.
   A file-upload bug, a stolen SFTP password, a supply-chain plugin, and lateral
   spread from a sibling site all converge there. The specific vulnerability is a
   variable that does not change the outcome.
2. **None of the published analysis could recover it.** The files are timestomped,
   so the filesystem cannot date the breach, and the samples contain persistence
   and theft logic but no reliable trace of the first exploit. mdpabel lists entry
   only as hypotheses.

Stage 1 is the step defenders expect a WordPress setting to block, and it is
exactly the step no WordPress setting touches. Once arbitrary PHP runs in your
document root, writing a file is a language feature. The only thing that can deny
it is a layer below PHP.

---

## Stage 0: where the first byte actually comes from

A natural objection to the "self-healing" story: the recovery loop rebuilds the
payload *from a store* - the database, shared memory, a ZIP. But at the very first
moment of infection none of those stores exist yet. So where does the first copy
come from?

The resolution is the single most useful thing to understand about arrival:

> The persistence stores are the **output** of infection, not the input. The first
> copy can never come from a store, because the first copy is what creates the
> stores. It always comes from **outside the victim.**

There is no bootstrap paradox. The mesh is what the payload builds *after* it
lands; it is never how it lands. Stage 0 delivers the bytes from elsewhere, by one
of five carriers:

1. **Inline in the exploit request.** A file-upload or file-write bug is triggered
   over HTTP, and the payload rides in that request body. The bytes existed on the
   attacker's side and crossed the network; nothing was on your disk until the
   request that wrote it.

2. **A small dropper fetches the rest.** Stage 1 writes a few-hundred-byte stub
   that pulls the full body. This is where the Ethereum resolver earns its place at
   *bootstrap*, not just for C2: the stub carries no blockable download URL. It
   issues `eth_call` (selector `0x3bc5de30`) against the contract, receives the
   current server address, and fetches the payload from there. Arrival and
   persistence reuse the same dead-drop resolver.

3. **Inside a plugin (supply chain).** No separate write at all - the full payload
   ships within a plugin the administrator installed deliberately (the Seven Labs
   case: `sp-news-and-widget`, `content-sync-helper`, `wordpesso`). The plugin's
   own activation code seeds the mesh. Stage 0 and Stage 1 collapse into an install
   click.

4. **Credentialed upload.** Stolen SFTP / FTP / SSH / control-panel access. The
   attacker simply writes the file. No WordPress step exists, so there was never a
   bootstrap question - the bytes came from the attacker's own disk over an
   authenticated channel.

5. **Lateral spread from a sibling.** For the second site on a shared account,
   Stage 0 *is* the first site's already-running mesh. Site 1's payload reads its
   own copy and writes it into site 2's document root, because they share a UID.
   The bytes come from another victim's store - still external to site 2.

### Why Stage 0 is the defender's window

Persistence is silent: it is local reads and writes inside a process you cannot
trust, hidden behind hooks the payload installs. **Arrival is the one moment the
malware is visible from outside itself,** because it has to cross a boundary it
does not yet control, and that boundary keeps records the payload cannot reach:

| Carrier | Boundary crossed | Evidence left, outside the payload's reach |
|---|---|---|
| Exploit / dropper | network | HTTP access + WAF logs; a POST with a payload-shaped body; outbound `eth_call` to a public Ethereum RPC from the PHP user |
| Supply-chain plugin | package | plugin provenance; a diff against the vendor's genuine ZIP; "installed from outside the official repository" |
| Credentialed upload | authentication | SFTP / SSH / panel auth logs; a session from an unexpected IP or time |
| Lateral spread | OS user / UID | a *different* site's PHP process writing into this docroot; patient-zero sharing nothing with the new site but an OS user |

This is the concrete reason the incident-response guidance says to correlate
backups against **server and provider logs, not file timestamps.** The timestamps
are forged by design; the arrival is not, because it happened before the payload
was running locally to cover it. If you want to answer "how did it get in", Stage 0
is the only stage that can tell you - and only from logs written outside the
compromised PHP process.

## The persistence mesh, as a consequence not a design

Because execution equals rewrite, the payload can place a complete, self-sufficient
copy of itself anywhere the PHP user can write. It does. Each copy is an
**independent execution path** that can rebuild the others.

```
                    payload source (~185 KB PHP)
                            |  gzdeflate + base64
        +----------+--------+--------+-----------+----------+
        v          v        v        v           v          v
   wp_options   db.php   theme    ZIP files   SysV shm   mu-plugin
   (sc_payload  drop-in  functions (uploads,  (fileless, (the live
    _persistent) copy    .php block  themes)   ftok key)  copy)
```

There is no primary and no backups. These are peers. The important property is not
how many there are, it is that they occupy **different trust domains**:

| Store | Survives ... | Why it is reachable |
|---|---|---|
| `mu-plugins/<alias>.php` | nothing special | auto-loaded by WordPress |
| `db.php`, `advanced-cache.php` | plugin/theme deletion | drop-ins load *before* mu-plugins |
| theme `functions.php` block | plugin deletion | theme loads regardless of plugin state |
| `wp_options` row | all file deletion | it is not a file |
| ZIP replicas | top-level file deletion | seeded into uploads and theme dirs too |
| System V shared memory | *all disk deletion* | lives in the PHP process, not on disk |
| `auto_prepend_file` loader | WordPress being bypassed | runs before WordPress at the PHP layer |

Deletion only wins if you sever **every** path at once, faster than any single one
executes. On a live site answering requests, you cannot - one surviving path runs
on the very next hit and rebuilds the rest. This is why the correct response is
*containment first* (stop the workers), not deletion first.

---

## The recovery loop

The "self-healing" is a pull, not a push. Nothing runs on a timer racing your
deletion. Instead, whatever executes on the next request checks whether the live
copy is intact and, if not, reconstructs it. Deletion is the trigger.

Deobfuscated and simplified for explanation. Inert. Not runnable as-is.

```php
<?php
// Present in db.php / advanced-cache.php / the theme block. Runs every request.

$target        = WP_CONTENT_DIR . '/mu-plugins/trace-scanner-lite.php';
$expected_size = 185171;

// The health check: missing OR truncated both count as "needs repair".
if ( ! file_exists( $target ) || filesize( $target ) < $expected_size ) {

    $code = null;
    if ( $opt = get_option( 'sc_payload_persistent' ) ) {   // 1. database
        $code = gzinflate( base64_decode( $opt ) );
    } elseif ( $z = glob( WP_CONTENT_DIR . '/*.zip' ) ) {    // 2. ZIP replica
        $code = read_first_php_from_zip( $z[0] );
    } elseif ( function_exists( 'shmop_open' ) ) {           // 3. shared memory
        $code = read_from_shm( ftok( ABSPATH . 'wp-config.php', 's' ) );
    } else {
        $code = SELF_EMBEDDED_COPY;                          // 4. this file's own copy
    }

    if ( $code && strncmp( $code, '<?php', 5 ) === 0 ) {
        @chmod( dirname( $target ), 0755 );
        file_put_contents( $target, $code );                 // DB/ZIP/mem  ->  disk
        @chmod( $target, 0444 );                             // lock it back to read-only
        if ( function_exists( 'opcache_invalidate' ) ) {
            opcache_invalidate( $target, true );             // so the new copy runs now
        }
    }
}
```

Two details that matter operationally:

- **`filesize() < $expected_size`.** A partial or queued deletion trips it. A file
  manager that truncates before unlinking, or antivirus that quarantines by zeroing
  the file, hands the loop its trigger and gets the file rewritten. Removal has to
  be atomic and coordinated, not incremental.
- **`chmod( dirname(...), 0755 )` then `chmod( $target, 0444 )`.** The read-only
  `0444` you find during triage is not protecting the file *from* the malware - the
  malware set it, and it flips it back at will. Which leads to the next point.

---

## Why the WordPress-level defenses do not bind

Each of these is enforced by the very interpreter the attacker now runs inside. A
guard cannot arrest the person operating it.

### `DISALLOW_FILE_MODS`

Feeds one function, `wp_is_file_mod_allowed()` in `wp-includes/load.php`, which
`map_meta_cap()` uses to revoke a fixed capability set (`edit_plugins`,
`install_plugins`, `update_core`, and so on). It is a permission check on
**WordPress's own admin routes**. The payload never uses those routes - it writes
files directly - so there is nothing for the constant to deny. As a side effect it
also disables background security updates (`WP_Automatic_Updater::is_disabled()`
calls the same function), so on an unmaintained site it is often a net loss. It
does close two doors: the stolen-admin-password-to-uploader path, and the service
worker's plugin-upload reinstall. Both go through wp-admin's uploader. Neither is
how the payload persists.

### `chmod 0444` on the files

`chmod()` requires **ownership, not write permission**. Where PHP runs as the file
owner - the common shared-hosting case - the payload owns the file, so it can
`chmod` it writable, replace it, and `chmod` it back. The recovered sample does
precisely this; its MU copy was found at `0444`. Mode bits are an obstacle to the
site owner, not to code running as the owner.

### Security plugins, WAF-in-PHP, integrity scanners loaded by WordPress

All of them are things WordPress *loads*. `auto_prepend_file` runs **before**
WordPress loads. Anything downstream of the attacker's boot code can be disabled,
filtered, or lied to by it - the sample already hooks `pre_user_query`, the REST
responses, Site Health, and file-manager listings to hide itself from exactly
these tools. You cannot defend a boot sequence from inside it.

---

## The test that separates real controls from theater

For any proposed defense, ask one question:

> **Is this enforced by a layer the attacker's code is not already standing on?**

- Enforced by PHP, inside the request the attacker controls -> theater. It can be
  bypassed, and this malware bypasses it.
- Enforced by the OS kernel, outside the PHP process -> real. The attacker's PHP is
  not the kernel and cannot filter it.

That single question sorts the entire defensive landscape:

| Control | Enforced by | Binds? |
|---|---|---|
| `DISALLOW_FILE_MODS` | PHP (capability check) | no |
| `chmod 0444`, PHP user owns files | PHP (owner can re-chmod) | no |
| Security plugin / integrity scanner | PHP (loaded by WP) | no |
| **PHP user is not the file owner** | kernel (file ownership) | **yes** |
| **No PHP execution in `uploads/`** | web server / kernel | **yes** |
| **Per-site OS user + PHP-FPM pool** | kernel (process isolation) | **yes** |
| **`chattr +i` on code files** | kernel (immutable flag) | **yes** |

The three controls the README recommends are exactly the three below the line.
They are recommended not because they are thorough but because they are the only
ones the attacker's code cannot reach.

---

## Mapping the entry routes to the one control that closes them

| Entry route | Closed by WP hardening | Closed by ownership split |
|---|---|---|
| File-upload / file-write bug in a plugin or theme | no | **yes** (write lands only in `uploads/`, which cannot execute) |
| Supply-chain backdoored plugin | no | **yes** (its writes to code dirs are denied) |
| RCE / object injection | no | **yes** |
| Stolen SFTP / FTP / SSH credentials | no | partly (depends whose account) |
| Lateral spread from a sibling site | no | **yes** (different UID cannot enter your docroot) |
| Stolen admin password via wp-admin uploader | `DISALLOW_FILE_MODS` | **yes** |

Notice the ownership split closes routes that are otherwise completely unrelated -
a plugin bug and a compromised sibling site share no code path, yet the same
kernel-level boundary stops both. That is the signature of fixing a root cause
rather than a symptom: one control, many symptoms closed.

---

## Exposure is two questions, not one

The trust-boundary test above answers the question that matters most, but it is
worth naming the question it does *not* answer, because conflating the two is the
most common strategic error.

**Question 1 - arrival. Can an attacker get code running in the document root at
all?** No single control answers this. It is the sum of patching, plugin
provenance, credential hygiene, and not sharing an OS user with a site you do not
control. It is also the only stage that leaves external evidence, so it is where
*detection* is possible but *prevention* is never complete. On a long enough
timeline, assume it is eventually answered "yes".

**Question 2 - persistence. If they do, does it become permanent?** This is the
decisive test: *can the PHP worker's UID write to the code directories?* If yes,
any execution becomes a self-healing implant. If no, execution is confined to the
directories that must stay writable and cannot reach into the code.

The asymmetry between them is the entire strategy:

- Question 1 you can only ever **reduce**. There will always be one more plugin CVE,
  one more phished credential, one more sibling site.
- Question 2 you can actually **close**, with kernel-enforced controls the
  attacker's PHP cannot reach.

And closing question 2 changes what a "yes" to question 1 *costs*. With the
ownership boundary in place, a break-in is a contained incident - some code ran,
wrote into `uploads/`, and could not execute or persist. Without it, the identical
break-in is a permanent, self-healing compromise of every site under the account.
Same entry, two completely different outcomes, decided entirely by question 2.

You cannot stop every break-in. You can make a break-in unable to become a
resident. That is the achievable goal, and it lives below PHP.

## Consequences for incident response

Everything in the README's eradication order follows from the above:

- **Contain before you delete.** Stop the PHP workers first. That is what clears
  the cached `.user.ini` (`user_ini.cache_ttl`, default 300 s), flushes OPcache,
  and destroys the shared-memory copy - the three stores that survive every file
  you remove. Deleting files while workers run is deleting leaves while the root
  regrows them.
- **Sever `auto_prepend_file` before touching payloads.** Until Stage 2 is broken,
  the loop runs before WordPress and undoes your work within one request.
- **Treat the database and process memory as infected surfaces**, not just the
  disk. A file-only cleanup leaves two live rebuild sources.
- **Clean the administrator browser.** The service worker is a rebuild path that
  lives entirely off your server; a perfect server cleanup does not touch it.
- **Rotate salts, not just passwords.** Forged cookies are valid 14 days and are
  keyed to the salts, so changing passwords alone does not invalidate them.
- **Sweep every site under the same OS user.** Same reasoning as lateral spread -
  the boundary that was missing is per-user, so the blast radius is per-user.

---

## Sources

- MD Pabel, *SC 4.0.3 Self-Healing WordPress Malware That Rebuilds Itself* (2026-08-22)
- Monarx, *The WordPress Infection That Rebuilds Itself Faster Than You Can Delete It*
- Seven Labs, *WordPress malware removal case study: edu.gov.sc*
- Jump.BG, *WordPress SC-403 self-healing malware*
- PHP manual: per-directory INI files, `auto_prepend_file` (`INI_PERDIR`)
- WordPress core: `wp-includes/load.php`, `wp-includes/capabilities.php`
