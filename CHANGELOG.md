# Changelog

## 2.0.0 - September 2026

Rebuilt around the `SCV:4.3.24` build, which appeared roughly two weeks after
SC 4.0.3 and broke every hash-based indicator in the 1.0.0 release. Both builds
are covered; the repo is now "SC 4.x" rather than "SC 4.0.3".

### The reason for the rewrite

4.3.24 pads every file it writes to a random size between 5.5 and 7.0 MB with
`/*<random hex>*/` comments. No two infections share a file hash any more, so a
hash list is no longer a detection strategy. What it cannot randomise is its
naming: three families of identifier, all plain `md5()` over the site's own
install path, and therefore all computable by the defender in advance.

```
FILES      substr(md5(ABSPATH . role), 0, n)
ENDPOINTS  91000000 + hexdec(substr(md5(ABSPATH . 'ep' . role), 0, 7)) % 8999999
OPTIONS    substr(md5(ABSPATH . '93819' . slot), 0, 12)
```

Everything below follows from that.

### sc403-scan.sh - 1.0.0 to 2.0.0

- Derives and checks the full artefact set for each site: nine file paths, the
  two `?p=` endpoints, the fourteen private option keys, the payload row, the
  writeKey and the injected script attribute. The previous version knew six
  filename roles, two of which (`sw`, `th_m`) do not exist in the recovered code.
- New `--names-only`: print the derived names for a path and scan nothing.
- New `--logs <dir>`: grep access logs for the derived `?p=` endpoints. Each hit
  is an administrator's browser that fetched the service worker, which is how
  you learn *which* browsers were infected, and when, from archived logs.
- New padding check: any PHP file over 4 MB under `wp-content`. Works even when
  every name has changed.
- New checks for `SC_WC` in `wp-config.php`, `db.php` backdated to before the
  WordPress install, the guard daemon's `.gl_/.gm_/.gp_/.gs_/.gv_` state files,
  and `.sc_*` staging directories.
- Database checks extended: the fourteen derived keys, the payload row,
  generated-looking cron hooks, and a `session_tokens` count. **Orphaned 12-hex
  option rows** are now reported - rows in the derived shape that the current
  `ABSPATH` does not predict, which means the site was moved or copied while
  infected and a stale worker URL is still registered in somebody's browser.
- Version-stamp reporting now prints the actual build (`SCV:4.3.24`,
  `SC_ADV_BEGIN:4.3.24:d17ba8df`) rather than just the marker name.
- Known-hash check retained but labelled 4.0.3-era only, and it now says so when
  it finds nothing.
- Summary text rewritten: restart the PHP-FPM pool *before* deleting files, and
  capture the database rows *before* cleaning them.

### sc403-guard.php - 1.0.0 to 2.0.0

- Computes all three derivations for the site it is installed on and watches for
  exactly those names. An equality test, not a heuristic.
- Detects orphaned derived option rows, decodes them with the implant's own
  codec, and reports any service-worker URL found inside.
- Watches for requests to the derived `?p=` endpoints (rate-limited to one
  recorded finding per minute, and findings are deduplicated before writing).
- New checks: the padding band, the timestomp watermark, `SC_WC` in
  `wp-config.php`, and `sc_c2_cache` / `sc_last_c2`, which hold the live C2 URLs
  in cleartext and are printed so they are captured before any cleanup.
- Plaintext option list extended from six names to sixteen.
- The browser audit now names the exact expected worker scriptURL
  (`home_url('?p=' . derived id)`) and says plainly when it finds it.
- Baseline hashing now covers `wp-config.php`, and hashes the first and last
  64 KB rather than whole files - md5 over a 7 MB padded file every fifteen
  minutes is real cost for no extra signal.
- `wp eval 'print_r( SC403_Guard::report() );'` prints the derived names and
  current findings for a ticket or a handover.

### New files

- **`sc403-derive.sh`** - the calculator on its own. Text, TSV, IOC-regex and
  SQL output modes, plus `--decode` for a single encoded option value. Reads
  nothing but the paths you give it; touches no database.
- **`00-sc403-sw-neutralizer.php`** - the browser half. Serves a byte-stable
  self-destructing service worker at the derived endpoint, answers the installer
  endpoint with `410 Gone` and a body that fails the implant's own liveness
  probe, sweeps registrations on every view, sends `Clear-Site-Data` on the
  login screen, emits the `data-sc=1` marker that disarms the worker's reinstall
  branch, and tombstones stale worker URLs recovered from orphaned rows. It
  deletes nothing and force-navigates nobody.

### Documentation

- `README.md`: new sections on what changed between the builds, on names rather
  than hashes, and on the browser half. Full scanner output for a clean and an
  infected site. Check table expanded from 12 to 15. Eradication order gains a
  step 0 - capture `sc_c2_cache`, `sc_last_c2` and the derived `sw_url`,
  `sw_cached` and `issued` rows before anything is deleted, because none of
  those start with `sc_` and a `LIKE 'sc\_%'` cleanup destroys them.
- `TECHNICAL.md`: what 4.3.24 added to the persistence mesh - the browser node,
  the detached CLI guard daemon, the deletion backoff, and the "already
  infected" test the implant runs before spreading to a site.
- `iocs.csv`: roughly fifty new rows - 4.3.24 markers, all three derivation
  formulas, every private option slot, the four C2 hosts and the RPC provider
  recovered from a live infection, and the behavioural indicators. One
  pre-existing malformed row (an unquoted regex containing a comma) fixed; the
  file now parses as valid CSV.

### Eradication tooling, now included

1.0.0 shipped detection only, on the reasoning that a half-finished cleanup is
what makes this malware look immortal. That reasoning has not changed - but
refusing to ship the tooling did not stop anyone cleaning badly, it just meant
they did it by hand. So the kill chain is now here, dry-run by default:

- **`sc403-killchain.sh`** - K0 to K8 in order, in one script. Dry run until
  `--execute`. `--pool-cmd` is the argument that decides whether it works.
- **`sc403-superclean.sh`** - account-wide wrapper: per-site derived IoCs
  injected into the engine, service-worker evidence captured before the database
  cleanup destroys it, the neutralizer installed on every site afterwards, the
  whole thing bundled with a sha256 manifest.
- **`wp-sc-account-cleaner-v45.sh`** - the engine. Quarantines every WordPress
  tree under one cPanel account before cleaning any of them, and releases only
  when all of them verify clean. Root only.
- **`sc403-vaccinate.sh`** - plants the implant's own "already infected"
  watermark on sites it has not reached, which removes them from the spread.
  Dry run until `--execute`.
- **`sc403-dbdump.sh`** - read-only: pulls and decodes every implant row in
  `wp_options`. Touches nothing else.

The detection half is unchanged and remains entirely read-only.

### On the sample data

Every derived name, option row and decoded value shown in the documentation
comes from a real infection with the site's identifiers substituted - install
path, hostname, generated account and its password - and the encoded values
re-encoded so they still decode correctly under the malware's own codec. The
algorithm, the structure and the lengths are untouched, so the examples verify
against the shipped tools; they just do not identify anybody.

## 1.0.0 - August 2026

Initial release: read-only scanner, guard MU-plugin, technical notes and IoC
catalogue for SC 4.0.3.
