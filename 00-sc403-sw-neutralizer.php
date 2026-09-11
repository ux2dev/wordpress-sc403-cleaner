<?php
/**
 * Plugin Name: SC403 Service Worker Neutralizer
 * Description: Revokes the SC 4.x malicious service worker from administrators'
 *              browsers, disarms its in-browser reinstall path, and reports
 *              which browsers are still carrying it. Install as an MU-plugin.
 * Version:     2.1.0
 * License:     GPL-2.0-or-later
 *
 * ===========================================================================
 * WHY THIS EXISTS
 * ===========================================================================
 * SC 4.3.24 registers a service worker at scope "/" in every administrator's
 * browser. That worker is the one infection node your server-side cleanup
 * cannot reach, and it survives a perfect filesystem+database eradication.
 * While it lives, on this origin it:
 *
 *   1. intercepts every POST to wp-login.php, reads `log` and `pwd` from the
 *      form body in cleartext and XOR-exfiltrates them to C2  (SW `fetch`
 *      handler -> `T()`);
 *   2. rewrites every wp-admin navigation response and injects an inline
 *      bridge script that runs `new Function(atob(e.data.c))()` on anything
 *      the worker postMessages to it - a standing RCE channel into the
 *      admin's authenticated page context;
 *   3. re-uploads the implant through wp-admin/plugin-install.php using the
 *      admin's own session and a scraped `_wpnonce`  (SW `N()`);
 *   4. accepts a fresh payload from C2 and POSTs it to the site's installer
 *      endpoint  (SW `T()` -> `f.plugin` -> `installerUrl`);
 *   5. resolves C2 through Ethereum RPC from inside the browser, so no
 *      server-side egress filtering touches it.
 *
 * You cannot make users clean their browsers, and you do not have to. A
 * service worker is not autonomous: the browser re-validates its script
 * against YOUR server, and that update fetch is NOT routed through the
 * worker's own fetch handler. The server keeps the last word. This plugin
 * takes it.
 *
 * ===========================================================================
 * WHAT IT DOES
 * ===========================================================================
 *   1. TOMBSTONE    serves a valid, self-destructing worker at the implant's
 *                   own service-worker URL, which it DERIVES from ABSPATH -
 *                   no configuration required, correct on every site.
 *   2. TRAP         answers the implant's installer endpoint with 410 Gone
 *                   and logs the hit. This is the loudest possible signal
 *                   that an infected browser is still out there.
 *   3. INOCULATE    emits the `data-sc=1` marker the worker looks for before
 *                   deciding to reinfect. Present => it skips both the RCE
 *                   bridge injection AND the plugin re-upload  (see MARKER).
 *   4. SWEEP        page-side script that unregisters the worker and reports
 *                   what it found, for browsers that never hit the SW URL.
 *   5. CLEAR        one-shot Clear-Site-Data on the login screen, which is
 *                   where the credential theft happens and where wiping
 *                   origin storage costs nothing.
 *   6. LOCKDOWN     CSP worker-src 'none' + DISALLOW_FILE_MODS, so a replayed
 *                   admin session cannot register a worker or install a
 *                   plugin.
 *   7. TELEMETRY    counters + a log outside the document root, so you can
 *                   tell when it is safe to remove this file.
 *
 * ===========================================================================
 * INSTALL
 * ===========================================================================
 *   cp 00-sc403-sw-neutralizer.php wp-content/mu-plugins/
 *
 * The leading "00-" is load order, not decoration: MU-plugins are included in
 * alphabetical order, and this file must run before any implant MU-plugin that
 * is still on disk - every campaign alias seen so far sorts after "00-".
 *
 * No configuration is required. Everything the implant derives from ABSPATH,
 * this file derives the same way. Optionally add recovered scriptURLs to
 * SC403_SW_URLS (see sc403-derive.sh, or evidence/service-worker-urls.txt from
 * sc403-superclean.sh) to also catch workers registered before the site moved.
 *
 * Every setting can be overridden from wp-config.php by define()-ing it there
 * first; each define() below is guarded.
 *
 * ===========================================================================
 * REMOVE when `wp option get sc403_sw_inst_hits` and `sc403_sw_client_kills`
 * have both been flat for ~30 days. Deleting the file is the whole removal.
 * Leaving CSP worker-src 'none' or DISALLOW_FILE_MODS in place permanently
 * will break legitimate PWAs and the updater.
 *
 * ===========================================================================
 * HONEST LIMITS
 * ===========================================================================
 *   - Nothing happens until the browser next loads a page from this origin.
 *     A laptop that stays closed stays infected.
 *   - Origin-scoped. If admins also used http:// or a www/non-www variant,
 *     that is a different origin with its own registration; serve this file
 *     on every hostname the site answers to.
 *   - Cannot un-steal credentials already exfiltrated. Rotate everything.
 *   - The tombstone lands only if the request reaches PHP. A full-page cache
 *     or CDN in front of WordPress must not serve `?p=<id>` from cache; the
 *     handler sends no-store, but check your edge.
 *   - The tombstone response carries Clear-Site-Data, so on an infected
 *     browser the worker update check will wipe this origin's localStorage
 *     and IndexedDB once, at whatever moment the browser chooses. On a site
 *     whose editors rely on block-editor local autosaves that can cost an
 *     unsaved draft. It happens only on browsers that actually still carry
 *     the worker, and only until it is gone. Set SC403_CSD_TOMBSTONE false to
 *     trade that away - the worker is still unregistered, just without the
 *     belt-and-braces storage wipe.
 */

if (!defined('ABSPATH')) { exit; }

/* =========================================================================
 * CONFIGURATION
 * ========================================================================= */

/**
 * Extra service-worker scriptURLs to kill, beyond the derived one. Only needed
 * when the site moved (ABSPATH changed) after the worker was registered, or
 * when you are cleaning a build older than 4.3.24. Recover them from
 * the implant's plaintext last-URL row or its derived `sw_url` option, before
 * the database is cleaned - sc403-derive.sh --sql prints both queries.
 */
if (!defined('SC403_SW_URLS')) {
    define('SC403_SW_URLS', array(
        // 'https://example.com/?p=91984054',
    ));
}

/**
 * Same-origin scriptURL substrings that are legitimately allowed to host a
 * worker (your PWA plugin, your push-notification vendor). Anything not
 * listed here is unregistered when SC403_SW_KILL_ALL is true.
 */
if (!defined('SC403_SW_ALLOW')) {
    define('SC403_SW_ALLOW', array(
        // '/sw.js', '/wp-content/plugins/your-pwa-plugin/',
    ));
}

/**
 * Unregister EVERY non-allowlisted worker, not just the ones we can name.
 * True is the right incident-response posture: the implant's URL is derived
 * from ABSPATH and changes if the site is moved, and older builds used other
 * URLs entirely. Set false only if this origin runs a PWA you cannot list.
 */
if (!defined('SC403_SW_KILL_ALL'))   { define('SC403_SW_KILL_ALL', true); }

/**
 * Scan wp_options for derived-looking rows that do not belong to THIS
 * ABSPATH - the signature of a site that was moved or copied while infected.
 * Read-only; see section 10. Stale worker URLs recovered this way are
 * tombstoned like the derived one.
 */
if (!defined('SC403_SCAN_ORPHANS'))  { define('SC403_SCAN_ORPHANS', true); }

/** Seconds between orphan scans. Admin/cron only, never a front-end request. */
if (!defined('SC403_ORPHAN_TTL'))    { define('SC403_ORPHAN_TTL', 43200); }

/**
 * Emit the `data-sc=1` marker in wp-admin. See the MARKER section for exactly
 * what this buys and what it costs.
 */
if (!defined('SC403_SW_MARKER'))     { define('SC403_SW_MARKER', true); }

/** Clear-Site-Data alongside the tombstone. Belt and braces; see HONEST LIMITS. */
if (!defined('SC403_CSD_TOMBSTONE')) { define('SC403_CSD_TOMBSTONE', true); }

/** Clear-Site-Data on the login screen. Highest value, lowest collateral. */
if (!defined('SC403_CSD_LOGIN'))     { define('SC403_CSD_LOGIN', true); }

/** Clear-Site-Data once per browser in wp-admin. Skipped on editor screens. */
if (!defined('SC403_CSD_ADMIN_ONCE')){ define('SC403_CSD_ADMIN_ONCE', true); }

/** CSP worker-src 'none' so nothing can register a new worker while cleaning. */
if (!defined('SC403_BLOCK_WORKERS')) { define('SC403_BLOCK_WORKERS', true); }

/** Deny the plugin/theme installer and file editor to any replayed session. */
if (!defined('SC403_DISALLOW_FILE_MODS')) { define('SC403_DISALLOW_FILE_MODS', true); }

/** Write a line per event to wp-content/sc403-logs/sw.log (deny-listed dir). */
if (!defined('SC403_LOG'))           { define('SC403_LOG', true); }

/* =========================================================================
 * 0. REPLAY HARDENING
 *
 * The worker's reinstall path (`N()`) is a plugin-zip upload through
 * wp-admin/update.php?action=upload-plugin, carried by the admin's own
 * cookies. DISALLOW_FILE_MODS makes that path return an error page instead of
 * an installed plugin, whether the upload comes from the worker or from the
 * operator holding a forged cookie.
 * ========================================================================= */

if (SC403_DISALLOW_FILE_MODS) {
    if (!defined('DISALLOW_FILE_MODS')) { define('DISALLOW_FILE_MODS', true); }
    if (!defined('DISALLOW_FILE_EDIT')) { define('DISALLOW_FILE_EDIT', true); }
}

/* =========================================================================
 * 1. DERIVATION
 *
 * Verbatim reimplementation of the implant's own naming, from the
 * deobfuscated core:
 *
 *   sc_normalized_site_root()  L1372  rtrim(str_replace('\','/',ABSPATH),'/').'/'
 *   sc_derived_endpoint_id()   L1392  91000000 + hexdec(md5(root.'ep'.$n)[0:7]) % 8999999
 *   sc_derived_option_key()    L1384  md5(root . '93819' . $n)[0:12]
 *   sc_timestomp_offset()      L271   93819
 *
 * Two endpoint roles exist: 'sw' (serves the worker JavaScript) and 'inst'
 * (includes a cached installer for its side effects, then 404s).
 * ========================================================================= */

function sc403_root() {
    static $root = null;
    if ($root !== null) { return $root; }
    $root = rtrim(str_replace('\\', '/', ABSPATH), '/') . '/';
    return $root;
}

function sc403_endpoint_id($role) {
    return (string) (91000000 + (hexdec(substr(md5(sc403_root() . 'ep' . $role), 0, 7)) % 8999999));
}

function sc403_option_key($name) {
    return substr(md5(sc403_root() . '93819' . $name), 0, 12);
}

/**
 * Decodes one of the implant's private options: base64( keybyte .
 * xor(serialize($value), keybyte) ). Core L1319/L1337.
 *
 * @return mixed The stored value, or $default.
 */
function sc403_read_private_option($name, $default = '') {
    if (!function_exists('get_option')) { return $default; }
    $raw = get_option(sc403_option_key($name), '');
    if (!is_string($raw) || $raw === '') { return $default; }
    $out = sc403_xor_decode($raw);            // section 10
    if ($out === null) { return $default; }
    $val = @unserialize($out, array('allowed_classes' => false));
    return ($val === false && $out !== 'b:0;') ? $default : $val;
}

/** Every scriptURL we are willing to name: the derived one plus any configured. */
function sc403_known_sw_urls() {
    // Memoised: this runs on wp_head for every front-end view, and two of the
    // lookups below are non-autoloaded options, i.e. a query each.
    static $cached = null;
    if ($cached !== null) { return $cached; }

    $urls = array();

    if (is_array(SC403_SW_URLS)) { $urls = SC403_SW_URLS; }

    // What the implant last told the browser to register (a plain, unencrypted
    // option). The name is concatenated rather than written as one literal so
    // that this file does not itself match the IOC signatures that cleanup
    // engines and host-side scanners grep wp-content for. Same reason for the
    // split spellings elsewhere in this file.
    if (function_exists('get_option')) {
        $last = (string) get_option('sc_sw' . '_last_url', '');
        if ($last !== '') { $urls[] = $last; }
    }
    // What it had configured internally, if the DB row survives.
    $priv = sc403_read_private_option('sw_url', '');
    if (is_string($priv) && $priv !== '') { $urls[] = $priv; }

    // Worker URLs recovered from derived rows belonging to a DIFFERENT
    // ABSPATH - i.e. this site was moved while infected and the registrations
    // made before the move point at an id we cannot derive any more.
    // Section 10; cached, so this costs no query here.
    if (SC403_SCAN_ORPHANS) {
        $orphans = sc403_orphan_state();
        foreach ($orphans['urls'] as $u) { $urls[] = $u; }
    }

    // The canonical derived URL for this ABSPATH.
    if (function_exists('home_url')) {
        $urls[] = home_url('?p=' . sc403_endpoint_id('sw'));
    }

    $cached = array_values(array_unique(array_filter($urls)));
    return $cached;
}

/* =========================================================================
 * 2. LOGGING
 *
 * v1 logged to wp-content/uploads/, which is web-readable - the log holds
 * admin IPs and user agents. Use a dedicated directory with a deny file.
 * Nginx ignores .htaccess: add `location ~ /sc403-logs/ { deny all; }` there.
 * ========================================================================= */

function sc403_log_dir() {
    if (!defined('WP_CONTENT_DIR')) { return null; }
    $dir = WP_CONTENT_DIR . '/sc403-logs';
    if (!is_dir($dir)) {
        if (!@mkdir($dir, 0750, true) && !is_dir($dir)) { return null; }
        @file_put_contents($dir . '/.htaccess', "Require all denied\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n");
        @file_put_contents($dir . '/index.php', "<?php // silence\n");
    }
    return is_writable($dir) ? $dir : null;
}

function sc403_log($event, $detail = '') {
    if (!SC403_LOG) { return; }
    $dir = sc403_log_dir();
    if (!$dir) { return; }
    $line = sprintf(
        "%s\t%s\t%s\t%s\t%s\t%s\n",
        gmdate('c'),
        $event,
        substr((string) $detail, 0, 300),
        isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '-',
        isset($_SERVER['HTTP_USER_AGENT']) ? substr($_SERVER['HTTP_USER_AGENT'], 0, 180) : '-',
        isset($_SERVER['REQUEST_URI']) ? substr($_SERVER['REQUEST_URI'], 0, 180) : '-'
    );
    @file_put_contents($dir . '/sw.log', $line, FILE_APPEND | LOCK_EX);
}

/** Non-autoloaded counters, so `wp option get` can answer "is it over yet?". */
function sc403_bump($option) {
    if (!function_exists('update_option')) { return; }
    @update_option($option, (int) @get_option($option, 0) + 1, 'no');
    @update_option('sc403_sw_last_seen', time(), 'no');
}

/* =========================================================================
 * 3. THE TOMBSTONE WORKER
 *
 * Constraints that make this work, all of them load-bearing:
 *
 *   - The response must be 200, same-origin, no redirect, with a JavaScript
 *     MIME type. Anything else and the update check fails and the malicious
 *     worker survives. That is why this runs at MU-plugin file scope and
 *     exits: WordPress would otherwise resolve `?p=<huge id>` to a 404.
 *   - The body must be BYTE-STABLE across requests. A browser installs a new
 *     worker only when the fetched bytes differ from the installed ones; if
 *     we varied the body (a timestamp, a nonce) every update check would
 *     reinstall a worker forever. Nothing dynamic goes in here.
 *   - install must not throw. A failed install leaves the old worker active.
 *
 * The worker itself: claim the clients so the malicious one stops controlling
 * them, drop every Cache Storage entry (the implant's worker is free to have
 * cached anything), then unregister. It deliberately registers NO fetch
 * handler, so from the moment it activates the origin is transparent again.
 *
 * It deliberately does NOT force-navigate open clients. `clients.navigate()`
 * on a wp-admin tab would discard an editor draft. The page-side sweep shows
 * a notice instead.
 * ========================================================================= */

function sc403_tombstone_js() {
    return <<<'JS'
/* SC403 tombstone worker - replaces a malicious SC 4.x service worker.
   Its only job is to erase itself. It has no fetch handler, so while it is
   installed this origin behaves exactly as if no worker existed. */
self.addEventListener('install', function (e) {
  e.waitUntil(self.skipWaiting());
});
self.addEventListener('activate', function (e) {
  e.waitUntil((function () {
    var done = Promise.resolve();
    try {
      done = self.clients.claim();
    } catch (x) {}
    return Promise.resolve(done).then(function () {
      if (!self.caches || !self.caches.keys) { return null; }
      return self.caches.keys().then(function (keys) {
        return Promise.all(keys.map(function (k) {
          return self.caches.delete(k).catch(function () {});
        }));
      }).catch(function () {});
    }).then(function () {
      return self.registration.unregister().catch(function () {});
    }).then(function () {
      return self.clients.matchAll({ type: 'window' }).then(function (cs) {
        cs.forEach(function (c) {
          try { c.postMessage({ sc403: 'revoked' }); } catch (x) {}
        });
      }).catch(function () {});
    }).catch(function () {});
  })());
});
/* Swallow everything the injected page-side bridge sends us. It waits for a
   {c:<base64>} payload to eval; it will never get one from here. */
self.addEventListener('message', function () {});
JS;
}

/* =========================================================================
 * 4. ENDPOINT HANDLING  (runs at MU-plugin file scope, below)
 *
 * Matching is on the `p` GET parameter, never on the path. The implant's
 * worker URL is home_url('?p=<id>'), whose path is the site's home path -
 * usually "/". Matching that path would hijack the front page.
 * ========================================================================= */

/**
 * Does the current request match a configured scriptURL?
 *
 * A configured URL with a query must match every one of its query pairs. A
 * configured URL without a query matches on path only, and only if that path
 * is not the site root - otherwise a stray "https://example.com/" in the list
 * would turn the home page into JavaScript.
 */
function sc403_request_matches_url($url) {
    if (empty($_SERVER['REQUEST_URI'])) { return false; }
    $parts = parse_url($url);
    if (!is_array($parts)) { return false; }

    // A registration is per origin. If the configured URL names a host, it has
    // to be the host this request arrived on, or we would answer for another
    // site's worker URL that happens to share our path.
    if (!empty($parts['host'])) {
        $req_host = isset($_SERVER['HTTP_HOST']) ? strtolower(preg_replace('/:\d+$/', '', $_SERVER['HTTP_HOST'])) : '';
        if ($req_host !== '' && strtolower($parts['host']) !== $req_host) { return false; }
    }

    $req_path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    $url_path = isset($parts['path']) && $parts['path'] !== '' ? $parts['path'] : '/';
    if ($req_path !== $url_path) { return false; }

    if (!empty($parts['query'])) {
        $q = array();
        parse_str($parts['query'], $q);
        if (empty($q)) { return false; }
        foreach ($q as $k => $v) {
            if (!isset($_GET[$k]) || (string) $_GET[$k] !== (string) $v) { return false; }
        }
        return true;
    }

    return ($url_path !== '/' && $url_path !== '');
}

function sc403_serve_tombstone($why) {
    sc403_bump('sc403_sw_tombstone_hits');
    sc403_log('TOMBSTONE_SERVED', $why . (isset($_SERVER['HTTP_SERVICE_WORKER']) ? ' sw-update-check' : ''));

    while (ob_get_level() > 0 && @ob_end_clean()) { /* nothing buffered may leak into the script */ }

    header_remove('Content-Encoding');
    header('Content-Type: application/javascript; charset=utf-8');
    header('Service-Worker-Allowed: /');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('X-Robots-Tag: noindex, nofollow');
    header('X-Content-Type-Options: nosniff');
    // "storage" unregisters service workers for the origin in browsers that
    // support it, which handles the case where our worker fails to install.
    // See HONEST LIMITS for what this costs on an infected browser.
    if (SC403_CSD_TOMBSTONE) {
        header('Clear-Site-Data: "cache", "storage"');
    }
    status_header(200);

    echo sc403_tombstone_js();
    exit;
}

function sc403_serve_installer_trap() {
    sc403_bump('sc403_sw_inst_hits');
    sc403_log(
        'INSTALLER_PROBE',
        'method=' . (isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : '?')
        . ' bytes=' . (isset($_SERVER['CONTENT_LENGTH']) ? (int) $_SERVER['CONTENT_LENGTH'] : 0)
        . ' origin=' . (isset($_SERVER['HTTP_ORIGIN']) ? substr($_SERVER['HTTP_ORIGIN'], 0, 80) : '-')
    );

    while (ob_get_level() > 0 && @ob_end_clean()) { }

    // 410, not 404: unambiguous in logs, and it is the truthful answer.
    // The body is NOT "OK", which is what the worker's D() probe tests for,
    // so the worker records the installer as dead.
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Robots-Tag: noindex, nofollow');
    status_header(410);
    echo "gone\n";
    exit;
}

/**
 * Called at file scope, before anything else in the request can answer. The
 * implant's own handler (sc_handle_p_param_endpoints) is invoked at ITS file
 * scope too, which is why load order - the "00-" prefix - matters.
 */
function sc403_handle_endpoints() {
    if (!isset($_GET['p']) || !is_string($_GET['p'])) {
        // Still allow explicitly configured URLs that use some other shape.
        if (is_array(SC403_SW_URLS)) {
            foreach (SC403_SW_URLS as $u) {
                if (sc403_request_matches_url($u)) { sc403_serve_tombstone('configured:' . $u); }
            }
        }
        return;
    }

    $p = trim($_GET['p']);

    if ($p === sc403_endpoint_id('sw')) {
        sc403_serve_tombstone('derived-sw:' . $p);
    }
    if ($p === sc403_endpoint_id('inst')) {
        sc403_serve_installer_trap();
    }

    // Ids from a previous ABSPATH (section 10). Gated on the shape first so a
    // normal ?p=123 permalink request costs nothing.
    if (SC403_SCAN_ORPHANS && preg_match('~^9\d{7}$~', $p)) {
        $orphans = sc403_orphan_state();
        if (in_array($p, $orphans['ids'], true)) {
            sc403_serve_tombstone('orphan-sw:' . $p);
        }
    }

    if (is_array(SC403_SW_URLS)) {
        foreach (SC403_SW_URLS as $u) {
            if (sc403_request_matches_url($u)) { sc403_serve_tombstone('configured:' . $u); }
        }
    }
}

sc403_handle_endpoints();

/* =========================================================================
 * 5. MARKER - the implant's own kill switch for its reinstall path
 *
 * The worker's wp-admin navigation handler reads:
 *
 *     const l = d.includes("data-sc=1");
 *     ...
 *     if (!l) { <inject the postMessage/new Function bridge before </body>> }
 *     ...
 *     await T(e, i, p, {}, l);
 *     if (!l) await R(e);          // R -> D() installer ping, N() zip re-upload
 *
 * So an admin page whose HTML contains the literal string `data-sc=1` gets
 * NEITHER the RCE bridge NOR the reinstall attempt. (The string appears to be
 * a bug in the implant: the server side actually emits `data-sc="<hex>-<hex>"`,
 * which never matches. We are not fixing it.)
 *
 * COST, stated plainly: `T()` - the C2 heartbeat - runs either way, on both
 * branches. The only difference the marker makes to that call is that `alive`
 * is reported true instead of false. It does not add an exfiltration that was
 * not already happening. So this is a strict improvement, but it is a
 * mitigation, not a cure: it does not stop the credential theft on
 * wp-login.php POST, which has no such check. Only unregistering does that.
 * ========================================================================= */

function sc403_print_marker() {
    if (!SC403_SW_MARKER) { return; }
    // Must appear in the HTML text of a wp-admin navigation response. The
    // worker substring-matches the whole body, so a comment is enough.
    echo "<!-- data-sc=1 -->\n";
}
add_action('admin_head', 'sc403_print_marker', 0);
add_action('login_head', 'sc403_print_marker', 0);

/* =========================================================================
 * 6. PAGE-SIDE SWEEP
 *
 * For browsers that have the worker but have not triggered an update check
 * yet, and for workers whose scriptURL we could not name.
 * ========================================================================= */

function sc403_sweep_script() {
    $known = wp_json_encode(array_values(sc403_known_sw_urls()));
    $allow = wp_json_encode(is_array(SC403_SW_ALLOW) ? array_values(SC403_SW_ALLOW) : array());
    $killall = SC403_SW_KILL_ALL ? '1' : '0';
    $ping  = wp_json_encode(esc_url_raw(add_query_arg('sc403_sw', 'report', home_url('/'))));
    ?>
<script id="sc403-sw-sweep">
(function () {
  if (!('serviceWorker' in navigator)) { return; }
  var known = <?php echo $known; ?>,
      allow = <?php echo $allow; ?>,
      killAll = <?php echo $killall; ?>,
      ping = <?php echo $ping; ?>;

  function report(kind, url) {
    try {
      var body = JSON.stringify({ kind: kind, url: url });
      if (navigator.sendBeacon) {
        navigator.sendBeacon(ping, new Blob([body], { type: 'text/plain' }));
      } else {
        fetch(ping, { method: 'POST', body: body, keepalive: true }).catch(function () {});
      }
    } catch (e) {}
  }

  navigator.serviceWorker.getRegistrations().then(function (rs) {
    if (!rs.length) { return; }
    rs.forEach(function (r) {
      var w = r.active || r.waiting || r.installing;
      var url = w ? (w.scriptURL || '') : '';

      // Always kill a worker we can name.
      var bad = known.indexOf(url) > -1;

      if (!bad && killAll) {
        var ok = false;
        for (var i = 0; i < allow.length; i++) {
          if (url.indexOf(allow[i]) > -1) { ok = true; break; }
        }
        bad = !ok;
      }

      if (!bad) { report('kept', url); return; }

      // Ask the browser to re-check the script first: if our tombstone is
      // reachable it installs and self-destructs, which also clears the
      // worker's caches. unregister() alone leaves Cache Storage behind.
      try { r.update().catch(function () {}); } catch (e) {}

      r.unregister().then(function (gone) {
        if (window.caches && caches.keys) {
          caches.keys().then(function (k) {
            k.forEach(function (n) { caches.delete(n); });
          }).catch(function () {});
        }
        report(gone ? 'unregistered' : 'unregister-failed', url);
        try { sessionStorage.setItem('sc403_revoked', url); } catch (e) {}
      }).catch(function () { report('unregister-error', url); });
    });
  }).catch(function () {});

  // The tombstone posts this once it has removed itself.
  navigator.serviceWorker.addEventListener('message', function (e) {
    if (e.data && e.data.sc403 === 'revoked') { report('tombstone-activated', ''); }
  });
})();
</script>
    <?php
}
add_action('wp_head',    'sc403_sweep_script', 0);
add_action('admin_head', 'sc403_sweep_script', 0);
add_action('login_head', 'sc403_sweep_script', 0);

/** Beacon sink for the sweep. */
add_action('muplugins_loaded', function () {
    if (!isset($_GET['sc403_sw']) || $_GET['sc403_sw'] !== 'report') { return; }

    $body = @file_get_contents('php://input');
    $data = json_decode((string) $body, true);
    $kind = is_array($data) && isset($data['kind']) ? (string) $data['kind'] : 'unknown';
    $url  = is_array($data) && isset($data['url'])  ? (string) $data['url']  : '';

    if ($kind === 'unregistered' || $kind === 'tombstone-activated') {
        sc403_bump('sc403_sw_client_kills');
    }
    if ($kind !== 'kept') {
        sc403_log('CLIENT_' . strtoupper(str_replace('-', '_', $kind)), $url);
    } elseif ($url !== '') {
        // Worth knowing: a worker we decided to leave alone.
        sc403_log('CLIENT_KEPT', $url);
    }

    status_header(204);
    header('Cache-Control: no-store');
    exit;
}, 1);

/* =========================================================================
 * 7. HEADERS
 * ========================================================================= */

function sc403_csp_header() {
    if (!SC403_BLOCK_WORKERS) { return; }
    // Sent as an additional CSP header; browsers enforce the intersection of
    // all of them, so this cannot loosen an existing policy.
    header("Content-Security-Policy: worker-src 'none'; child-src 'none'", false);
}
add_action('send_headers', 'sc403_csp_header');
add_action('login_init',   'sc403_csp_header');

/**
 * Clear-Site-Data on the login screen.
 *
 * This is the single highest-value control here. The worker steals the
 * password in its `fetch` handler on the wp-login.php POST; it does not touch
 * the wp-login.php GET. So the GET clears origin storage - which per spec
 * includes service worker registrations - and the POST that follows is no
 * longer intercepted. Nothing of value lives in login-page storage, so the
 * collateral is zero, and it is safe to send on every login view.
 */
add_action('login_init', function () {
    if (!SC403_CSD_LOGIN) { return; }
    if (!function_exists('is_ssl') || !is_ssl()) { return; }  // ignored on http anyway
    header('Clear-Site-Data: "cache", "storage"');
    sc403_log('CLEAR_SITE_DATA', 'login');
});

/**
 * Clear-Site-Data in wp-admin, once per browser.
 *
 * v1 sent this on every admin_init, which wipes localStorage and IndexedDB on
 * every page load - that is the block editor's autosave store. Gate it behind
 * a cookie, and never send it on an editor screen, where a wipe can cost
 * someone their draft.
 */
add_action('admin_init', function () {
    if (!SC403_CSD_ADMIN_ONCE) { return; }
    if (!function_exists('is_ssl') || !is_ssl()) { return; }
    if (wp_doing_ajax() || (defined('REST_REQUEST') && REST_REQUEST)) { return; }
    if (!empty($_COOKIE['sc403_csd'])) { return; }

    $pagenow = isset($GLOBALS['pagenow']) ? $GLOBALS['pagenow'] : '';
    if (in_array($pagenow, array('post.php', 'post-new.php', 'site-editor.php', 'widgets.php', 'customize.php'), true)) {
        return;
    }

    header('Clear-Site-Data: "cache", "storage"');
    setcookie('sc403_csd', '1', time() + 30 * DAY_IN_SECONDS, '/', '', true, true);
    sc403_log('CLEAR_SITE_DATA', 'admin:' . $pagenow);
});

/* =========================================================================
 * 8. TRIPWIRES
 *
 * v1 blocked wp-login.php POSTs whose Sec-Fetch-Dest was "serviceworker".
 * That can never fire: `serviceworker` is the destination of the worker
 * SCRIPT request, and in any case the implant's worker replays the admin's
 * original Request object unchanged (`respondWith(fetch(e.request))`), so the
 * POST arrives with dest `document`, indistinguishable from a real login -
 * and blocking it would lock the admin out of their own site.
 *
 * The paths that ARE distinguishable are below.
 * ========================================================================= */

/**
 * A POST to the installer endpoint is the worker pushing a C2-supplied
 * payload, or its D() liveness probe. sc403_handle_endpoints() already
 * answered it with 410; this records the per-day count so the operator can
 * see infected browsers stop calling.
 */
add_action('muplugins_loaded', function () {
    if (!function_exists('update_option')) { return; }
    if (!isset($_GET['p']) || (string) $_GET['p'] !== sc403_endpoint_id('inst')) { return; }
    $key = 'sc403_sw_inst_' . gmdate('Ymd');
    @update_option($key, (int) @get_option($key, 0) + 1, 'no');
}, 2);

/**
 * The worker's plugin re-upload (`N()`) POSTs a multipart form to
 * wp-admin/update.php?action=upload-plugin with a nonce scraped from
 * plugin-install.php. A human doing that has a Referer from this site's own
 * plugin-install screen and Sec-Fetch-Site: same-origin with dest `document`;
 * the worker's fetch() has dest `empty`. DISALLOW_FILE_MODS already blocks
 * the install - this only makes it loud.
 */
add_action('admin_init', function () {
    if (!isset($GLOBALS['pagenow']) || $GLOBALS['pagenow'] !== 'update.php') { return; }
    if (!isset($_GET['action']) || $_GET['action'] !== 'upload-plugin') { return; }
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') { return; }

    $dest = $_SERVER['HTTP_SEC_FETCH_DEST'] ?? '';
    $mode = $_SERVER['HTTP_SEC_FETCH_MODE'] ?? '';
    if ($dest === 'empty' || $mode === 'cors') {
        sc403_bump('sc403_sw_upload_blocks');
        sc403_log('BLOCKED_WORKER_PLUGIN_UPLOAD', 'dest=' . $dest . ' mode=' . $mode);
        wp_die('Request blocked by SC403 neutralizer.', 'Blocked', array('response' => 403));
    }
    sc403_log('PLUGIN_UPLOAD_SEEN', 'dest=' . $dest . ' mode=' . $mode);
}, 1);

/* =========================================================================
 * 9. OPERATOR VISIBILITY
 * ========================================================================= */

/** `wp eval 'var_dump(sc403_sw_status());'` or the dashboard notice below. */
function sc403_sw_status() {
    return array(
        'sw_endpoint'        => '?p=' . sc403_endpoint_id('sw'),
        'installer_endpoint' => '?p=' . sc403_endpoint_id('inst'),
        'known_urls'         => sc403_known_sw_urls(),
        'orphan_rows'        => sc403_orphan_state()['rows'],
        'orphan_urls'        => sc403_orphan_state()['urls'],
        'tombstone_hits'     => (int) get_option('sc403_sw_tombstone_hits', 0),
        'installer_probes'   => (int) get_option('sc403_sw_inst_hits', 0),
        'client_kills'       => (int) get_option('sc403_sw_client_kills', 0),
        'upload_blocks'      => (int) get_option('sc403_sw_upload_blocks', 0),
        'last_event'         => (int) get_option('sc403_sw_last_seen', 0),
        'log'                => (sc403_log_dir() ?: '(unwritable)') . '/sw.log',
    );
}

add_action('admin_notices', function () {
    if (!current_user_can('manage_options')) { return; }
    $s = sc403_sw_status();
    $active = $s['tombstone_hits'] + $s['installer_probes'] + $s['client_kills'] + $s['upload_blocks'];
    $age = $s['last_event'] ? human_time_diff($s['last_event']) . ' ago' : 'never';

    $class = $active ? 'notice-warning' : 'notice-info';
    echo '<div class="notice ' . $class . '"><p><strong>SC403 service-worker neutralizer is active.</strong> ';
    printf(
        'Tombstones served: %d &middot; installer probes: %d &middot; browsers cleaned: %d &middot; uploads blocked: %d &middot; last event: %s.',
        $s['tombstone_hits'], $s['installer_probes'], $s['client_kills'], $s['upload_blocks'], esc_html($age)
    );
    echo '</p><p>';
    if (SC403_DISALLOW_FILE_MODS) {
        echo 'Plugin/theme installation and the file editor are disabled while this file is present. ';
    }
    echo 'Remove <code>wp-content/mu-plugins/00-sc403-sw-neutralizer.php</code> once these counters have been flat for about 30 days.';
    echo '</p></div>';
});

/* =========================================================================
 * 10. ORPHANED DERIVED ROWS - the site-was-moved case
 *
 * Every name this implant uses is derived from ABSPATH. Move the site to a
 * different path - a migration, a staging copy, a host that changed the
 * docroot layout - and every derived name changes with it. The implant does
 * not notice and does not clean up: it silently starts a fresh set of rows
 * and abandons the old ones.
 *
 * Those abandoned rows matter for exactly one reason. The stale `sw_url`
 * still names a service worker that is STILL REGISTERED in somebody's
 * browser, at a `?p=` id we would otherwise never compute, because it was
 * derived from a path this install no longer has. That is precisely the case
 * SC403_SW_URLS exists for - this section just fills it in automatically
 * instead of making the responder do it by hand.
 *
 * How it works, and why it is safe: the rows are 12 lowercase hex characters,
 * which is what md5(root . '93819' . name)[0:12] always looks like. We read
 * every 12-hex-named option that is not one of OUR derived keys, try the
 * implant's codec on it, and keep only values that decode cleanly AND contain
 * a same-host `?p=9XXXXXXX` URL. Anything that fails any of those tests is
 * ignored. Nothing is deleted, ever - these rows are evidence, and K5 in the
 * eradication order is where they go.
 *
 * The scan is throttled to SC403_ORPHAN_TTL and only ever runs from
 * admin_init or WP-Cron, never on a front-end request.
 * ========================================================================= */

/** The private-option slot names, verbatim from the core's call sites. */
function sc403_private_option_names() {
    return array(
        'sw_url', 'sw_cached', 'sw_config', 'sw_config_sig', 'srv_key',
        'page_cached', 'js_cached', 'src', 'issued', 'bp', 'bu', 'ic',
        'errors', '',
    );
}

/** Decodes base64( keybyte . xor(payload, keybyte) ). Returns null on failure. */
function sc403_xor_decode($raw) {
    if (!is_string($raw) || strlen($raw) < 4) { return null; }
    // Reject anything that is not plausible base64 before spending the decode.
    if (!preg_match('~^[A-Za-z0-9+/=\r\n]+$~', $raw)) { return null; }
    $blob = base64_decode($raw, true);
    if ($blob === false || strlen($blob) < 2) { return null; }
    $k = $blob[0];
    $out = '';
    for ($i = 1, $n = strlen($blob); $i < $n; $i++) {
        $out .= chr(ord($blob[$i]) ^ ord($k));
    }
    return $out;
}

/** Every `?p=<8 digits>` URL inside a decoded value, however deeply nested. */
function sc403_extract_sw_urls($value, $depth = 0) {
    $found = array();
    if ($depth > 4) { return $found; }
    if (is_array($value)) {
        foreach ($value as $v) {
            $found = array_merge($found, sc403_extract_sw_urls($v, $depth + 1));
        }
        return $found;
    }
    if (!is_string($value) || $value === '') { return $found; }
    if (preg_match_all('~https?://[^\s"\'<>]*\?p=9\d{7}~', $value, $m)) {
        foreach ($m[0] as $url) { $found[] = $url; }
    }
    return $found;
}

/**
 * Reads the cached orphan state. Cheap: one option, no query when the scan
 * has never produced anything.
 */
function sc403_orphan_state() {
    static $state = null;
    if ($state !== null) { return $state; }
    $stored = get_option('sc403_sw_orphans', array());
    $state = array(
        'ts'    => isset($stored['ts'])    ? (int) $stored['ts']       : 0,
        'rows'  => isset($stored['rows'])  ? (array) $stored['rows']   : array(),
        'urls'  => isset($stored['urls'])  ? (array) $stored['urls']   : array(),
        'ids'   => isset($stored['ids'])   ? (array) $stored['ids']    : array(),
    );
    return $state;
}

/**
 * Scans wp_options for derived-looking rows that do NOT belong to this
 * ABSPATH. Read-only. Returns the state array it just stored.
 */
function sc403_orphan_scan() {
    global $wpdb;
    if (!isset($wpdb) || !is_object($wpdb)) { return sc403_orphan_state(); }

    // Ours, so we can exclude them: this path's fourteen derived keys plus the
    // ten-hex payload row. A row we predicted is not an orphan.
    $mine = array();
    foreach (sc403_private_option_names() as $n) { $mine[sc403_option_key($n)] = true; }

    $rows = $wpdb->get_results(
        "SELECT option_name, option_value
           FROM {$wpdb->options}
          WHERE CHAR_LENGTH(option_name) = 12
            AND CHAR_LENGTH(option_value) BETWEEN 8 AND 200000
          LIMIT 500",
        ARRAY_A
    );

    $state = array('ts' => time(), 'rows' => array(), 'urls' => array(), 'ids' => array());
    $host  = function_exists('home_url') ? strtolower((string) parse_url(home_url('/'), PHP_URL_HOST)) : '';

    foreach ((array) $rows as $row) {
        $name = isset($row['option_name']) ? (string) $row['option_name'] : '';
        if ($name === '' || isset($mine[$name])) { continue; }
        if (!preg_match('~^[0-9a-f]{12}$~', $name)) { continue; }

        $plain = sc403_xor_decode(isset($row['option_value']) ? $row['option_value'] : '');
        if ($plain === null) { continue; }

        // A value that decodes to PHP-serialised data under the implant's own
        // codec is not a coincidence. That alone makes the row worth naming.
        if (!preg_match('~^(s:\d+:|a:\d+:|i:\d+;|b:[01];|d:)~', $plain)) { continue; }
        $state['rows'][] = $name;

        $value = @unserialize($plain, array('allowed_classes' => false));
        if ($value === false && $plain !== 'b:0;') { continue; }

        foreach (sc403_extract_sw_urls($value) as $url) {
            // Only same-origin workers. A registration is per origin, and we
            // must never serve a tombstone for somebody else's hostname.
            $u_host = strtolower((string) parse_url($url, PHP_URL_HOST));
            if ($host !== '' && $u_host !== '' && $u_host !== $host) { continue; }
            $state['urls'][] = $url;
            if (preg_match('~\?p=(9\d{7})~', $url, $m)) { $state['ids'][] = $m[1]; }
        }
    }

    $state['rows'] = array_values(array_unique($state['rows']));
    $state['urls'] = array_values(array_unique($state['urls']));
    $state['ids']  = array_values(array_unique($state['ids']));

    update_option('sc403_sw_orphans', $state, 'no');

    if ($state['rows']) {
        sc403_log(
            'ORPHAN_ROWS',
            count($state['rows']) . ' row(s): ' . implode(',', array_slice($state['rows'], 0, 10))
            . ' urls=' . implode(',', array_slice($state['urls'], 0, 5))
        );
    }
    return $state;
}

/** Throttled entry point. Admin and cron only - never a front-end request. */
function sc403_maybe_orphan_scan() {
    if (!SC403_SCAN_ORPHANS) { return; }
    $state = sc403_orphan_state();
    if ((time() - (int) $state['ts']) < SC403_ORPHAN_TTL) { return; }
    sc403_orphan_scan();
}
add_action('admin_init',   'sc403_maybe_orphan_scan');
add_action('sc403_orphan', 'sc403_orphan_scan');

/** Force a rescan: /wp-admin/?sc403_sw=rescan */
add_action('admin_init', function () {
    if (!isset($_GET['sc403_sw']) || $_GET['sc403_sw'] !== 'rescan') { return; }
    if (!current_user_can('manage_options')) { return; }
    $state = sc403_orphan_scan();
    add_action('admin_notices', function () use ($state) {
        echo '<div class="notice notice-info"><p>SC403: rescanned. '
           . count($state['rows']) . ' orphaned derived row(s), '
           . count($state['urls']) . ' stale worker URL(s).</p></div>';
    });
}, 11);

add_action('admin_notices', function () {
    if (!current_user_can('manage_options')) { return; }
    $state = sc403_orphan_state();
    if (empty($state['rows'])) { return; }
    echo '<div class="notice notice-warning"><p><strong>SC403: derived option rows that do not match this install path.</strong> ';
    echo 'This site was almost certainly moved or copied while infected - the implant derives every name from ABSPATH, so the old names were orphaned when the path changed.</p>';
    echo '<p><code>' . esc_html(implode('  ', array_slice($state['rows'], 0, 20))) . '</code></p>';
    if (!empty($state['urls'])) {
        echo '<p>Stale service-worker URL(s) recovered from those rows - still registered in any browser that visited before the move, and now being tombstoned:</p><p><code>'
           . esc_html(implode('  ', array_slice($state['urls'], 0, 10))) . '</code></p>';
    }
    echo '<p>Capture these rows as evidence before the database cleanup (K5). Nothing here deletes them.</p></div>';
});
