<?php
/**
 * Plugin Name: SC 4.x Guard
 * Description: Early warning and hardening against the "SC 4.x" self-healing WordPress
 *              malware (SC 4.0.3 through SCV:4.3.24). Watches the filesystem
 *              locations the implant needs, computes the site-specific names it
 *              derives from ABSPATH and looks for exactly those, detects an
 *              administrator hidden behind pre_user_query, blocks the generated
 *              admin-name pattern, spots database rows left behind by a site that
 *              was moved while infected, and audits the administrator's browser
 *              for the service worker that survives server-side cleanup.
 * Version:     2.0.0
 * Requires at least: 5.6
 * Requires PHP: 7.4
 * Author:      Hristo Laskov (hristo@ux2.dev)
 * License:     GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * Installation: upload to wp-content/mu-plugins/sc403-guard.php
 * Repo:         https://github.com/ux2dev/wordpress-sc403-cleaner
 *
 * ---------------------------------------------------------------------------
 * READ THIS FIRST -- what this file can and cannot do
 * ---------------------------------------------------------------------------
 * This is a TRIPWIRE for a site you believe is clean. It is NOT a cleaner and
 * NOT a shield for a site that is already infected.
 *
 * SC 4.x runs *above* anything an mu-plugin can reach:
 *   - a .user.ini auto_prepend_file directive executes before PHP loads WordPress;
 *   - wp-content/db.php and advanced-cache.php are drop-ins that load before
 *     must-use plugins do;
 *   - the payload accepts regular expressions from its C2 telling it which
 *     rival code to strip out of plugins, mu-plugins and themes.
 *
 * So on an infected site this file can be neutralised, and its silence proves
 * nothing. Detection on a live compromise belongs in sc403-scan.sh, run from a
 * shell, outside PHP. Use this file to find out *early* -- ideally on the day
 * the first artefact lands, while it is still one file and not nine.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS NEW IN 2.0.0, AND WHY
 * ---------------------------------------------------------------------------
 * 4.3.24 pads every file it writes with megabytes of random hex, so file
 * hashes are worthless as indicators. What it cannot randomise is its naming:
 * three families of identifier, all derived from ABSPATH with plain md5(), all
 * therefore computable by the defender before the malware has done anything.
 *
 *   FILES      substr(md5(ABSPATH . role), 0, n)
 *   ENDPOINTS  91000000 + hexdec(md5(ABSPATH . 'ep' . role)[0:7]) % 8999999
 *   OPTIONS    substr(md5(ABSPATH . '93819' . name), 0, 12)
 *
 * This version computes all three for the site it is installed on and watches
 * for exactly those names. It is an equality test, not a heuristic: a file at
 * the predicted path, or a database row at the predicted key, is not a
 * coincidence that a legitimate plugin can produce.
 *
 * 93819 is the same constant the implant uses for its forged timestamps
 * (mtime % 100000 == 93819), which is why one number unlocks both families.
 *
 * Persistence mesh this watches for (see README.md):
 *   Layer 1 (files)   -- new/changed files in mu-plugins and the drop-in slots
 *   Layer 2 (theme)   -- appended blocks in active + parent theme functions.php
 *   Layer 3 (php.ini) -- auto_prepend_file appearing in .user.ini / .htaccess
 *   Layer 4 (users)   -- administrator visible to SQL but hidden from get_users()
 *   Layer 5 (users)   -- creation of admin_/adm_/administrator_/backup_ + hex accounts
 *   Layer 6 (db)      -- sc_* options, the derived option keys, the cron event
 *   Layer 7 (browser) -- unexpected service worker registered in wp-admin
 *   Layer 8 (names)   -- any of the ABSPATH-derived artefact names existing
 *   Layer 9 (size)    -- PHP files inside the 4.3.24 padding band
 *
 * Optional constants (define in wp-config.php):
 *   define( 'SC403_GUARD_EMAIL', 'you@example.com' );  // where alerts are sent
 *   define( 'SC403_GUARD_DISABLE_SW_AUDIT', true );    // skip the browser check
 *   define( 'SC403_GUARD_SCAN_INTERVAL', 900 );        // seconds between scans
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

final class SC403_Guard {

    /** Option holding the filesystem baseline. */
    private const BASELINE_OPT = 'sc403_guard_baseline';

    /** Option holding findings from the most recent scan. */
    private const FINDINGS_OPT = 'sc403_guard_findings';

    /** Throttle: seconds between filesystem scans. */
    private const SCAN_INTERVAL = 900;

    /** Usernames the implant generates for its concealed administrator. */
    private const ROGUE_USER_PATTERN = '/^(admin_|adm_|administrator_|backup_)[0-9a-f]{6,10}$/i';

    /**
     * The timestomp residue, and the salt in the option-key derivation.
     * Files are backdated so that filemtime() % 100000 === this.
     */
    private const WATERMARK = 93819;

    /**
     * 4.3.24 inflates every file it writes to a random size between 5.5 and
     * 7.0 MB. Anything over this floor in wp-content is worth a look on its own.
     */
    private const PAD_FLOOR = 4000000;

    /**
     * Plaintext option names the implant is known to use. These are the easy
     * half -- the derived keys below are the half that cleanups miss.
     */
    private const ROGUE_OPTIONS = [
        'sc_payload_persistent',
        'sc_persist_manifest',
        'sc_last_recovery_check',
        'sc_last_rpc',
        'sc_last_fetch_ts',
        'sc_initialized',
        'sc_last_c2',
        'sc_c2_cache',
        'sc_own_rec',
        'sc_own_manifest',
        'sc_sw_had',
        'sc_sw_last_url',
        'sc_ini_fail',
        'sc_ini_dead',
        'sc_fetch_fails',
        'sc_pad_off_ts',
    ];

    /**
     * The private-option slot names, verbatim from the core's own call sites.
     * Fourteen, counting the empty-string slot. Their real key is
     * md5(ABSPATH . 93819 . name)[0:12], which is what makes them invisible to
     * a `LIKE 'sc\_%'` search -- and what makes such a cleanup destroy the two
     * most valuable rows on the system: sw_cached (the JavaScript being served
     * to your admins) and issued (who holds forged 14-day sessions).
     */
    private const PRIVATE_SLOTS = [
        'sw_url', 'sw_cached', 'sw_config', 'sw_config_sig', 'srv_key',
        'page_cached', 'js_cached', 'src', 'issued', 'bp', 'bu', 'ic',
        'errors', '',
    ];

    /** Scheduled event the implant registers for self-repair. */
    private const ROGUE_CRON_HOOK = 'sc_cron_fetch';

    /** Content markers written into the files themselves. */
    private const CONTENT_MARKERS = [
        'SC_ADV_BEGIN', 'SC_DB_BEGIN', 'SC_TH_BEGIN', 'SC_CORE_BOOT_VER',
        'sc_payload_persistent', 'sc_boot_ver', '/* SCV:',
    ];

    private static ?self $instance = null;

    /** ABSPATH as the implant normalises it: forward slashes, trailing slash. */
    private string $root;

    public static function boot(): void {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }
    }

    private function __construct() {
        $this->root = rtrim( str_replace( '\\', '/', ABSPATH ), '/' ) . '/';

        // Layer 5 -- refuse the generated administrator name at both the
        // validation layer and the last point before the INSERT.
        add_filter( 'illegal_user_logins', [ $this, 'add_illegal_logins' ] );
        add_filter( 'wp_pre_insert_user_data', [ $this, 'block_rogue_insert' ], 10, 4 );

        // Layers 1-4, 6, 8, 9 -- throttled scan on admin page loads plus an hourly cron.
        add_action( 'admin_init', [ $this, 'maybe_scan' ] );
        add_action( 'sc403_guard_scan', [ $this, 'scan' ] );
        if ( ! wp_next_scheduled( 'sc403_guard_scan' ) ) {
            wp_schedule_event( time() + 300, 'hourly', 'sc403_guard_scan' );
        }

        // Any request to a derived endpoint is a browser asking for the worker.
        add_action( 'init', [ $this, 'watch_endpoints' ], 0 );

        // Report.
        add_action( 'admin_notices', [ $this, 'render_notice' ] );

        // Layer 7 -- audit the administrator's own browser.
        if ( ! defined( 'SC403_GUARD_DISABLE_SW_AUDIT' ) || ! SC403_GUARD_DISABLE_SW_AUDIT ) {
            add_action( 'admin_footer', [ $this, 'render_service_worker_audit' ] );
        }
    }

    // -----------------------------------------------------------------------
    // The three derivations
    // -----------------------------------------------------------------------

    /** substr(md5(ABSPATH . role), 0, $len) -- the filename family. */
    public function derived_name( string $role, int $len = 8 ): string {
        return substr( md5( $this->root . $role ), 0, $len );
    }

    /** substr(md5(ABSPATH . '93819' . name), 0, 12) -- the database family. */
    public function derived_option_key( string $slot ): string {
        return substr( md5( $this->root . self::WATERMARK . $slot ), 0, 12 );
    }

    /**
     * 91000000 + hexdec(md5(ABSPATH . 'ep' . role)[0:7]) % 8999999 -- the HTTP
     * family. Always an eight-digit number used as a WordPress post ID, which
     * is why a request for ?p=9XXXXXXX on a real site is close to a
     * zero-false-positive signal. Nobody has ninety-one million posts.
     */
    public function derived_endpoint_id( string $role ): string {
        $n = hexdec( substr( md5( $this->root . 'ep' . $role ), 0, 7 ) );
        return (string) ( 91000000 + ( $n % 8999999 ) );
    }

    /** Every artefact path this ABSPATH predicts, as path => description. */
    private function predicted_paths(): array {
        $c    = defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR : $this->root . 'wp-content';
        $dir  = $this->derived_name( 'dir' );
        $g    = $this->derived_name( 'g' );
        $sc   = $c . '/.sc_' . $dir;

        $paths = [
            $c . '/' . $this->derived_name( 'htl' ) . '.php'  => 'visible loader',
            $c . '/.' . $this->derived_name( 'ldr' ) . '.php' => 'hidden loader',
            $sc                                                => 'staging directory',
            $sc . '/core_' . $this->derived_name( 'core' ) . '.php' => 'canonical core',
            $sc . '/' . $this->derived_name( 'inst' ) . '.php'      => 'installer template',
            $sc . '/own_' . $this->derived_name( 'own' ) . '.php'   => 'state manifest',
            $c . '/' . $this->derived_name( 'zip' ) . '.zip'        => 'replica archive',
            $c . '/.wp-object-cache-' . $this->derived_name( 'oc' ) . '.dat'     => 'object-cache replica',
            $c . '/.wp-object-cache-' . $this->derived_name( 'oc' ) . '.dat.lkg' => 'object-cache replica (last known good)',
            $c . '/.g_' . $g . '.php' => 'guard stub',
        ];
        foreach ( [ 'gl_', 'gm_', 'gp_', 'gs_', 'gv_' ] as $prefix ) {
            $paths[ $c . '/.' . $prefix . $g ] = 'guard daemon state (' . rtrim( $prefix, '_' ) . ')';
        }
        return $paths;
    }

    // -----------------------------------------------------------------------
    // Layer 5: block the generated administrator name
    // -----------------------------------------------------------------------

    /**
     * WordPress rejects any login listed here, for every registration path.
     */
    public function add_illegal_logins( $logins ): array {
        $logins = is_array( $logins ) ? $logins : [];
        // illegal_user_logins is an exact-match list, so seed the common
        // prefixes; block_rogue_insert() below covers the hex suffixes.
        return array_merge( $logins, [ 'admin_', 'adm_', 'administrator_', 'backup_' ] );
    }

    /**
     * Last gate before the users row is written. Catches the full pattern.
     */
    public function block_rogue_insert( $data, $update, $user_id, $userdata ) {
        if ( ! is_array( $data ) || empty( $data['user_login'] ) ) {
            return $data;
        }
        if ( preg_match( self::ROGUE_USER_PATTERN, (string) $data['user_login'] ) ) {
            $this->record( sprintf(
                'Blocked creation of user "%s" -- matches the SC generated administrator pattern.',
                $data['user_login']
            ) );
            // An empty login makes wp_insert_user() fail with an error rather
            // than writing the row.
            $data['user_login'] = '';
        }
        return $data;
    }

    // -----------------------------------------------------------------------
    // Layer 8b: the HTTP endpoints
    // -----------------------------------------------------------------------

    /**
     * The implant answers ?p=<derived id> at MU-plugin file scope, before
     * WordPress can resolve the query, and serves the service-worker
     * JavaScript from there. We cannot intercept that on an infected site --
     * a file-scope handler in an earlier-loading file has already exited. What
     * we CAN do on a clean site is notice that somebody is asking for it,
     * which means a browser somewhere still holds a registration.
     */
    public function watch_endpoints(): void {
        if ( empty( $_GET['p'] ) || ! is_scalar( $_GET['p'] ) ) {
            return;
        }
        $p = trim( (string) $_GET['p'] );
        if ( ! preg_match( '/^9\d{7}$/', $p ) ) {
            return;
        }
        // One record per minute, whatever the traffic looks like.
        if ( get_transient( 'sc403_guard_ep_seen' ) ) {
            return;
        }
        set_transient( 'sc403_guard_ep_seen', 1, MINUTE_IN_SECONDS );
        if ( $p === $this->derived_endpoint_id( 'sw' ) ) {
            $this->record( sprintf(
                'A browser requested the derived service-worker endpoint ?p=%s from %s. '
                . 'That registration predates this scan: the browser still holds the malicious worker.',
                $p, $this->client_ip()
            ) );
        } elseif ( $p === $this->derived_endpoint_id( 'inst' ) ) {
            $this->record( sprintf(
                'A browser POSTed to the derived installer endpoint ?p=%s from %s.',
                $p, $this->client_ip()
            ) );
        } else {
            // Eight-digit post IDs starting with 9 do not occur naturally.
            $this->record( sprintf(
                'Request for ?p=%s -- an impossible post ID, and the shape SC uses for its endpoints. '
                . 'If this site was ever moved, it may be an endpoint derived from the OLD path.',
                $p
            ) );
        }
    }

    private function client_ip(): string {
        $ip = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '-';
        return preg_match( '/^[0-9a-fA-F:.]{3,45}$/', $ip ) ? $ip : '-';
    }

    // -----------------------------------------------------------------------
    // Scanning
    // -----------------------------------------------------------------------

    public function maybe_scan(): void {
        $interval = defined( 'SC403_GUARD_SCAN_INTERVAL' )
            ? (int) SC403_GUARD_SCAN_INTERVAL
            : self::SCAN_INTERVAL;
        $last = (int) get_option( 'sc403_guard_last_scan', 0 );
        if ( ( time() - $last ) < $interval ) {
            return;
        }
        $this->scan();
    }

    public function scan(): void {
        update_option( 'sc403_guard_last_scan', time(), false );

        $findings = [];
        $findings = array_merge( $findings, $this->check_filesystem() );
        $findings = array_merge( $findings, $this->check_predicted_names() );
        $findings = array_merge( $findings, $this->check_padding() );
        $findings = array_merge( $findings, $this->check_timestomp() );
        $findings = array_merge( $findings, $this->check_prepend_directives() );
        $findings = array_merge( $findings, $this->check_hidden_admins() );
        $findings = array_merge( $findings, $this->check_database() );
        $findings = array_merge( $findings, $this->check_derived_options() );
        $findings = array_merge( $findings, $this->check_orphan_options() );
        $findings = array_merge( $findings, $this->check_fight_log() );

        $previous = (array) get_option( self::FINDINGS_OPT, [] );
        update_option( self::FINDINGS_OPT, $findings, false );

        // Only alert on findings that are new since the last scan, so a standing
        // problem does not mail the owner every hour.
        $fresh = array_values( array_diff( $findings, $previous ) );
        if ( $fresh ) {
            $this->respond_to_detection( $fresh );
        }
    }

    /**
     * Layers 1-2: hash the files the implant must touch, and diff against a
     * baseline captured the first time this runs.
     */
    private function check_filesystem(): array {
        $watch = [];

        $mu = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
        foreach ( (array) glob( $mu . '/*.php' ) as $file ) {
            $watch[] = $file;
        }
        foreach ( [ 'db.php', 'advanced-cache.php', 'object-cache.php' ] as $dropin ) {
            $watch[] = WP_CONTENT_DIR . '/' . $dropin;
        }
        $watch[] = get_stylesheet_directory() . '/functions.php';
        $watch[] = get_template_directory() . '/functions.php';
        $watch[] = ABSPATH . 'wp-config.php';

        $current = [];
        foreach ( array_unique( $watch ) as $file ) {
            if ( is_readable( $file ) && is_file( $file ) ) {
                // Hash the head and tail rather than the whole file: 4.3.24
                // pads its writes into the megabytes, and md5_file() on a 7 MB
                // file every fifteen minutes is a real cost for no extra signal.
                $size = (int) filesize( $file );
                $sig  = $size . ':' . md5( $this->head( $file, 65536 ) . $this->tail( $file, 65536 ) );
                $current[ $file ] = $sig;
            }
        }

        $baseline = get_option( self::BASELINE_OPT, null );
        if ( null === $baseline ) {
            // First run: adopt the current state. This is why the guard belongs
            // on a site you have already verified is clean.
            update_option( self::BASELINE_OPT, $current, false );
            return [];
        }

        $findings = [];
        foreach ( $current as $file => $sig ) {
            if ( ! isset( $baseline[ $file ] ) ) {
                $findings[] = sprintf( 'New file in a persistence slot: %s', $file );
            } elseif ( $baseline[ $file ] !== $sig ) {
                $findings[] = sprintf( 'Watched file changed: %s', $file );
            }
        }
        foreach ( array_keys( $baseline ) as $file ) {
            if ( ! isset( $current[ $file ] ) ) {
                $findings[] = sprintf( 'Watched file disappeared: %s', $file );
            }
        }

        // Content markers, in case a change slipped in before the baseline.
        foreach ( array_keys( $current ) as $file ) {
            $window = $this->head( $file, 8192 ) . $this->tail( $file, 8192 );
            foreach ( self::CONTENT_MARKERS as $marker ) {
                if ( false !== strpos( $window, $marker ) ) {
                    $findings[] = sprintf( 'SC marker "%s" found in %s', $marker, $file );
                }
            }
        }

        // wp-config.php gets `define('WP_CACHE', true); /* SC_WC */` so that
        // WordPress loads the advanced-cache.php drop-in for it.
        $config = ABSPATH . 'wp-config.php';
        if ( is_readable( $config ) && false !== strpos( (string) @file_get_contents( $config ), 'SC_WC' ) ) {
            $findings[] = 'wp-config.php carries the SC_WC marker (WP_CACHE forced on to load advanced-cache.php).';
        }

        update_option( self::BASELINE_OPT, $current, false );
        return $findings;
    }

    /**
     * Layer 8: the names this ABSPATH predicts. An equality test, not a
     * heuristic -- if a file exists at one of these paths, the only thing that
     * put it there computed md5(ABSPATH . role).
     */
    private function check_predicted_names(): array {
        $findings = [];
        foreach ( $this->predicted_paths() as $path => $what ) {
            if ( file_exists( $path ) ) {
                $findings[] = sprintf( 'Predicted SC artefact exists (%s): %s', $what, $path );
            }
        }
        return $findings;
    }

    /**
     * Layer 9: the padding band. Works even when every name has changed,
     * because inflating a PHP file to several megabytes is the one thing the
     * implant does that is visible without knowing anything about it.
     */
    private function check_padding(): array {
        $findings = [];
        $dirs = [
            defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins',
            WP_CONTENT_DIR,
        ];
        foreach ( $dirs as $dir ) {
            foreach ( (array) glob( $dir . '/*.php' ) as $file ) {
                if ( is_file( $file ) && (int) filesize( $file ) > self::PAD_FLOOR ) {
                    $findings[] = sprintf(
                        'PHP file of %d bytes: %s -- inside the SC 4.3.24 padding band.',
                        (int) filesize( $file ),
                        $file
                    );
                }
            }
        }
        return $findings;
    }

    /**
     * The timestomp watermark. The implant backdates what it writes so that
     * filemtime() % 100000 === 93819, and it uses that same test to decide
     * whether a site is already infected before spreading to it.
     */
    private function check_timestomp(): array {
        $findings = [];
        $mu = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
        $files = array_merge(
            (array) glob( $mu . '/*.php' ),
            (array) glob( WP_CONTENT_DIR . '/*.php' ),
            (array) glob( WP_CONTENT_DIR . '/plugins/*/*.php' )
        );
        foreach ( $files as $file ) {
            if ( ! is_file( $file ) ) {
                continue;
            }
            $mtime = (int) @filemtime( $file );
            if ( $mtime > 0 && ( $mtime % 100000 ) === self::WATERMARK ) {
                $findings[] = sprintf(
                    'Watermarked timestamp (mtime %% 100000 == %d) on %s -- either SC wrote it, or somebody planted a decoy.',
                    self::WATERMARK,
                    $file
                );
            }
        }
        return array_slice( $findings, 0, 20 );
    }

    /**
     * Layer 3: auto_prepend_file is how the implant runs before WordPress.
     */
    private function check_prepend_directives(): array {
        $findings = [];
        $dirs = array_unique( [ ABSPATH, WP_CONTENT_DIR, dirname( untrailingslashit( ABSPATH ) ) ] );

        foreach ( $dirs as $dir ) {
            foreach ( [ '.user.ini', '.htaccess' ] as $name ) {
                $file = trailingslashit( $dir ) . $name;
                if ( is_readable( $file ) && false !== strpos( (string) @file_get_contents( $file ), 'auto_prepend_file' ) ) {
                    $findings[] = sprintf( 'auto_prepend_file directive present in %s', $file );
                }
            }
        }

        // The running configuration is the authority, not just the files.
        $ini = (string) ini_get( 'auto_prepend_file' );
        if ( '' !== $ini ) {
            $findings[] = sprintf( 'PHP is running with auto_prepend_file = %s', $ini );
        }
        return $findings;
    }

    /**
     * Layer 4: the implant filters pre_user_query, the REST responses and the
     * user counts to hide its administrator. It cannot filter $wpdb, so the
     * API view and the SQL view disagree exactly when you are infected.
     */
    private function check_hidden_admins(): array {
        global $wpdb;
        $findings = [];

        $api = get_users( [ 'role' => 'administrator', 'fields' => 'user_login' ] );
        $api = array_map( 'strval', (array) $api );

        $raw = $wpdb->get_col( $wpdb->prepare(
            "SELECT u.user_login
               FROM {$wpdb->users} u
               INNER JOIN {$wpdb->usermeta} m ON m.user_id = u.ID
              WHERE m.meta_key = %s
                AND m.meta_value LIKE %s",
            $wpdb->get_blog_prefix() . 'capabilities',
            '%administrator%'
        ) );
        $raw = array_map( 'strval', (array) $raw );

        foreach ( array_diff( $raw, $api ) as $hidden ) {
            $findings[] = sprintf(
                'Administrator "%s" exists in the database but is hidden from the Users screen.',
                $hidden
            );
        }
        foreach ( $raw as $login ) {
            if ( preg_match( self::ROGUE_USER_PATTERN, $login ) ) {
                $findings[] = sprintf(
                    'Administrator "%s" matches the SC generated-name pattern.',
                    $login
                );
            }
        }
        return $findings;
    }

    /**
     * Layer 6: plaintext options, transients and the self-repair cron event.
     */
    private function check_database(): array {
        global $wpdb;
        $findings = [];

        $names = "'" . implode( "','", array_map( 'esc_sql', self::ROGUE_OPTIONS ) ) . "'";
        $found = $wpdb->get_col(
            "SELECT option_name FROM {$wpdb->options} WHERE option_name IN ($names)"
        );
        foreach ( (array) $found as $name ) {
            $findings[] = sprintf( 'SC option present in the database: %s', $name );
        }

        // sc_c2_cache and sc_last_c2 are stored in cleartext. If they are here,
        // read them before anyone deletes anything: they are the live C2 list.
        foreach ( [ 'sc_c2_cache', 'sc_last_c2' ] as $c2opt ) {
            $value = get_option( $c2opt, '' );
            if ( is_string( $value ) && '' !== $value ) {
                $findings[] = sprintf(
                    '%s holds C2 URLs in cleartext. Record them before cleanup: %s',
                    $c2opt,
                    substr( $value, 0, 200 )
                );
            }
        }

        $transients = $wpdb->get_col(
            "SELECT option_name FROM {$wpdb->options}
              WHERE option_name LIKE '\\_transient\\_sc\\_%' LIMIT 10"
        );
        foreach ( (array) $transients as $t ) {
            $findings[] = sprintf( 'SC transient present: %s', $t );
        }

        if ( wp_next_scheduled( self::ROGUE_CRON_HOOK ) ) {
            $findings[] = sprintf( 'Self-repair cron event "%s" is scheduled.', self::ROGUE_CRON_HOOK );
        }
        return $findings;
    }

    /**
     * The fourteen derived option keys for THIS ABSPATH. None of them start
     * with sc_, so nothing that greps for a prefix will ever see them.
     */
    private function check_derived_options(): array {
        global $wpdb;

        $keys = [];
        foreach ( self::PRIVATE_SLOTS as $slot ) {
            $keys[ $this->derived_option_key( $slot ) ] = $slot;
        }
        // The payload row uses a different formula: md5(ABSPATH . 'opt')[0:10],
        // and holds base64(gzip(payload)) rather than the XOR codec.
        $payload_key = $this->derived_name( 'opt', 10 );
        $keys[ $payload_key ] = 'payload';

        $names = "'" . implode( "','", array_map( 'esc_sql', array_keys( $keys ) ) ) . "'";
        $rows  = $wpdb->get_results(
            "SELECT option_name, LENGTH(option_value) AS bytes
               FROM {$wpdb->options} WHERE option_name IN ($names)",
            ARRAY_A
        );

        $findings = [];
        foreach ( (array) $rows as $row ) {
            $name = (string) $row['option_name'];
            $findings[] = sprintf(
                'Derived SC option row present: %s (slot "%s", %d bytes). This key is md5(ABSPATH.%d.slot) -- it cannot occur by accident.',
                $name,
                isset( $keys[ $name ] ) ? $keys[ $name ] : '?',
                (int) $row['bytes'],
                self::WATERMARK
            );
        }
        return $findings;
    }

    /**
     * Derived-looking rows that this ABSPATH does NOT predict.
     *
     * Every name the implant uses comes from the install path. Move the site --
     * a migration, a staging copy, a host that changed the docroot layout --
     * and every derived name changes with it. The implant does not notice and
     * does not clean up: it starts a fresh set of rows and abandons the old
     * ones.
     *
     * Those abandoned rows matter for one reason. The stale sw_url still names
     * a service worker that is STILL REGISTERED in somebody's browser, at a
     * ?p= id nobody can derive any more, because it came from a path this
     * install no longer has. That is the one case where the arithmetic stops
     * being enough and you need the row.
     */
    private function check_orphan_options(): array {
        global $wpdb;

        $mine = [];
        foreach ( self::PRIVATE_SLOTS as $slot ) {
            $mine[] = $this->derived_option_key( $slot );
        }
        $names = "'" . implode( "','", array_map( 'esc_sql', $mine ) ) . "'";

        $rows = $wpdb->get_results(
            "SELECT option_name, option_value
               FROM {$wpdb->options}
              WHERE CHAR_LENGTH(option_name) = 12
                AND CHAR_LENGTH(option_value) BETWEEN 8 AND 200000
                AND option_name NOT IN ($names)
              LIMIT 200",
            ARRAY_A
        );

        $findings = [];
        foreach ( (array) $rows as $row ) {
            $name = (string) $row['option_name'];
            if ( ! preg_match( '/^[0-9a-f]{12}$/', $name ) ) {
                continue;
            }
            $plain = $this->xor_decode( (string) $row['option_value'] );
            if ( null === $plain ) {
                continue;
            }
            // A value that decodes to PHP-serialised data under the implant's
            // own codec is not a coincidence.
            if ( ! preg_match( '/^(s:\d+:|a:\d+:|i:\d+;|b:[01];|d:)/', $plain ) ) {
                continue;
            }

            $detail = '';
            if ( preg_match( '~https?://[^\s"\'<>]*\?p=9\d{7}~', $plain, $m ) ) {
                $detail = ' It contains a service-worker URL: ' . $m[0]
                    . ' -- that worker is still registered in any browser that used this site before the move.';
            }
            $findings[] = sprintf(
                'Option "%s" is not a key this install path predicts, but it decodes under the SC codec. '
                . 'This site was almost certainly moved or copied while infected.%s',
                $name,
                $detail
            );
        }
        return array_slice( $findings, 0, 20 );
    }

    /**
     * The implant's own record of how your cleanup went.
     *
     * Before rewriting a drop-in it consults sc_reinstall_allowed(), which reads
     * sc_reins_<key> in the form "<day number>|<count>" and refuses the rewrite
     * once the count reaches three for the current UTC day. So it counts how many
     * times you have deleted each file, and after the third deletion in one day
     * it stops putting it back - until midnight, when the day number changes.
     *
     * Which means a site in backoff looks cleaned and is not. Anyone who deleted
     * the drop-ins three times, saw them stay gone and went home has verified
     * nothing. That is worth saying out loud in the admin notice.
     */
    private function check_fight_log(): array {
        global $wpdb;

        $rows = $wpdb->get_results(
            "SELECT option_name, option_value
               FROM {$wpdb->options}
              WHERE option_name LIKE 'sc\\_reins\\_%'
                 OR option_name IN ('sc_ini_fail','sc_ini_dead','sc_ht_fail','sc_fetch_fails')",
            ARRAY_A
        );
        if ( ! $rows ) {
            return [];
        }

        $today    = (int) ( time() / 86400 );
        $findings = [];
        $capped   = false;

        foreach ( (array) $rows as $row ) {
            $name  = (string) $row['option_name'];
            $value = (string) $row['option_value'];

            if ( 0 === strpos( $name, 'sc_reins_' ) && false !== strpos( $value, '|' ) ) {
                list( $day, $count ) = array_map( 'intval', explode( '|', $value, 2 ) );
                if ( $day === $today && $count >= 3 ) {
                    $capped = true;
                    $findings[] = sprintf(
                        '%s: %d rebuilds today - at the daily cap, so this file has stopped coming back on its own.',
                        $name, $count
                    );
                } else {
                    $findings[] = sprintf(
                        '%s: %d rebuild(s) on %s.',
                        $name, $count, gmdate( 'Y-m-d', $day * 86400 )
                    );
                }
                continue;
            }
            if ( 'sc_ini_dead' === $name ) {
                $findings[] = sprintf(
                    'sc_ini_dead: the auto_prepend_file circuit breaker opened %d hours ago - its own canary refused the write.',
                    (int) ( ( time() - (int) $value ) / 3600 )
                );
                continue;
            }
            $findings[] = sprintf( '%s = %s', $name, substr( $value, 0, 60 ) );
        }

        if ( $capped ) {
            $findings[] = 'THIS SITE IS IN BACKOFF: a drop-in has hit three rebuilds today, so the implant '
                . 'has stopped restoring it until midnight UTC. A site that looks clean right now is not '
                . 'necessarily clean. Verify after 00:00 UTC, never before.';
        }
        return $findings;
    }

    /**
     * Reverses base64( keybyte . xor(serialize(v), keybyte) ). Returns null if
     * the value is not in that shape. Nothing is unserialised here -- this is a
     * text transform and stays one.
     */
    private function xor_decode( string $raw ): ?string {
        if ( strlen( $raw ) < 4 || ! preg_match( '~^[A-Za-z0-9+/=\r\n]+$~', $raw ) ) {
            return null;
        }
        $blob = base64_decode( $raw, true );
        if ( false === $blob || strlen( $blob ) < 2 ) {
            return null;
        }
        $k   = $blob[0];
        $out = '';
        for ( $i = 1, $n = strlen( $blob ); $i < $n; $i++ ) {
            $out .= chr( ord( $blob[ $i ] ) ^ ord( $k ) );
        }
        return $out;
    }

    // -----------------------------------------------------------------------
    // Response
    // -----------------------------------------------------------------------

    /**
     * Decide what happens when a fresh indicator appears.
     *
     * TODO(you): implement the alerting/containment policy for your sites.
     *
     * $findings is a list of human-readable strings, already filtered to only
     * those that are new since the previous scan.
     *
     * The trade-off is availability against containment, and the right answer
     * differs per site:
     *
     *   (a) Log only        -- error_log() and let the admin notice carry it.
     *                          Zero risk of taking a healthy site down over a
     *                          false positive, but nobody finds out until
     *                          somebody logs in.
     *   (b) Email the owner -- wp_mail() to SC403_GUARD_EMAIL. Reaches a human
     *                          who is not looking at wp-admin. Beware: the
     *                          implant blanks the recipient on some mail while
     *                          it forges sessions, and a noisy false positive
     *                          trains people to ignore the alert.
     *   (c) Hard containment -- wp_die() on wp-admin requests, or force
     *                          maintenance mode. Strongest answer, because
     *                          every extra administrator login hands the
     *                          implant a fresh session token to forge cookies
     *                          from. Also the fastest way to lock yourself out
     *                          of a site over a bad heuristic.
     *
     * My suggestion for a starting point: (a) + (b), never (c) automatically --
     * containment on this malware needs a human who has read the eradication
     * order, because a half-finished cleanup is what makes it regenerate. But
     * you run these sites, so this call is yours.
     *
     * @param string[] $findings Newly detected indicators.
     */
    private function respond_to_detection( array $findings ): void {
        // TODO(you): your policy here.
    }

    /**
     * Store a finding immediately, outside the scan cycle.
     */
    private function record( string $message ): void {
        $findings = (array) get_option( self::FINDINGS_OPT, [] );
        // Never write the same finding twice. watch_endpoints() runs on
        // ordinary front-end requests, and an option write per request is a
        // gift to anyone who decides to hammer the endpoint.
        if ( in_array( $message, $findings, true ) ) {
            return;
        }
        $findings[] = $message;
        update_option( self::FINDINGS_OPT, array_slice( array_unique( $findings ), -50 ), false );
    }

    public function render_notice(): void {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }
        $findings = (array) get_option( self::FINDINGS_OPT, [] );
        if ( ! $findings ) {
            return;
        }
        echo '<div class="notice notice-error"><p><strong>SC 4.x Guard</strong> found indicators on this site:</p><ul style="list-style:disc;margin-left:2em">';
        foreach ( $findings as $finding ) {
            echo '<li>' . esc_html( $finding ) . '</li>';
        }
        echo '</ul><p>Do not start deleting files one at a time. Run <code>sc403-scan.sh</code> from a shell and follow the eradication order in the README. '
           . 'Restart the PHP-FPM pool <em>before</em> you delete anything, and capture the database rows before you clean them.</p></div>';
    }

    /**
     * What this site's names resolve to, plus anything found so far.
     *   wp eval 'print_r( SC403_Guard::report() );'
     */
    public static function report(): array {
        self::boot();
        return self::$instance->status();
    }

    /** What this site's names resolve to. Useful in a ticket. */
    public function status(): array {
        $slots = [];
        foreach ( self::PRIVATE_SLOTS as $slot ) {
            $slots[ '' === $slot ? '(empty)' : $slot ] = $this->derived_option_key( $slot );
        }
        return [
            'abspath'        => $this->root,
            'sw_endpoint'    => '?p=' . $this->derived_endpoint_id( 'sw' ),
            'inst_endpoint'  => '?p=' . $this->derived_endpoint_id( 'inst' ),
            'payload_option' => $this->derived_name( 'opt', 10 ),
            'paths'          => array_keys( $this->predicted_paths() ),
            'option_keys'    => $slots,
            'last_scan'      => (int) get_option( 'sc403_guard_last_scan', 0 ),
            'findings'       => (array) get_option( self::FINDINGS_OPT, [] ),
        ];
    }

    // -----------------------------------------------------------------------
    // Layer 7: the administrator's browser
    // -----------------------------------------------------------------------

    /**
     * SC 4.x registers a service worker scoped to "/" from wp-admin. It
     * intercepts login POSTs and can re-upload the plugin using the
     * administrator's own session -- so it survives a perfect server cleanup.
     * WordPress core registers no service worker, so on a stock site any
     * registration here deserves a look.
     *
     * We can now name the exact scriptURL to expect, because it is
     * home_url('?p=' . derived id). A registration at that URL is not a
     * judgement call.
     */
    public function render_service_worker_audit(): void {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }
        $expected = esc_url_raw( home_url( '?p=' . $this->derived_endpoint_id( 'sw' ) ) );
        ?>
        <script>
        ( function () {
            if ( ! ( 'serviceWorker' in navigator ) ) { return; }
            var expected = <?php echo wp_json_encode( $expected ); ?>;
            navigator.serviceWorker.getRegistrations().then( function ( regs ) {
                if ( ! regs.length ) { return; }
                var known = false;
                var list = regs.map( function ( r ) {
                    var url = ( r.active && r.active.scriptURL ) || '';
                    if ( url && url.indexOf( expected ) === 0 ) { known = true; }
                    return r.scope + ( url ? ' -> ' + url : '' );
                } ).join( '<br>' );

                var box = document.createElement( 'div' );
                box.className = 'notice notice-error';
                box.style.margin = '10px 20px 10px 2px';
                box.style.padding = '10px';
                box.innerHTML =
                    '<p><strong>SC 4.x Guard:</strong> ' + regs.length +
                    ' service worker(s) registered in this browser for this site. ' +
                    ( known
                        ? 'One of them is at <code>' + expected + '</code>, which is the exact URL this ' +
                          'site\'s ABSPATH derives for the SC service worker. That is the infection, not a PWA.'
                        : 'WordPress core registers none. If you did not install a PWA plugin, ' +
                          'this is the browser-side half of the infection and it survives server cleanup.' ) +
                    '</p>' +
                    '<p style="font-family:monospace;font-size:12px">' + list + '</p>' +
                    '<p><button type="button" class="button button-primary" id="sc403-unreg">' +
                    'Unregister all service workers for this site</button></p>';
                var anchor = document.querySelector( '.wrap' ) || document.body;
                anchor.insertBefore( box, anchor.firstChild );
                document.getElementById( 'sc403-unreg' ).addEventListener( 'click', function () {
                    Promise.all( regs.map( function ( r ) { return r.unregister(); } ) ).then( function () {
                        if ( window.caches && caches.keys ) {
                            caches.keys().then( function ( keys ) {
                                keys.forEach( function ( k ) { caches.delete( k ); } );
                            } );
                        }
                        box.innerHTML = '<p><strong>SC 4.x Guard:</strong> service workers unregistered ' +
                            'and cache storage cleared. Now clear this site\'s cookies and site data, ' +
                            'then change your password from a different device. This browser is clean; ' +
                            'every other admin browser still is not.</p>';
                    } );
                } );
            } ).catch( function () {} );
        } )();
        </script>
        <?php
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /** Read the first $bytes of a file. */
    private function head( string $file, int $bytes ): string {
        return (string) @file_get_contents( $file, false, null, 0, $bytes );
    }

    /** Read the last $bytes of a file without loading all of it. */
    private function tail( string $file, int $bytes ): string {
        $size = @filesize( $file );
        if ( ! $size ) {
            return '';
        }
        $offset = max( 0, $size - $bytes );
        return (string) @file_get_contents( $file, false, null, $offset, $bytes );
    }

    private function __clone() {}
    public function __wakeup(): void {
        throw new \RuntimeException( 'Cannot unserialize SC403_Guard' );
    }
}

SC403_Guard::boot();
