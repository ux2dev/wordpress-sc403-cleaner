<?php
/**
 * Plugin Name: SC 4.0.3 Guard
 * Description: Early warning and hardening against the "SC 4.0.3" self-healing WordPress
 *              malware. Watches the four filesystem locations the implant needs
 *              (mu-plugins, drop-ins, theme functions.php, PHP startup config),
 *              detects an administrator account hidden behind pre_user_query,
 *              blocks the implant's generated admin-name pattern, and audits the
 *              administrator's browser for the service worker that survives
 *              server-side cleanup.
 * Version:     1.0.0
 * Requires at least: 5.6
 * Requires PHP: 7.4
 * Author:      Hristo Laskov (hristo@ux2.dev)
 * License:     GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * Installation: upload to wp-content/mu-plugins/sc403-guard.php
 *
 * ---------------------------------------------------------------------------
 * READ THIS FIRST -- what this file can and cannot do
 * ---------------------------------------------------------------------------
 * This is a TRIPWIRE for a site you believe is clean. It is NOT a cleaner and
 * NOT a shield for a site that is already infected.
 *
 * SC 4.0.3 runs *above* anything an mu-plugin can reach:
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
 * Persistence mesh this watches for (see README.md):
 *   Layer 1 (files)   -- new/changed files in mu-plugins and the drop-in slots
 *   Layer 2 (theme)   -- appended blocks in active + parent theme functions.php
 *   Layer 3 (php.ini) -- auto_prepend_file appearing in .user.ini / .htaccess
 *   Layer 4 (users)   -- administrator visible to SQL but hidden from get_users()
 *   Layer 5 (users)   -- creation of admin_/adm_/administrator_/backup_ + hex accounts
 *   Layer 6 (db)      -- sc_* options, transients and the sc_cron_fetch event
 *   Layer 7 (browser) -- unexpected service worker registered in wp-admin
 *
 * Optional constants (define in wp-config.php):
 *   define( 'SC403_GUARD_EMAIL', 'you@example.com' );  // where alerts are sent
 *   define( 'SC403_GUARD_DISABLE_SW_AUDIT', true );    // skip the browser check
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

    /** Option and transient name fragments the implant is known to use. */
    private const ROGUE_OPTIONS = [
        'sc_payload_persistent',
        'sc_persist_manifest',
        'sc_last_recovery_check',
        'sc_last_rpc',
        'sc_last_fetch_ts',
        'sc_initialized',
    ];

    /** Scheduled event the implant registers for self-repair. */
    private const ROGUE_CRON_HOOK = 'sc_cron_fetch';

    private static ?self $instance = null;

    public static function boot(): void {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }
    }

    private function __construct() {
        // Layer 5 -- refuse the generated administrator name at both the
        // validation layer and the last point before the INSERT.
        add_filter( 'illegal_user_logins', [ $this, 'add_illegal_logins' ] );
        add_filter( 'wp_pre_insert_user_data', [ $this, 'block_rogue_insert' ], 10, 4 );

        // Layers 1-4, 6 -- throttled scan on admin page loads plus an hourly cron.
        add_action( 'admin_init', [ $this, 'maybe_scan' ] );
        add_action( 'sc403_guard_scan', [ $this, 'scan' ] );
        if ( ! wp_next_scheduled( 'sc403_guard_scan' ) ) {
            wp_schedule_event( time() + 300, 'hourly', 'sc403_guard_scan' );
        }

        // Report.
        add_action( 'admin_notices', [ $this, 'render_notice' ] );

        // Layer 7 -- audit the administrator's own browser.
        if ( ! defined( 'SC403_GUARD_DISABLE_SW_AUDIT' ) || ! SC403_GUARD_DISABLE_SW_AUDIT ) {
            add_action( 'admin_footer', [ $this, 'render_service_worker_audit' ] );
        }
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
                'Blocked creation of user "%s" -- matches the SC 4.0.3 generated administrator pattern.',
                $data['user_login']
            ) );
            // An empty login makes wp_insert_user() fail with an error rather
            // than writing the row.
            $data['user_login'] = '';
        }
        return $data;
    }

    // -----------------------------------------------------------------------
    // Scanning
    // -----------------------------------------------------------------------

    public function maybe_scan(): void {
        $last = (int) get_option( 'sc403_guard_last_scan', 0 );
        if ( ( time() - $last ) < self::SCAN_INTERVAL ) {
            return;
        }
        $this->scan();
    }

    public function scan(): void {
        update_option( 'sc403_guard_last_scan', time(), false );

        $findings = [];
        $findings = array_merge( $findings, $this->check_filesystem() );
        $findings = array_merge( $findings, $this->check_prepend_directives() );
        $findings = array_merge( $findings, $this->check_hidden_admins() );
        $findings = array_merge( $findings, $this->check_database() );

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

        $current = [];
        foreach ( array_unique( $watch ) as $file ) {
            if ( is_readable( $file ) && is_file( $file ) ) {
                $current[ $file ] = filesize( $file ) . ':' . md5_file( $file );
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
            $head = (string) @file_get_contents( $file, false, null, 0, 8192 );
            $tail = $this->tail( $file, 8192 );
            foreach ( [ 'SC_ADV_BEGIN', 'SC_DB_BEGIN', 'SC_TH_BEGIN', 'sc_payload_persistent' ] as $marker ) {
                if ( false !== strpos( $head . $tail, $marker ) ) {
                    $findings[] = sprintf( 'SC 4.0.3 marker "%s" found in %s', $marker, $file );
                }
            }
        }

        update_option( self::BASELINE_OPT, $current, false );
        return $findings;
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
                    'Administrator "%s" matches the SC 4.0.3 generated-name pattern.',
                    $login
                );
            }
        }
        return $findings;
    }

    /**
     * Layer 6: options, transients and the self-repair cron event.
     */
    private function check_database(): array {
        global $wpdb;
        $findings = [];

        foreach ( self::ROGUE_OPTIONS as $name ) {
            $exists = $wpdb->get_var( $wpdb->prepare(
                "SELECT option_name FROM {$wpdb->options} WHERE option_name = %s LIMIT 1",
                $name
            ) );
            if ( $exists ) {
                $findings[] = sprintf( 'SC 4.0.3 option present in the database: %s', $name );
            }
        }

        $transients = $wpdb->get_col(
            "SELECT option_name FROM {$wpdb->options}
              WHERE option_name LIKE '\\_transient\\_sc\\_%' LIMIT 10"
        );
        foreach ( (array) $transients as $t ) {
            $findings[] = sprintf( 'SC 4.0.3 transient present: %s', $t );
        }

        if ( wp_next_scheduled( self::ROGUE_CRON_HOOK ) ) {
            $findings[] = sprintf( 'Self-repair cron event "%s" is scheduled.', self::ROGUE_CRON_HOOK );
        }
        return $findings;
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
     *                          implant suppresses some notification mail, and
     *                          a noisy false positive trains people to ignore
     *                          the alert.
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
        echo '<div class="notice notice-error"><p><strong>SC 4.0.3 Guard</strong> found indicators on this site:</p><ul style="list-style:disc;margin-left:2em">';
        foreach ( $findings as $finding ) {
            echo '<li>' . esc_html( $finding ) . '</li>';
        }
        echo '</ul><p>Do not start deleting files one at a time. Run <code>sc403-scan.sh</code> from a shell and follow the eradication order in the README.</p></div>';
    }

    // -----------------------------------------------------------------------
    // Layer 7: the administrator's browser
    // -----------------------------------------------------------------------

    /**
     * SC 4.0.3 registers a service worker scoped to "/" from wp-admin. It
     * intercepts login POSTs and can re-upload the plugin using the
     * administrator's own session -- so it survives a perfect server cleanup.
     * WordPress core registers no service worker, so on a stock site any
     * registration here deserves a look.
     */
    public function render_service_worker_audit(): void {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }
        ?>
        <script>
        ( function () {
            if ( ! ( 'serviceWorker' in navigator ) ) { return; }
            navigator.serviceWorker.getRegistrations().then( function ( regs ) {
                if ( ! regs.length ) { return; }
                var box = document.createElement( 'div' );
                box.className = 'notice notice-error';
                box.style.margin = '10px 20px 10px 2px';
                box.style.padding = '10px';
                var list = regs.map( function ( r ) {
                    return r.scope + ( r.active && r.active.scriptURL ? ' -> ' + r.active.scriptURL : '' );
                } ).join( '<br>' );
                box.innerHTML =
                    '<p><strong>SC 4.0.3 Guard:</strong> ' + regs.length +
                    ' service worker(s) registered in this browser for this site. ' +
                    'WordPress core registers none. If you did not install a PWA plugin, ' +
                    'this is the browser-side half of the infection and it survives server cleanup.</p>' +
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
                        box.innerHTML = '<p><strong>SC 4.0.3 Guard:</strong> service workers unregistered ' +
                            'and cache storage cleared. Now clear this site\'s cookies and site data, ' +
                            'then change your password from a different device.</p>';
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
