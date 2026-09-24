<?php
/**
 * Checks for wp-config.php, constants, cron, database and protective plugins.
 *
 * @package CmsAdmins\SecurityCheck
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Configuration checks.
 */
class CASCR_Checks_Config extends CASCR_Checks_Base {

	/**
	 * Is debug output switched on in production?
	 *
	 * @return array
	 */
	public static function wp_debug() {
		if ( ! defined( 'WP_DEBUG' ) || ! WP_DEBUG ) {
			return CASCR_Result::pass( __( 'Debug mode is switched off.', 'security-check-report' ) );
		}

		$items = array( 'WP_DEBUG' );

		if ( defined( 'WP_DEBUG_DISPLAY' ) && WP_DEBUG_DISPLAY ) {
			$items[] = 'WP_DEBUG_DISPLAY';
		}
		if ( defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG ) {
			$items[] = 'SCRIPT_DEBUG';
		}
		if ( defined( 'SAVEQUERIES' ) && SAVEQUERIES ) {
			$items[] = 'SAVEQUERIES';
		}

		$display = defined( 'WP_DEBUG_DISPLAY' ) && WP_DEBUG_DISPLAY;

		return $display
			? CASCR_Result::fail(
				__( 'Debug mode is on and errors are printed into the page.', 'security-check-report' ),
				8,
				$items,
				__( 'Set WP_DEBUG to false in wp-config.php, or at least WP_DEBUG_DISPLAY.', 'security-check-report' )
			)
			: CASCR_Result::warn(
				__( 'Debug mode is on.', 'security-check-report' ),
				6,
				$items,
				__( 'Set WP_DEBUG to false in wp-config.php on production sites.', 'security-check-report' )
			);
	}

	/**
	 * Is the debug log readable from the web?
	 *
	 * @return array
	 */
	public static function debug_log_exposure() {
		$log = WP_CONTENT_DIR . '/debug.log';

		if ( defined( 'WP_DEBUG_LOG' ) && is_string( WP_DEBUG_LOG ) && '' !== WP_DEBUG_LOG ) {
			$log = WP_DEBUG_LOG;
		}

		if ( ! file_exists( $log ) ) {
			return CASCR_Result::pass( __( 'No debug log exists.', 'security-check-report' ) );
		}

		$size = filesize( $log );
		$item = sprintf(
			/* translators: 1: file path, 2: human readable file size. */
			__( '%1$s (%2$s)', 'security-check-report' ),
			self::relative( $log ),
			size_format( $size ? $size : 0 )
		);

		$url = self::served_url( $log );

		if ( '' === $url ) {
			return CASCR_Result::pass(
				__( 'A debug log exists, but it sits outside everything the web server hands out.', 'security-check-report' ),
				array( $item )
			);
		}

		$public = CASCR_Http::is_public( $url );

		if ( null === $public ) {
			return CASCR_Result::inconclusive(
				__( 'A debug log exists, but it could not be checked whether it is publicly readable.', 'security-check-report' )
			);
		}

		if ( $public ) {
			return CASCR_Result::fail(
				__( 'The debug log is readable from the web and exposes error details, file paths and sometimes credentials.', 'security-check-report' ),
				9,
				array( $item ),
				__( 'Delete the file and block access to it in the server configuration.', 'security-check-report' )
			);
		}

		return CASCR_Result::warn(
			__( 'A debug log exists but is not publicly readable.', 'security-check-report' ),
			4,
			array( $item ),
			__( 'Delete the file once the problem is solved.', 'security-check-report' )
		);
	}

	/**
	 * Can code be edited from the dashboard?
	 *
	 * @return array
	 */
	public static function file_edit() {
		if ( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT ) {
			return CASCR_Result::pass( __( 'The theme and plugin editor is disabled.', 'security-check-report' ) );
		}

		// map_meta_cap() denies edit_plugins and edit_themes for either
		// constant, so DISALLOW_FILE_MODS closes the editor as well. The item
		// says which of the two is doing it, because only one of them also
		// stops updates.
		if ( defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS ) {
			return CASCR_Result::pass(
				__( 'The theme and plugin editor is disabled.', 'security-check-report' ),
				array( __( 'DISALLOW_FILE_MODS closes the editor, DISALLOW_FILE_EDIT is not set', 'security-check-report' ) )
			);
		}

		return CASCR_Result::fail(
			__( 'The theme and plugin editor is available, so anyone who reaches an administrator account can run code.', 'security-check-report' ),
			8,
			array(),
			__( "Add define( 'DISALLOW_FILE_EDIT', true ); to wp-config.php.", 'security-check-report' )
		);
	}

	/**
	 * Can code be installed from the dashboard?
	 *
	 * @return array
	 */
	public static function disallow_file_mods() {
		if ( defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS ) {
			return CASCR_Result::pass( __( 'Installing plugins and themes from the dashboard is disabled.', 'security-check-report' ) );
		}

		return CASCR_Result::warn(
			__( 'Plugins and themes can be installed from the dashboard. That is the shortest path from a stolen login to running code.', 'security-check-report' ),
			5,
			array(),
			__( "On sites where code is deployed rather than installed, add define( 'DISALLOW_FILE_MODS', true ); to wp-config.php. Note that this also stops automatic updates.", 'security-check-report' )
		);
	}

	/**
	 * Are the authentication keys set, long enough and distinct?
	 *
	 * @return array
	 */
	public static function security_keys_salts() {
		$names = array(
			'AUTH_KEY',
			'SECURE_AUTH_KEY',
			'LOGGED_IN_KEY',
			'NONCE_KEY',
			'AUTH_SALT',
			'SECURE_AUTH_SALT',
			'LOGGED_IN_SALT',
			'NONCE_SALT',
		);

		$weak   = array();
		$values = array();

		foreach ( $names as $name ) {
			if ( ! defined( $name ) ) {
				$weak[] = sprintf(
					/* translators: %s: name of the wp-config.php constant. */
					__( '%s is not defined', 'security-check-report' ),
					$name
				);
				continue;
			}

			$value = (string) constant( $name );

			if ( strlen( $value ) < 32 || false !== stripos( $value, 'put your unique phrase here' ) ) {
				$weak[] = sprintf(
					/* translators: %s: name of the wp-config.php constant. */
					__( '%s is a placeholder or too short', 'security-check-report' ),
					$name
				);
				continue;
			}

			if ( in_array( $value, $values, true ) ) {
				$weak[] = sprintf(
					/* translators: %s: name of the wp-config.php constant. */
					__( '%s repeats the value of another key', 'security-check-report' ),
					$name
				);
				continue;
			}

			$values[] = $value;
		}

		if ( ! empty( $weak ) ) {
			return CASCR_Result::fail(
				__( 'The authentication keys are not set up correctly, which weakens every login cookie and nonce.', 'security-check-report' ),
				8,
				$weak,
				__( 'Generate a fresh set at api.wordpress.org/secret-key/1.1/salt/ and replace the block in wp-config.php. Everyone gets logged out once.', 'security-check-report' )
			);
		}

		// There is no record of when the keys themselves changed. All that can
		// be read is the modification time of the file they live in, which any
		// unrelated edit resets and which a restored backup carries over from
		// somewhere else. The wording stays with what was measured.
		$config   = ABSPATH . 'wp-config.php';
		$modified = file_exists( $config ) ? (int) filemtime( $config ) : 0;

		if ( $modified > 0 && ( time() - $modified ) > YEAR_IN_SECONDS ) {
			return CASCR_Result::warn(
				__( 'The authentication keys are set correctly. wp-config.php has not been changed in over a year, which usually means the keys have not been rotated either.', 'security-check-report' ),
				4,
				array(
					sprintf(
						/* translators: %s: human readable time difference, for instance "14 months". */
						__( 'wp-config.php was last modified %s ago; this is the age of the file, not of the keys', 'security-check-report' ),
						human_time_diff( $modified, time() )
					),
				),
				__( 'Generate a fresh set at api.wordpress.org/secret-key/1.1/salt/ and replace the block in wp-config.php. Rotating invalidates every stored session, which is the fastest way to lock out a stolen cookie. Everyone gets logged out once.', 'security-check-report' )
			);
		}

		return CASCR_Result::pass( __( 'All eight authentication keys are set, long enough and distinct.', 'security-check-report' ) );
	}

	/**
	 * Is the default table prefix in use?
	 *
	 * @return array
	 */
	public static function db_prefix() {
		global $wpdb;

		// On multisite every subsite carries its own numeric suffix, so only
		// the base prefix says anything about how predictable the names are.
		$prefix = is_multisite() ? $wpdb->base_prefix : $wpdb->prefix;

		if ( 'wp_' === $prefix ) {
			return CASCR_Result::warn(
				__( 'The database uses the default table prefix, which makes blind injection attempts easier.', 'security-check-report' ),
				4,
				array( $prefix ),
				__( 'Changing the prefix on a live site is risky. Do it during a migration, not as a standalone step.', 'security-check-report' )
			);
		}

		return CASCR_Result::pass(
			sprintf(
				/* translators: %s: database table prefix. */
				__( 'A custom table prefix (%s) is in use.', 'security-check-report' ),
				$prefix
			)
		);
	}

	/**
	 * Does the database account have more rights than WordPress needs?
	 *
	 * @return array
	 */
	public static function database_user_privileges() {
		global $wpdb;

		$suppress = $wpdb->suppress_errors( true );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- There is no API for grants and the result is not cacheable across sites.
		$grants = $wpdb->get_results( 'SHOW GRANTS FOR CURRENT_USER', ARRAY_N );
		$wpdb->suppress_errors( $suppress );

		if ( empty( $grants ) ) {
			return CASCR_Result::inconclusive(
				__( 'The database account is not allowed to inspect its own privileges.', 'security-check-report' )
			);
		}

		$excessive = array();

		foreach ( $grants as $row ) {
			$line = isset( $row[0] ) ? $row[0] : '';

			// Full rights on the site database are normal on shared hosting.
			// Full rights on every database, or the right to hand out rights
			// on every database, are not. A grant option that some hosts add
			// to the site database alone hands out nothing the account does
			// not already have there, so it is not counted.
			if ( preg_match( '/\bALL PRIVILEGES\s+ON\s+\*\.\*/i', $line ) ) {
				$excessive[] = __( 'all privileges on every database', 'security-check-report' );
			}

			if ( false !== stripos( $line, 'WITH GRANT OPTION' ) && preg_match( '/\bON\s+\*\.\*/i', $line ) ) {
				$excessive[] = __( 'may grant privileges on every database to other accounts', 'security-check-report' );
			}

			foreach ( array( 'SUPER', 'FILE', 'PROCESS', 'SHUTDOWN' ) as $privilege ) {
				if ( preg_match( '/\b' . $privilege . '\b/i', $line ) && preg_match( '/ON\s+\*\.\*/i', $line ) ) {
					$excessive[] = sprintf(
						/* translators: %s: name of a MySQL privilege. */
						__( 'holds the %s privilege', 'security-check-report' ),
						$privilege
					);
				}
			}
		}

		$excessive = array_values( array_unique( $excessive ) );

		if ( empty( $excessive ) ) {
			return CASCR_Result::pass( __( 'The database account is limited to what WordPress needs.', 'security-check-report' ) );
		}

		return CASCR_Result::fail(
			__( 'The database account has more rights than WordPress needs, so an injection reaches further than this site.', 'security-check-report' ),
			9,
			$excessive,
			__( 'Create a dedicated account with rights on this database only and update wp-config.php.', 'security-check-report' )
		);
	}

	/**
	 * Is the scheduler actually running, and is anything unexpected scheduled?
	 *
	 * @return array
	 */
	public static function wp_cron_health() {
		$issues   = array();
		$summary  = array();
		$score    = 0;
		$disabled = defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON;

		$crons   = _get_cron_array();
		$overdue = 0;
		$oldest  = 0;
		$now     = time();

		if ( is_array( $crons ) ) {
			foreach ( $crons as $timestamp => $hooks ) {
				if ( $timestamp >= $now ) {
					continue;
				}

				$overdue += is_array( $hooks ) ? count( $hooks ) : 0;

				if ( 0 === $oldest || $timestamp < $oldest ) {
					$oldest = $timestamp;
				}
			}
		}

		// A stalled scheduler is a security problem, not a performance one:
		// update checks, vulnerability scans and backups all sit in cron.
		if ( $overdue > 0 && $oldest > 0 && ( $now - $oldest ) > 6 * HOUR_IN_SECONDS ) {
			$issues[] = sprintf(
				/* translators: 1: number of overdue events, 2: human readable time difference. */
				_n(
					'%1$d scheduled event is overdue by %2$s',
					'%1$d scheduled events are overdue, the oldest by %2$s',
					$overdue,
					'security-check-report'
				),
				$overdue,
				human_time_diff( $oldest, $now )
			);

			$summary[] = sprintf(
				/* translators: 1: number of overdue events, 2: human readable time difference. */
				_n(
					'%1$d scheduled event is overdue by %2$s.',
					'%1$d scheduled events are overdue, the oldest by %2$s.',
					$overdue,
					'security-check-report'
				),
				$overdue,
				human_time_diff( $oldest, $now )
			);

			$score = $disabled ? 8 : 6;
		}

		if ( defined( 'ALTERNATE_WP_CRON' ) && ALTERNATE_WP_CRON ) {
			$summary[] = __( 'ALTERNATE_WP_CRON is enabled.', 'security-check-report' );
			$issues[]  = __( 'ALTERNATE_WP_CRON is enabled: it schedules through a redirect that carries doing_wp_cron in the address, which defeats page caching for that request and leaves the parameter in access logs and in referrers sent to other sites', 'security-check-report' );
			$score     = max( $score, 4 );
		}

		$orphaned = self::orphaned_cron_hooks( $crons );

		if ( ! empty( $orphaned ) ) {
			foreach ( $orphaned as $hook ) {
				$issues[] = sprintf(
					/* translators: %s: name of a scheduled hook with no listener in this request. */
					__( 'scheduled hook with no listener registered in this request: %s', 'security-check-report' ),
					$hook
				);
			}

			$summary[] = sprintf(
				/* translators: %d: number of scheduled hooks with no listener. */
				_n(
					'%d scheduled hook has no listener in this request.',
					'%d scheduled hooks have no listener in this request.',
					count( $orphaned ),
					'security-check-report'
				),
				count( $orphaned )
			);

			// Usually a leftover from a removed plugin, occasionally something
			// that was planted. Worth a look, not worth an alarm.
			$score = max( $score, 5 );
		}

		if ( empty( $issues ) ) {
			return CASCR_Result::pass(
				$disabled
					? __( 'WP-Cron is handled by a server cron job and nothing is overdue.', 'security-check-report' )
					: __( 'WP-Cron runs on page loads and nothing is overdue.', 'security-check-report' )
			);
		}

		$fix = $disabled && $overdue > 0
			? __( 'DISABLE_WP_CRON is set but nothing is triggering wp-cron.php. Set up a server cron job, or remove the constant.', 'security-check-report' )
			: __( 'WordPress ships no screen for scheduled events. List them with wp cron event list on the command line, or install a scheduler plugin to see them in the dashboard.', 'security-check-report' );

		// Naming what was found, because the list of events is only visible
		// once the row is opened and the exports carry this sentence alone.
		$found = implode( ' ', $summary );

		return $score >= CASCR_Result::THRESHOLD_FAIL
			? CASCR_Result::fail( $found, $score, $issues, $fix )
			: CASCR_Result::warn( $found, max( $score, 4 ), $issues, $fix );
	}

	/**
	 * How much data is loaded on every single request?
	 *
	 * @return array
	 */
	public static function autoload_options_size() {
		$options = wp_load_alloptions();

		if ( ! is_array( $options ) ) {
			return CASCR_Result::inconclusive( __( 'The autoloaded options could not be read.', 'security-check-report' ) );
		}

		$total   = 0;
		$largest = array();

		foreach ( $options as $name => $value ) {
			$length           = strlen( (string) $value );
			$total           += $length;
			$largest[ $name ] = $length;
		}

		arsort( $largest );
		$largest = array_slice( $largest, 0, 5, true );

		$items = array();
		foreach ( $largest as $name => $length ) {
			$items[] = sprintf(
				/* translators: 1: option name, 2: human readable size. */
				__( '%1$s (%2$s)', 'security-check-report' ),
				$name,
				size_format( $length )
			);
		}

		if ( $total < 800 * KB_IN_BYTES ) {
			return CASCR_Result::pass(
				sprintf(
					/* translators: %s: human readable size. */
					__( '%s of options is loaded on every request.', 'security-check-report' ),
					size_format( $total )
				)
			);
		}

		return CASCR_Result::warn(
			sprintf(
				/* translators: %s: human readable size. */
				__( '%s of options is loaded on every request. Bloated autoloaded options are often forgotten logs or planted payloads.', 'security-check-report' ),
				size_format( $total )
			),
			4,
			$items,
			__( 'Look at what the largest entries contain before deleting anything.', 'security-check-report' )
		);
	}

	/**
	 * Do any options carry injected code or scripts from another host?
	 *
	 * Search engine spam is written into the options table far more often than
	 * into files, because it survives a plugin reinstall.
	 *
	 * Code fragments and foreign script tags are kept apart on purpose. A
	 * fragment of PHP in an option has no legitimate reason to be there; a
	 * script tag usually belongs to an analytics or consent tool and only
	 * deserves a look, not an alarm.
	 *
	 * @return array
	 */
	public static function suspicious_options() {
		$code    = array();
		$scripts = array();

		$site = wp_parse_url( home_url(), PHP_URL_HOST );

		$options = wp_load_alloptions();

		if ( is_array( $options ) ) {
			foreach ( $options as $name => $value ) {
				$value = (string) $value;

				if ( strlen( $value ) > 200000 ) {
					continue;
				}

				foreach ( array( 'base64_decode(', 'eval(', 'gzinflate(', 'str_rot13(' ) as $needle ) {
					if ( false !== strpos( $value, $needle ) ) {
						$code[] = sprintf(
							/* translators: 1: option name, 2: the suspicious code fragment. */
							__( 'option %1$s contains %2$s', 'security-check-report' ),
							$name,
							$needle
						);
						break;
					}
				}

				if ( preg_match_all( '#<script[^>]+src=["\']?(https?:)?//([^"\'/\s>]+)#i', $value, $matches ) ) {
					foreach ( $matches[2] as $host ) {
						if ( $host !== $site ) {
							$scripts[] = sprintf(
								/* translators: 1: option name, 2: external host name. */
								__( 'option %1$s loads a script from %2$s', 'security-check-report' ),
								$name,
								$host
							);
						}
					}
				}
			}
		}

		$code    = array_values( array_unique( $code ) );
		$scripts = array_values( array_unique( $scripts ) );

		if ( ! empty( $code ) ) {
			return CASCR_Result::fail(
				sprintf(
					/* translators: %d: number of option entries containing code fragments. */
					_n(
						'%d option entry contains a code fragment.',
						'%d option entries contain code fragments.',
						count( $code ),
						'security-check-report'
					),
					count( $code )
				),
				9,
				self::cap( array_merge( $code, $scripts ) ),
				__( 'Look at each entry before removing it. An option that stores PHP is worth tracing back to the plugin that wrote it.', 'security-check-report' )
			);
		}

		if ( ! empty( $scripts ) ) {
			return CASCR_Result::warn(
				sprintf(
					/* translators: %d: number of option entries loading a script from another host. */
					_n(
						'%d option entry loads a script from another host.',
						'%d option entries load a script from another host.',
						count( $scripts ),
						'security-check-report'
					),
					count( $scripts )
				),
				4,
				self::cap( $scripts ),
				__( 'Analytics and consent tools store script tags this way on purpose. Go through the list once and check that every host is one you chose.', 'security-check-report' )
			);
		}

		return CASCR_Result::pass( __( 'No option contains a code fragment or loads a script from another host.', 'security-check-report' ) );
	}

	/**
	 * Is anything taking backups?
	 *
	 * @return array
	 */
	public static function backup() {
		$active = self::active_from_list( 'backup_plugins' );

		if ( ! empty( $active ) ) {
			return CASCR_Result::pass(
				__( 'A backup plugin is active.', 'security-check-report' ),
				$active
			);
		}

		return CASCR_Result::warn(
			__( 'No backup plugin was detected. Recovery from a compromise depends on having one.', 'security-check-report' ),
			6,
			array(),
			__( 'A backup taken by the host also counts. This check can only see plugins.', 'security-check-report' )
		);
	}

	/**
	 * Which security plugins are active? Informational only.
	 *
	 * @return array
	 */
	public static function security_plugins() {
		$active = self::active_from_list( 'security_plugins' );

		if ( empty( $active ) ) {
			return CASCR_Result::info( __( 'No security plugin from the known list is active.', 'security-check-report' ) );
		}

		return CASCR_Result::info(
			sprintf(
				/* translators: %d: number of active security plugins. */
				_n( '%d security plugin is active.', '%d security plugins are active.', count( $active ), 'security-check-report' ),
				count( $active )
			),
			$active
		);
	}

	/**
	 * Is anything slowing down repeated login attempts?
	 *
	 * @return array
	 */
	public static function brute_force() {
		$active = array_values(
			array_unique(
				array_merge(
					self::active_from_list( 'brute_force_plugins' ),
					self::active_from_list( 'login_protection_plugins' )
				)
			)
		);

		if ( ! empty( $active ) ) {
			return CASCR_Result::pass(
				__( 'Repeated login attempts are being limited.', 'security-check-report' ),
				$active
			);
		}

		// A limit in the web server, in a firewall or at a reverse proxy is
		// invisible from inside WordPress, so this says what was looked at
		// rather than claiming there is no limit anywhere.
		return CASCR_Result::fail(
			__( 'No plugin that limits repeated login attempts is active. This check can only see plugins, so a limit in the web server or in front of the site does not show up here.', 'security-check-report' ),
			8,
			array(),
			__( 'Install a login limiter, or rate limit wp-login.php and the XML-RPC endpoint at the server. If a limit is already in place outside WordPress, mute this check.', 'security-check-report' )
		);
	}

	/**
	 * Is anything enforcing password quality?
	 *
	 * @return array
	 */
	public static function password_policy() {
		$active = self::active_from_list( 'password_plugins' );

		if ( ! empty( $active ) ) {
			return CASCR_Result::pass(
				__( 'A password policy is enforced.', 'security-check-report' ),
				$active
			);
		}

		return CASCR_Result::warn(
			__( 'No password policy plugin is active. This check can only see plugins, so a rule enforced in a theme, in an identity provider or by a hosting platform does not show up here. On its own, WordPress warns about weak passwords and then accepts them.', 'security-check-report' ),
			5,
			array(),
			__( 'Enforce a minimum strength for accounts that can publish or administer. If that already happens outside WordPress, mute this check.', 'security-check-report' )
		);
	}

	/**
	 * Scheduled hooks that nothing listens to in this request.
	 *
	 * Replaces the previous heuristic, which flagged any hook name made of
	 * eight to twelve lowercase letters and therefore caught legitimate ones.
	 *
	 * has_action() only knows the callbacks registered for the request that is
	 * running, so a plugin that hooks up in the front end alone shows up here
	 * during an admin run. The item text says so rather than claiming the code
	 * is gone.
	 *
	 * @param array $crons Output of _get_cron_array().
	 * @return string[]
	 */
	private static function orphaned_cron_hooks( $crons ) {
		if ( ! is_array( $crons ) ) {
			return array();
		}

		$core = array(
			'wp_version_check',
			'wp_update_plugins',
			'wp_update_themes',
			'wp_scheduled_delete',
			'wp_scheduled_auto_draft_delete',
			'delete_expired_transients',
			'wp_privacy_delete_old_export_files',
			'recovery_mode_clean_expired_keys',
			'wp_site_health_scheduled_check',
			'wp_https_detection',
			'wp_delete_temp_updater_backups',
			'do_pings',
			'publish_future_post',
			'importer_scheduled_cleanup',
			'upgrader_scheduled_cleanup',
		);

		$orphaned = array();

		foreach ( $crons as $hooks ) {
			if ( ! is_array( $hooks ) ) {
				continue;
			}

			foreach ( array_keys( $hooks ) as $hook ) {
				if ( in_array( $hook, $core, true ) || has_action( $hook ) ) {
					continue;
				}

				$orphaned[] = $hook;
			}
		}

		return array_slice( array_values( array_unique( $orphaned ) ), 0, 10 );
	}

	/**
	 * The address a file would be served under, empty when it is out of reach.
	 *
	 * A log at a path of its own used to be reported without ever being looked
	 * at, which said the same thing about a path above the web root as about
	 * one sitting next to the uploads. Only the second of those is a finding,
	 * and which one it is can be answered here.
	 *
	 * Protected rather than private because WP_DEBUG_LOG is a constant core
	 * always defines, so the test suite cannot reach this through the check.
	 *
	 * @param string $path File path.
	 * @return string Empty when the file is below neither the content directory nor the web root.
	 */
	protected static function served_url( $path ) {
		$path = self::canonical( $path );

		// The content directory is tried first: it is the more specific of the
		// two and is allowed to sit outside ABSPATH entirely.
		$content = trailingslashit( self::canonical( WP_CONTENT_DIR ) );

		if ( 0 === strpos( $path, $content ) ) {
			return content_url( '/' . substr( $path, strlen( $content ) ) );
		}

		$root = trailingslashit( self::canonical( ABSPATH ) );

		if ( 0 === strpos( $path, $root ) ) {
			return site_url( '/' . substr( $path, strlen( $root ) ) );
		}

		return '';
	}

	/**
	 * A path in the one spelling two of them can be compared in.
	 *
	 * WP_DEBUG_LOG is handed to the error log of PHP unchanged, so it may be
	 * relative, may contain a symlink and may walk back up through the tree.
	 * Any of those would otherwise read as a path outside the web root.
	 *
	 * @param string $path File or directory path.
	 * @return string
	 */
	private static function canonical( $path ) {
		$real = realpath( $path );

		return wp_normalize_path( false !== $real ? $real : $path );
	}
}
