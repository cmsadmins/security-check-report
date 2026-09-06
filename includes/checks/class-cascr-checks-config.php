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
		$url = content_url( '/debug.log' );

		if ( defined( 'WP_DEBUG_LOG' ) && is_string( WP_DEBUG_LOG ) && '' !== WP_DEBUG_LOG ) {
			$log = WP_DEBUG_LOG;
			$url = '';
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

		if ( '' === $url ) {
			return CASCR_Result::warn(
				__( 'A debug log exists outside the default location.', 'security-check-report' ),
				4,
				array( $item ),
				__( 'Make sure the file sits outside the web root and delete it once the problem is solved.', 'security-check-report' )
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

		$config = ABSPATH . 'wp-config.php';
		$age    = file_exists( $config ) ? time() - filemtime( $config ) : 0;

		if ( $age > YEAR_IN_SECONDS ) {
			return CASCR_Result::warn(
				__( 'The authentication keys are set correctly but have not been rotated in over a year.', 'security-check-report' ),
				4,
				array(),
				__( 'Rotating the keys invalidates every stored session, which is the fastest way to lock out a stolen cookie.', 'security-check-report' )
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
			// Full rights on every database, or the right to hand out rights,
			// are not.
			if ( preg_match( '/\bALL PRIVILEGES\s+ON\s+\*\.\*/i', $line ) ) {
				$excessive[] = __( 'all privileges on every database', 'security-check-report' );
			}

			if ( false !== stripos( $line, 'WITH GRANT OPTION' ) ) {
				$excessive[] = __( 'may grant privileges to other accounts', 'security-check-report' );
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
					'%1$d scheduled event is overdue, by %2$s',
					'%1$d scheduled events are overdue, the oldest by %2$s',
					$overdue,
					'security-check-report'
				),
				$overdue,
				human_time_diff( $oldest, $now )
			);

			$score = $disabled ? 8 : 6;
		}

		if ( defined( 'ALTERNATE_WP_CRON' ) && ALTERNATE_WP_CRON ) {
			$issues[] = __( 'ALTERNATE_WP_CRON is enabled, which appends scheduling parameters to visitor URLs', 'security-check-report' );
			$score    = max( $score, 4 );
		}

		$orphaned = self::orphaned_cron_hooks( $crons );

		if ( ! empty( $orphaned ) ) {
			foreach ( $orphaned as $hook ) {
				$issues[] = sprintf(
					/* translators: %s: name of a scheduled hook with no code behind it. */
					__( 'scheduled hook with no code behind it: %s', 'security-check-report' ),
					$hook
				);
			}

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
			: __( 'Review the scheduled events under Tools, Site Health, Info.', 'security-check-report' );

		return $score >= CASCR_Result::THRESHOLD_FAIL
			? CASCR_Result::fail( __( 'The scheduler needs attention.', 'security-check-report' ), $score, $issues, $fix )
			: CASCR_Result::warn( __( 'The scheduler needs attention.', 'security-check-report' ), max( $score, 4 ), $issues, $fix );
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
	 * Do any options carry injected markup or foreign addresses?
	 *
	 * Search engine spam is written into the options table far more often than
	 * into files, because it survives a plugin reinstall.
	 *
	 * @return array
	 */
	public static function suspicious_options() {
		$findings = array();

		$site = wp_parse_url( home_url(), PHP_URL_HOST );

		if ( untrailingslashit( get_option( 'siteurl' ) ) !== untrailingslashit( get_option( 'home' ) ) ) {
			$findings[] = sprintf(
				/* translators: 1: siteurl option, 2: home option. */
				__( 'siteurl (%1$s) and home (%2$s) point to different addresses', 'security-check-report' ),
				get_option( 'siteurl' ),
				get_option( 'home' )
			);
		}

		$options = wp_load_alloptions();

		if ( is_array( $options ) ) {
			foreach ( $options as $name => $value ) {
				$value = (string) $value;

				if ( strlen( $value ) > 200000 ) {
					continue;
				}

				foreach ( array( 'base64_decode(', 'eval(', 'gzinflate(', 'str_rot13(' ) as $needle ) {
					if ( false !== strpos( $value, $needle ) ) {
						$findings[] = sprintf(
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
							$findings[] = sprintf(
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

		$findings = array_values( array_unique( $findings ) );

		if ( empty( $findings ) ) {
			return CASCR_Result::pass( __( 'No injected markup or foreign addresses were found in the options.', 'security-check-report' ) );
		}

		return CASCR_Result::fail(
			sprintf(
				/* translators: %d: number of suspicious option entries. */
				_n(
					'%d option entry looks injected.',
					'%d option entries look injected.',
					count( $findings ),
					'security-check-report'
				),
				count( $findings )
			),
			9,
			self::cap( $findings ),
			__( 'Check each entry. Some are legitimate, for instance analytics snippets a plugin stores on purpose.', 'security-check-report' )
		);
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

		return CASCR_Result::fail(
			__( 'Nothing limits repeated login attempts, so passwords can be guessed at full speed.', 'security-check-report' ),
			8,
			array(),
			__( 'Install a login limiter, or rate limit wp-login.php and the XML-RPC endpoint at the server.', 'security-check-report' )
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
			__( 'No password policy is enforced. WordPress warns about weak passwords but still accepts them.', 'security-check-report' ),
			5,
			array(),
			__( 'Enforce a minimum strength for accounts that can publish or administer.', 'security-check-report' )
		);
	}

	/**
	 * Scheduled hooks that no code listens to any more.
	 *
	 * Replaces the previous heuristic, which flagged any hook name made of
	 * eight to twelve lowercase letters and therefore caught legitimate ones.
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
}
