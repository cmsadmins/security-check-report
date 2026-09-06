<?php
/**
 * Checks for WordPress core, PHP, plugins and themes.
 *
 * @package CmsAdmins\SecurityCheck
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Core, runtime and extension checks.
 */
class CASCR_Checks_Core extends CASCR_Checks_Base {

	/**
	 * End of security support per PHP branch.
	 *
	 * Dates instead of a hardcoded minimum, so the check keeps telling the
	 * truth as branches age out without anyone editing the comparison.
	 *
	 * @var array<string, string>
	 */
	private static $php_eol = array(
		'7.0' => '2019-01-10',
		'7.1' => '2019-12-01',
		'7.2' => '2020-11-30',
		'7.3' => '2021-12-06',
		'7.4' => '2022-11-28',
		'8.0' => '2023-11-26',
		'8.1' => '2025-12-31',
		'8.2' => '2026-12-31',
		'8.3' => '2027-12-31',
		'8.4' => '2028-12-31',
		'8.5' => '2029-12-31',
	);

	/**
	 * End of active (bug fix) support per PHP branch.
	 *
	 * @var array<string, string>
	 */
	private static $php_active = array(
		'8.1' => '2023-11-25',
		'8.2' => '2024-12-08',
		'8.3' => '2025-12-31',
		'8.4' => '2026-12-31',
		'8.5' => '2027-12-31',
	);

	/**
	 * Memoised core checksums.
	 *
	 * @var array|false|null
	 */
	private static $checksums = null;

	/**
	 * Is WordPress itself up to date?
	 *
	 * @return array
	 */
	public static function wordpress_version() {
		global $wp_version;

		require_once ABSPATH . 'wp-admin/includes/update.php';

		$updates = get_core_updates( array( 'dismissed' => false ) );

		if ( ! is_array( $updates ) || empty( $updates ) ) {
			return CASCR_Result::inconclusive(
				__( 'The latest WordPress version could not be determined.', 'security-check-report' ),
				__( 'Check that the site can reach api.wordpress.org.', 'security-check-report' )
			);
		}

		$latest = '';
		foreach ( $updates as $update ) {
			if ( isset( $update->response ) && 'upgrade' === $update->response && isset( $update->current ) ) {
				$latest = $update->current;
				break;
			}
		}

		if ( '' === $latest ) {
			return CASCR_Result::pass(
				sprintf(
					/* translators: %s: WordPress version number. */
					__( 'WordPress %s is up to date.', 'security-check-report' ),
					$wp_version
				)
			);
		}

		return CASCR_Result::fail(
			sprintf(
				/* translators: 1: installed WordPress version, 2: latest available version. */
				__( 'WordPress %1$s is outdated, %2$s is available.', 'security-check-report' ),
				$wp_version,
				$latest
			),
			10,
			array(),
			__( 'Install the update from Dashboard, Updates. Take a backup first.', 'security-check-report' )
		);
	}

	/**
	 * Is the PHP branch still receiving security fixes?
	 *
	 * @return array
	 */
	public static function php_version() {
		$version = phpversion();
		$parts   = explode( '.', $version );
		$branch  = isset( $parts[1] ) ? $parts[0] . '.' . $parts[1] : $version;
		$now     = time();

		if ( ! isset( self::$php_eol[ $branch ] ) ) {
			// A branch newer than anything this release knows about.
			return CASCR_Result::pass(
				sprintf(
					/* translators: %s: PHP version number. */
					__( 'PHP %s is in use.', 'security-check-report' ),
					$version
				)
			);
		}

		$eol = strtotime( self::$php_eol[ $branch ] . ' 23:59:59' );

		if ( $now > $eol ) {
			return CASCR_Result::fail(
				sprintf(
					/* translators: 1: PHP version number, 2: end of support date. */
					__( 'PHP %1$s stopped receiving security fixes on %2$s.', 'security-check-report' ),
					$version,
					date_i18n( get_option( 'date_format' ), $eol )
				),
				9,
				array(),
				__( 'Ask your host to move the site to a supported PHP branch. Test on a staging copy first.', 'security-check-report' )
			);
		}

		if ( $eol - $now < 6 * MONTH_IN_SECONDS ) {
			return CASCR_Result::warn(
				sprintf(
					/* translators: 1: PHP version number, 2: end of support date. */
					__( 'PHP %1$s reaches end of security support on %2$s.', 'security-check-report' ),
					$version,
					date_i18n( get_option( 'date_format' ), $eol )
				),
				5,
				array(),
				__( 'Plan the upgrade to a newer PHP branch before that date.', 'security-check-report' )
			);
		}

		if ( isset( self::$php_active[ $branch ] ) && $now > strtotime( self::$php_active[ $branch ] . ' 23:59:59' ) ) {
			return CASCR_Result::warn(
				sprintf(
					/* translators: 1: PHP version number, 2: end of support date. */
					__( 'PHP %1$s only receives security fixes, no more bug fixes. Support ends on %2$s.', 'security-check-report' ),
					$version,
					date_i18n( get_option( 'date_format' ), $eol )
				),
				4
			);
		}

		return CASCR_Result::pass(
			sprintf(
				/* translators: %s: PHP version number. */
				__( 'PHP %s is fully supported.', 'security-check-report' ),
				$version
			)
		);
	}

	/**
	 * Are automatic core updates enabled?
	 *
	 * @return array
	 */
	public static function automatic_core_updates() {
		$setting = defined( 'WP_AUTO_UPDATE_CORE' ) ? WP_AUTO_UPDATE_CORE : 'minor';

		// true means every core update, which is more coverage than 'minor',
		// not less. The previous version reported it as a risk.
		if ( true === $setting ) {
			return CASCR_Result::pass( __( 'All automatic core updates are enabled.', 'security-check-report' ) );
		}

		if ( 'minor' === $setting ) {
			return CASCR_Result::pass( __( 'Automatic minor and security updates are enabled.', 'security-check-report' ) );
		}

		if ( in_array( $setting, array( 'beta', 'rc', 'development' ), true ) ) {
			return CASCR_Result::warn(
				__( 'This installation receives pre-release core updates.', 'security-check-report' ),
				5,
				array( (string) $setting ),
				__( 'Set WP_AUTO_UPDATE_CORE to minor on production sites.', 'security-check-report' )
			);
		}

		return CASCR_Result::fail(
			__( 'Automatic core updates are switched off, so security releases are not installed on their own.', 'security-check-report' ),
			8,
			array(),
			__( 'Remove the WP_AUTO_UPDATE_CORE constant from wp-config.php or set it to minor.', 'security-check-report' )
		);
	}

	/**
	 * Do the core files still match the official checksums?
	 *
	 * @return array
	 */
	public static function core_file_integrity() {
		$checksums = self::checksums();

		if ( empty( $checksums ) ) {
			return CASCR_Result::inconclusive(
				__( 'No official checksums are available for this WordPress version.', 'security-check-report' ),
				__( 'Checksums are only published for release builds. Nightly or patched builds cannot be verified.', 'security-check-report' )
			);
		}

		$modified = array();
		$missing  = array();
		$checked  = 0;

		foreach ( $checksums as $file => $checksum ) {
			if ( 0 === strpos( $file, 'wp-content/' ) ) {
				continue;
			}

			$path = ABSPATH . $file;

			if ( ! file_exists( $path ) ) {
				if ( 0 === strpos( $file, 'wp-admin/' ) || 0 === strpos( $file, 'wp-includes/' ) ) {
					$missing[] = $file;
				}
				continue;
			}

			++$checked;

			if ( md5_file( $path ) !== $checksum ) {
				$modified[] = $file;
			}
		}

		if ( empty( $modified ) && empty( $missing ) ) {
			return CASCR_Result::pass(
				sprintf(
					/* translators: %d: number of files verified. */
					_n(
						'The %d core file matches the official checksums.',
						'All %d core files match the official checksums.',
						$checked,
						'security-check-report'
					),
					$checked
				)
			);
		}

		$items = array();
		foreach ( $modified as $file ) {
			/* translators: %s: file path relative to the WordPress root. */
			$items[] = sprintf( __( 'modified: %s', 'security-check-report' ), $file );
		}
		foreach ( $missing as $file ) {
			/* translators: %s: file path relative to the WordPress root. */
			$items[] = sprintf( __( 'missing: %s', 'security-check-report' ), $file );
		}

		$total = count( $modified ) + count( $missing );
		$score = count( $modified ) > 5 ? 9 : min( 9, 5 + $total );

		return CASCR_Result::fail(
			sprintf(
				/* translators: %d: number of core files that differ from the official release. */
				_n(
					'%d core file differs from the official release.',
					'%d core files differ from the official release.',
					$total,
					'security-check-report'
				),
				$total
			),
			$score,
			self::cap( $items ),
			__( 'Reinstall WordPress from Dashboard, Updates, Reinstall. If files keep changing, treat the site as compromised.', 'security-check-report' )
		);
	}

	/**
	 * Are there files in the core directories that do not belong to WordPress?
	 *
	 * This replaces the old signature scan, which looked for strings such as
	 * eval( and $_GET[ in exactly the two directories where core lives, and
	 * needed a hand maintained allow list of core files to stay quiet. Comparing
	 * against the official file list finds the same thing without the list.
	 *
	 * @return array
	 */
	public static function unknown_core_files() {
		$checksums = self::checksums();

		if ( empty( $checksums ) ) {
			return CASCR_Result::inconclusive(
				__( 'No official file list is available for this WordPress version.', 'security-check-report' )
			);
		}

		$known   = array_fill_keys( array_keys( $checksums ), true );
		$unknown = array();
		$scanned = 0;
		$limit   = 8000;

		foreach ( array( 'wp-admin', 'wp-includes' ) as $dir ) {
			$root = ABSPATH . $dir;

			if ( ! is_dir( $root ) ) {
				continue;
			}

			try {
				$iterator = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $root, RecursiveDirectoryIterator::SKIP_DOTS )
				);

				foreach ( $iterator as $file ) {
					if ( $scanned >= $limit ) {
						break 2;
					}

					if ( ! $file->isFile() ) {
						continue;
					}

					++$scanned;

					$extension = strtolower( $file->getExtension() );
					if ( ! in_array( $extension, array( 'php', 'phtml', 'phar', 'inc' ), true ) ) {
						continue;
					}

					$relative = self::relative( $file->getPathname() );

					if ( ! isset( $known[ $relative ] ) ) {
						$unknown[] = $relative;
					}
				}
			} catch ( Exception $e ) {
				return CASCR_Result::inconclusive(
					__( 'The core directories could not be read completely.', 'security-check-report' )
				);
			}
		}

		if ( empty( $unknown ) ) {
			return CASCR_Result::pass(
				__( 'The core directories contain no files beyond the official release.', 'security-check-report' )
			);
		}

		return CASCR_Result::fail(
			sprintf(
				/* translators: %d: number of unexpected executable files. */
				_n(
					'%d executable file in the core directories is not part of WordPress.',
					'%d executable files in the core directories are not part of WordPress.',
					count( $unknown ),
					'security-check-report'
				),
				count( $unknown )
			),
			9,
			self::cap( $unknown ),
			__( 'Inspect each file. Nothing but WordPress itself belongs in wp-admin or wp-includes.', 'security-check-report' )
		);
	}

	/**
	 * Do any active plugins have an update waiting?
	 *
	 * @return array
	 */
	public static function outdated_plugins() {
		self::load_plugin_api();

		$updates = self::plugin_updates();

		if ( null === $updates ) {
			return CASCR_Result::inconclusive(
				__( 'Plugin update information is not available.', 'security-check-report' )
			);
		}

		$outdated = array();

		foreach ( $updates as $file => $update ) {
			if ( ! is_plugin_active( $file ) ) {
				continue;
			}

			$data = file_exists( WP_PLUGIN_DIR . '/' . $file )
				? get_plugin_data( WP_PLUGIN_DIR . '/' . $file, false, false )
				: array();

			$outdated[] = sprintf(
				/* translators: 1: plugin name, 2: installed version, 3: available version. */
				__( '%1$s (%2$s to %3$s)', 'security-check-report' ),
				! empty( $data['Name'] ) ? $data['Name'] : $file,
				! empty( $data['Version'] ) ? $data['Version'] : '?',
				isset( $update->new_version ) ? $update->new_version : '?'
			);
		}

		if ( empty( $outdated ) ) {
			return CASCR_Result::pass( __( 'All active plugins are up to date.', 'security-check-report' ) );
		}

		return CASCR_Result::fail(
			sprintf(
				/* translators: %d: number of active plugins with a pending update. */
				_n(
					'%d active plugin has an update waiting.',
					'%d active plugins have updates waiting.',
					count( $outdated ),
					'security-check-report'
				),
				count( $outdated )
			),
			8,
			self::cap( $outdated ),
			__( 'Install the updates from Dashboard, Updates.', 'security-check-report' )
		);
	}

	/**
	 * Do any themes have an update waiting?
	 *
	 * @return array
	 */
	public static function outdated_themes() {
		$transient = get_site_transient( 'update_themes' );

		if ( ! is_object( $transient ) ) {
			wp_update_themes();
			$transient = get_site_transient( 'update_themes' );
		}

		if ( ! is_object( $transient ) || ! isset( $transient->response ) ) {
			return CASCR_Result::inconclusive(
				__( 'Theme update information is not available.', 'security-check-report' )
			);
		}

		$outdated = array();
		$themes   = wp_get_themes();

		foreach ( $transient->response as $stylesheet => $update ) {
			$name = isset( $themes[ $stylesheet ] ) ? $themes[ $stylesheet ]->get( 'Name' ) : $stylesheet;

			$outdated[] = sprintf(
				/* translators: 1: theme name, 2: available version. */
				__( '%1$s (update to %2$s)', 'security-check-report' ),
				$name,
				isset( $update['new_version'] ) ? $update['new_version'] : '?'
			);
		}

		if ( empty( $outdated ) ) {
			return CASCR_Result::pass( __( 'All themes are up to date.', 'security-check-report' ) );
		}

		return CASCR_Result::fail(
			sprintf(
				/* translators: %d: number of themes with a pending update. */
				_n(
					'%d theme has an update waiting.',
					'%d themes have updates waiting.',
					count( $outdated ),
					'security-check-report'
				),
				count( $outdated )
			),
			7,
			self::cap( $outdated ),
			__( 'Install the updates from Dashboard, Updates.', 'security-check-report' )
		);
	}

	/**
	 * Inactive plugins and unused themes still ship code that can be reached.
	 *
	 * @return array
	 */
	public static function plugin_hygiene() {
		self::load_plugin_api();

		$inactive_plugins = array();
		foreach ( get_plugins() as $file => $data ) {
			if ( ! is_plugin_active( $file ) ) {
				$inactive_plugins[] = ! empty( $data['Name'] ) ? $data['Name'] : $file;
			}
		}

		$current       = get_stylesheet();
		$parent        = get_template();
		$unused_themes = array();
		foreach ( wp_get_themes() as $stylesheet => $theme ) {
			if ( $stylesheet !== $current && $stylesheet !== $parent ) {
				$unused_themes[] = $theme->get( 'Name' );
			}
		}

		$total = count( $inactive_plugins ) + count( $unused_themes );

		if ( 0 === $total ) {
			return CASCR_Result::pass( __( 'No inactive plugins or unused themes are installed.', 'security-check-report' ) );
		}

		$items = array();
		foreach ( $inactive_plugins as $name ) {
			/* translators: %s: plugin name. */
			$items[] = sprintf( __( 'inactive plugin: %s', 'security-check-report' ), $name );
		}
		foreach ( $unused_themes as $name ) {
			/* translators: %s: theme name. */
			$items[] = sprintf( __( 'unused theme: %s', 'security-check-report' ), $name );
		}

		return CASCR_Result::warn(
			sprintf(
				/* translators: %d: number of inactive plugins and unused themes. */
				_n(
					'%d inactive plugin or unused theme is installed.',
					'%d inactive plugins or unused themes are installed.',
					$total,
					'security-check-report'
				),
				$total
			),
			5,
			self::cap( $items ),
			__( 'Delete what is not needed. Deactivated code still sits on disk and stops receiving attention.', 'security-check-report' )
		);
	}

	/**
	 * Plugins that look abandoned by their author.
	 *
	 * The previous version treated any plugin whose files had not changed in six
	 * months as outdated, which flagged well maintained, stable plugins. What
	 * matters is what the directory says about the plugin, not its file dates.
	 *
	 * @return array
	 */
	public static function plugin_abandonment() {
		self::load_plugin_api();

		$findings = array();
		$checked  = 0;

		foreach ( get_plugins() as $file => $data ) {
			if ( ! is_plugin_active( $file ) ) {
				continue;
			}

			$info = self::directory_info( $file );

			if ( null === $info || is_wp_error( $info ) ) {
				continue;
			}

			++$checked;

			$reasons = array();
			$age     = ! empty( $info->last_updated ) ? time() - strtotime( $info->last_updated ) : 0;

			if ( $age > 2 * YEAR_IN_SECONDS ) {
				$reasons[] = __( 'no release in over two years', 'security-check-report' );
			} elseif ( $age > YEAR_IN_SECONDS ) {
				$reasons[] = __( 'no release in over a year', 'security-check-report' );
			}

			// A plugin lagging one WordPress branch behind is normal in the
			// weeks after a release. Only worth mentioning once the plugin has
			// also gone quiet, otherwise this fires for nearly every plugin
			// every six months.
			if ( ! empty( $reasons ) && ! empty( $info->tested ) && version_compare( $info->tested, self::wp_branch(), '<' ) ) {
				$reasons[] = sprintf(
					/* translators: %s: WordPress version the plugin was last tested against. */
					__( 'last tested against WordPress %s', 'security-check-report' ),
					$info->tested
				);
			}

			if ( ! empty( $reasons ) ) {
				$findings[] = sprintf(
					/* translators: 1: plugin name, 2: comma separated list of reasons. */
					__( '%1$s: %2$s', 'security-check-report' ),
					! empty( $data['Name'] ) ? $data['Name'] : $file,
					implode( ', ', $reasons )
				);
			}
		}

		if ( 0 === $checked ) {
			return CASCR_Result::inconclusive(
				__( 'No plugin information could be retrieved from the directory.', 'security-check-report' )
			);
		}

		if ( empty( $findings ) ) {
			return CASCR_Result::pass( __( 'Every active plugin from the directory is actively maintained.', 'security-check-report' ) );
		}

		return CASCR_Result::warn(
			sprintf(
				/* translators: %d: number of plugins that look abandoned. */
				_n(
					'%d active plugin looks abandoned.',
					'%d active plugins look abandoned.',
					count( $findings ),
					'security-check-report'
				),
				count( $findings )
			),
			6,
			self::cap( $findings ),
			__( 'Look for a maintained alternative. Abandoned plugins do not get security fixes.', 'security-check-report' )
		);
	}

	/**
	 * Plugins that were pulled from the WordPress directory.
	 *
	 * A closed listing usually means an unfixed security problem, which is why
	 * this weighs heavier than a plugin that merely has a known vulnerability.
	 *
	 * @return array
	 */
	public static function plugin_removed_from_repo() {
		self::load_plugin_api();

		$closed  = array();
		$checked = 0;

		foreach ( get_plugins() as $file => $data ) {
			if ( ! is_plugin_active( $file ) ) {
				continue;
			}

			$info = self::directory_info( $file );

			if ( null === $info || is_wp_error( $info ) ) {
				continue;
			}

			++$checked;

			if ( ! empty( $info->closed ) ) {
				$closed[] = ! empty( $data['Name'] ) ? $data['Name'] : $file;
			}
		}

		if ( 0 === $checked ) {
			return CASCR_Result::inconclusive(
				__( 'No plugin information could be retrieved from the directory.', 'security-check-report' )
			);
		}

		if ( empty( $closed ) ) {
			return CASCR_Result::pass( __( 'No active plugin has been removed from the directory.', 'security-check-report' ) );
		}

		return CASCR_Result::fail(
			sprintf(
				/* translators: %d: number of plugins that were removed from the directory. */
				_n(
					'%d active plugin has been removed from the WordPress directory.',
					'%d active plugins have been removed from the WordPress directory.',
					count( $closed ),
					'security-check-report'
				),
				count( $closed )
			),
			10,
			self::cap( $closed ),
			__( 'Remove the plugin and replace it. A closed listing usually means an unfixed security problem.', 'security-check-report' )
		);
	}

	/**
	 * Did the author behind an installed plugin change?
	 *
	 * Buying an established plugin and pushing a malicious update to its
	 * existing user base has become a common route in. A changed author line is
	 * the earliest signal a site can observe on its own.
	 *
	 * @return array
	 */
	public static function plugin_ownership_change() {
		self::load_plugin_api();

		$current = array();
		foreach ( get_plugins() as $file => $data ) {
			$current[ $file ] = trim( wp_strip_all_tags( isset( $data['Author'] ) ? $data['Author'] : '' ) );
		}

		if ( CASCR_Store::remember( 'plugin_authors', $current ) ) {
			return CASCR_Result::pass(
				__( 'The plugin authors have been recorded. Changes will be reported from the next scan on.', 'security-check-report' )
			);
		}

		$baseline = CASCR_Store::baseline( 'plugin_authors', array() );
		$changed  = array();

		foreach ( $current as $file => $author ) {
			if ( ! isset( $baseline[ $file ] ) || $baseline[ $file ] === $author ) {
				continue;
			}

			$changed[] = sprintf(
				/* translators: 1: plugin file, 2: previous author, 3: current author. */
				__( '%1$s: %2$s became %3$s', 'security-check-report' ),
				$file,
				'' !== $baseline[ $file ] ? $baseline[ $file ] : __( '(none)', 'security-check-report' ),
				'' !== $author ? $author : __( '(none)', 'security-check-report' )
			);
		}

		if ( empty( $changed ) ) {
			return CASCR_Result::pass( __( 'No installed plugin changed its author.', 'security-check-report' ) );
		}

		return CASCR_Result::fail(
			sprintf(
				/* translators: %d: number of plugins whose author changed. */
				_n(
					'%d plugin changed its author.',
					'%d plugins changed their author.',
					count( $changed ),
					'security-check-report'
				),
				count( $changed )
			),
			7,
			self::cap( $changed ),
			__( 'Confirm the handover is legitimate and read the changelog of the release that came with it.', 'security-check-report' )
		);
	}

	/**
	 * Must-use plugins and drop-ins that appeared after the first scan.
	 *
	 * Both load on every request and neither can be deactivated from the
	 * dashboard, which makes them a favourite place to hide persistent code.
	 *
	 * @return array
	 */
	public static function mu_plugins_and_dropins() {
		self::load_plugin_api();

		$present = array();

		foreach ( get_mu_plugins() as $file => $data ) {
			$present[ 'mu:' . $file ] = sprintf(
				/* translators: 1: file name, 2: plugin name. */
				__( 'must-use plugin %1$s (%2$s)', 'security-check-report' ),
				$file,
				! empty( $data['Name'] ) ? $data['Name'] : __( 'no name', 'security-check-report' )
			);
		}

		foreach ( get_dropins() as $file => $data ) {
			$present[ 'dropin:' . $file ] = sprintf(
				/* translators: 1: file name, 2: plugin name. */
				__( 'drop-in %1$s (%2$s)', 'security-check-report' ),
				$file,
				! empty( $data['Name'] ) ? $data['Name'] : __( 'no name', 'security-check-report' )
			);
		}

		$keys = array_keys( $present );
		sort( $keys );

		if ( CASCR_Store::remember( 'mu_and_dropins', $keys ) ) {
			if ( empty( $present ) ) {
				return CASCR_Result::pass( __( 'No must-use plugins or drop-ins are installed.', 'security-check-report' ) );
			}

			return CASCR_Result::info(
				sprintf(
					/* translators: %d: number of must-use plugins and drop-ins. */
					_n(
						'%d must-use plugin or drop-in is installed and has been recorded.',
						'%d must-use plugins or drop-ins are installed and have been recorded.',
						count( $present ),
						'security-check-report'
					),
					count( $present )
				),
				array_values( $present )
			);
		}

		$baseline = CASCR_Store::baseline( 'mu_and_dropins', array() );
		$added    = array_diff( $keys, $baseline );

		if ( empty( $added ) ) {
			if ( empty( $present ) ) {
				return CASCR_Result::pass( __( 'No must-use plugins or drop-ins are installed.', 'security-check-report' ) );
			}

			return CASCR_Result::info(
				sprintf(
					/* translators: %d: number of must-use plugins and drop-ins. */
					_n(
						'%d known must-use plugin or drop-in is installed.',
						'%d known must-use plugins or drop-ins are installed.',
						count( $present ),
						'security-check-report'
					),
					count( $present )
				),
				array_values( $present )
			);
		}

		$items = array();
		foreach ( $added as $key ) {
			$items[] = $present[ $key ];
		}

		return CASCR_Result::fail(
			sprintf(
				/* translators: %d: number of newly appeared must-use plugins or drop-ins. */
				_n(
					'%d must-use plugin or drop-in appeared since the first scan.',
					'%d must-use plugins or drop-ins appeared since the first scan.',
					count( $added ),
					'security-check-report'
				),
				count( $added )
			),
			8,
			self::cap( $items ),
			__( 'Open each file. This code runs on every request and cannot be switched off from the dashboard.', 'security-check-report' )
		);
	}

	/**
	 * Other WordPress installations sharing the same account.
	 *
	 * @return array
	 */
	public static function other_wp_installs() {
		$parent  = dirname( ABSPATH );
		$current = realpath( ABSPATH );

		if ( ! is_dir( $parent ) || ! is_readable( $parent ) ) {
			return CASCR_Result::inconclusive(
				__( 'The parent directory could not be read.', 'security-check-report' )
			);
		}

		$installs = array();
		$visited  = 0;

		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $parent, RecursiveDirectoryIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::SELF_FIRST
			);
			$iterator->setMaxDepth( 2 );

			foreach ( $iterator as $file ) {
				if ( ++$visited > 20000 ) {
					break;
				}

				if ( ! $file->isFile() || 'wp-config.php' !== $file->getFilename() ) {
					continue;
				}

				$path = realpath( dirname( $file->getPathname() ) );
				if ( $path && $path !== $current ) {
					$installs[] = $path;
				}
			}
		} catch ( Exception $e ) {
			return CASCR_Result::inconclusive(
				__( 'The scan for other installations could not be completed.', 'security-check-report' )
			);
		}

		if ( empty( $installs ) ) {
			return CASCR_Result::pass( __( 'No other WordPress installation was found next to this one.', 'security-check-report' ) );
		}

		return CASCR_Result::warn(
			sprintf(
				/* translators: %d: number of other WordPress installations found. */
				_n(
					'%d other WordPress installation shares this hosting account.',
					'%d other WordPress installations share this hosting account.',
					count( $installs ),
					'security-check-report'
				),
				count( $installs )
			),
			min( 6, 2 + count( $installs ) ),
			self::cap( $installs ),
			__( 'Keep every installation updated. A neglected one next door is an entry point into this one.', 'security-check-report' )
		);
	}

	/**
	 * Official checksums for the running WordPress build.
	 *
	 * @return array
	 */
	private static function checksums() {
		if ( null !== self::$checksums ) {
			return is_array( self::$checksums ) ? self::$checksums : array();
		}

		global $wp_version;

		require_once ABSPATH . 'wp-admin/includes/update.php';

		$checksums = get_core_checksums( $wp_version, get_locale() );

		if ( ! is_array( $checksums ) || empty( $checksums ) ) {
			$checksums = get_core_checksums( $wp_version, 'en_US' );
		}

		self::$checksums = is_array( $checksums ) ? $checksums : false;

		return is_array( self::$checksums ) ? self::$checksums : array();
	}

	/**
	 * Pending plugin updates, keyed by plugin file.
	 *
	 * Uses the update transient WordPress maintains anyway. The previous
	 * implementation asked the directory about every single plugin, which meant
	 * one outbound request per installed plugin on every scan.
	 *
	 * @return array|null
	 */
	private static function plugin_updates() {
		$transient = get_site_transient( 'update_plugins' );

		if ( ! is_object( $transient ) ) {
			wp_update_plugins();
			$transient = get_site_transient( 'update_plugins' );
		}

		if ( ! is_object( $transient ) || ! isset( $transient->response ) ) {
			return null;
		}

		return (array) $transient->response;
	}

	/**
	 * Directory metadata for a plugin, cached for twelve hours.
	 *
	 * @param string $file Plugin file, for example akismet/akismet.php.
	 * @return object|WP_Error|null Null when the plugin has no directory slug.
	 */
	private static function directory_info( $file ) {
		$slug = dirname( $file );

		if ( '.' === $slug || '' === $slug ) {
			return null;
		}

		$cache_key = 'cascr_plugin_' . md5( $slug );
		$cached    = get_transient( $cache_key );

		if ( false !== $cached ) {
			return 'none' === $cached ? new WP_Error( 'cascr_not_listed' ) : (object) $cached;
		}

		require_once ABSPATH . 'wp-admin/includes/plugin-install.php';

		$info = plugins_api(
			'plugin_information',
			array(
				'slug'   => $slug,
				'fields' => array(
					'sections'          => false,
					'short_description' => false,
					'screenshots'       => false,
					'ratings'           => false,
					'contributors'      => false,
					'banners'           => false,
					'icons'             => false,
					'last_updated'      => true,
					'tested'            => true,
					'active_installs'   => true,
				),
			)
		);

		if ( is_wp_error( $info ) ) {
			set_transient( $cache_key, 'none', 12 * HOUR_IN_SECONDS );

			return $info;
		}

		$slim = array(
			'slug'            => isset( $info->slug ) ? $info->slug : $slug,
			'last_updated'    => isset( $info->last_updated ) ? $info->last_updated : '',
			'tested'          => isset( $info->tested ) ? $info->tested : '',
			'active_installs' => isset( $info->active_installs ) ? $info->active_installs : 0,
			'closed'          => ! empty( $info->closed ),
		);

		set_transient( $cache_key, $slim, 12 * HOUR_IN_SECONDS );

		return (object) $slim;
	}

	/**
	 * The running WordPress version reduced to major.minor.
	 *
	 * @return string
	 */
	private static function wp_branch() {
		global $wp_version;

		$parts = explode( '.', (string) $wp_version );

		return isset( $parts[1] ) ? $parts[0] . '.' . $parts[1] : (string) $wp_version;
	}
}
