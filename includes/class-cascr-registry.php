<?php
/**
 * The single source of truth for every security check.
 *
 * @package CmsAdmins\SecurityCheck
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Test registry.
 *
 * Identity, label, grouping, urgency, score weight and callback live in one
 * place. Documentation is keyed by the same identifier in config/docs.php, so
 * a test and its description cannot drift apart.
 */
class CASCR_Registry {

	const SEVERITY_CRITICAL = 'critical';
	const SEVERITY_HIGH     = 'high';
	const SEVERITY_MEDIUM   = 'medium';
	const SEVERITY_LOW      = 'low';

	const CATEGORY_CORE    = 'core';
	const CATEGORY_CONFIG  = 'configuration';
	const CATEGORY_FILES   = 'files';
	const CATEGORY_ACCOUNT = 'accounts';
	const CATEGORY_NETWORK = 'network';

	/**
	 * How much a failing check of each urgency drags the grade down.
	 *
	 * @var array<string, float>
	 */
	private static $default_weights = array(
		self::SEVERITY_CRITICAL => 3.0,
		self::SEVERITY_HIGH     => 2.0,
		self::SEVERITY_MEDIUM   => 1.5,
		self::SEVERITY_LOW      => 1.0,
	);

	/**
	 * Sort order for the priority list, highest urgency first.
	 *
	 * @var array<string, int>
	 */
	private static $severity_rank = array(
		self::SEVERITY_CRITICAL => 4,
		self::SEVERITY_HIGH     => 3,
		self::SEVERITY_MEDIUM   => 2,
		self::SEVERITY_LOW      => 1,
	);

	/**
	 * Memoised registry.
	 *
	 * @var array|null
	 */
	private static $tests = null;

	/**
	 * Memoised documentation.
	 *
	 * @var array|null
	 */
	private static $docs = null;

	/**
	 * All registered checks, keyed by test identifier.
	 *
	 * Labels are translated, so this must not run before the init hook.
	 *
	 * @return array<string, array>
	 */
	public static function all() {
		if ( null !== self::$tests ) {
			return self::$tests;
		}

		$tests = array_merge(
			self::core_tests(),
			self::config_tests(),
			self::file_tests(),
			self::account_tests(),
			self::network_tests()
		);

		/**
		 * Filters the registry before it is used.
		 *
		 * @param array $tests Test definitions keyed by identifier.
		 */
		$tests = apply_filters( 'cascr_registry', $tests );

		self::$tests = self::normalize( $tests );

		return self::$tests;
	}

	/**
	 * A single check definition.
	 *
	 * @param string $id Test identifier.
	 * @return array|null
	 */
	public static function get( $id ) {
		$tests = self::all();

		return isset( $tests[ $id ] ) ? $tests[ $id ] : null;
	}

	/**
	 * Whether a check with this identifier exists.
	 *
	 * @param string $id Test identifier.
	 * @return bool
	 */
	public static function exists( $id ) {
		$tests = self::all();

		return isset( $tests[ $id ] );
	}

	/**
	 * All test identifiers in registry order.
	 *
	 * @return string[]
	 */
	public static function ids() {
		return array_keys( self::all() );
	}

	/**
	 * The registry stripped of callbacks, ready to hand to the browser.
	 *
	 * @return array<string, array>
	 */
	public static function for_client() {
		$out = array();

		foreach ( self::all() as $id => $test ) {
			$out[ $id ] = array(
				'label'    => $test['label'],
				'category' => $test['category'],
				'severity' => $test['severity'],
				'doc'      => self::doc( $id ),
			);
		}

		return $out;
	}

	/**
	 * Numeric rank of an urgency level, for sorting.
	 *
	 * @param string $severity Severity slug.
	 * @return int
	 */
	public static function severity_rank( $severity ) {
		return isset( self::$severity_rank[ $severity ] ) ? self::$severity_rank[ $severity ] : 0;
	}

	/**
	 * Translated category labels, in display order.
	 *
	 * @return array<string, string>
	 */
	public static function categories() {
		return array(
			self::CATEGORY_CORE    => __( 'Core, plugins and themes', 'security-check-report' ),
			self::CATEGORY_CONFIG  => __( 'Configuration', 'security-check-report' ),
			self::CATEGORY_FILES   => __( 'Files and permissions', 'security-check-report' ),
			self::CATEGORY_ACCOUNT => __( 'Accounts and access', 'security-check-report' ),
			self::CATEGORY_NETWORK => __( 'Network and transport', 'security-check-report' ),
		);
	}

	/**
	 * Documentation for a single check.
	 *
	 * @param string $id Test identifier.
	 * @return string HTML, safe for wp_kses_post.
	 */
	public static function doc( $id ) {
		if ( null === self::$docs ) {
			self::$docs = include CASCR_PATH . 'config/docs.php';
		}

		return isset( self::$docs[ $id ] ) ? self::$docs[ $id ] : '';
	}

	/**
	 * All documentation entries, keyed by test identifier.
	 *
	 * @return array<string, string>
	 */
	public static function docs() {
		self::doc( '' );

		return self::$docs;
	}

	/**
	 * Drops memoised state. Used between test cases.
	 */
	public static function reset() {
		self::$tests = null;
		self::$docs  = null;
	}

	/**
	 * Fills in defaults and discards malformed entries.
	 *
	 * @param array $tests Raw definitions.
	 * @return array
	 */
	private static function normalize( $tests ) {
		$out = array();

		foreach ( $tests as $id => $test ) {
			if ( ! is_array( $test ) || empty( $test['callback'] ) || ! is_callable( $test['callback'] ) ) {
				continue;
			}

			$severity = isset( $test['severity'] ) ? $test['severity'] : self::SEVERITY_MEDIUM;
			if ( ! isset( self::$default_weights[ $severity ] ) ) {
				$severity = self::SEVERITY_MEDIUM;
			}

			$out[ $id ] = array(
				'id'       => $id,
				'label'    => isset( $test['label'] ) ? $test['label'] : $id,
				'category' => isset( $test['category'] ) ? $test['category'] : self::CATEGORY_CONFIG,
				'severity' => $severity,
				'weight'   => isset( $test['weight'] ) ? (float) $test['weight'] : self::$default_weights[ $severity ],
				'callback' => $test['callback'],
			);
		}

		return $out;
	}

	/**
	 * @return array
	 */
	private static function core_tests() {
		$c = 'CASCR_Checks_Core';

		return array(
			'wordpress_version'        => array(
				'label'    => __( 'WordPress version', 'security-check-report' ),
				'category' => self::CATEGORY_CORE,
				'severity' => self::SEVERITY_HIGH,
				'callback' => array( $c, 'wordpress_version' ),
			),
			'php_version'              => array(
				'label'    => __( 'PHP version', 'security-check-report' ),
				'category' => self::CATEGORY_CORE,
				'severity' => self::SEVERITY_HIGH,
				'callback' => array( $c, 'php_version' ),
			),
			'automatic_core_updates'   => array(
				'label'    => __( 'Automatic core updates', 'security-check-report' ),
				'category' => self::CATEGORY_CORE,
				'severity' => self::SEVERITY_HIGH,
				'callback' => array( $c, 'automatic_core_updates' ),
			),
			'core_file_integrity'      => array(
				'label'    => __( 'Core file integrity', 'security-check-report' ),
				'category' => self::CATEGORY_CORE,
				'severity' => self::SEVERITY_HIGH,
				'callback' => array( $c, 'core_file_integrity' ),
			),
			'unknown_core_files'       => array(
				'label'    => __( 'Unknown files in core directories', 'security-check-report' ),
				'category' => self::CATEGORY_CORE,
				'severity' => self::SEVERITY_CRITICAL,
				'callback' => array( $c, 'unknown_core_files' ),
			),
			'outdated_plugins'         => array(
				'label'    => __( 'Plugin updates', 'security-check-report' ),
				'category' => self::CATEGORY_CORE,
				'severity' => self::SEVERITY_HIGH,
				'callback' => array( $c, 'outdated_plugins' ),
			),
			'outdated_themes'          => array(
				'label'    => __( 'Theme updates', 'security-check-report' ),
				'category' => self::CATEGORY_CORE,
				'severity' => self::SEVERITY_MEDIUM,
				'callback' => array( $c, 'outdated_themes' ),
			),
			'plugin_hygiene'           => array(
				'label'    => __( 'Unused plugins and themes', 'security-check-report' ),
				'category' => self::CATEGORY_CORE,
				'severity' => self::SEVERITY_MEDIUM,
				'callback' => array( $c, 'plugin_hygiene' ),
			),
			'plugin_abandonment'       => array(
				'label'    => __( 'Abandoned plugins', 'security-check-report' ),
				'category' => self::CATEGORY_CORE,
				'severity' => self::SEVERITY_MEDIUM,
				'callback' => array( $c, 'plugin_abandonment' ),
			),
			'plugin_removed_from_repo' => array(
				'label'    => __( 'Plugins removed from the directory', 'security-check-report' ),
				'category' => self::CATEGORY_CORE,
				'severity' => self::SEVERITY_CRITICAL,
				'callback' => array( $c, 'plugin_removed_from_repo' ),
			),
			'plugin_ownership_change'  => array(
				'label'    => __( 'Plugin ownership changes', 'security-check-report' ),
				'category' => self::CATEGORY_CORE,
				'severity' => self::SEVERITY_HIGH,
				'callback' => array( $c, 'plugin_ownership_change' ),
			),
			'mu_plugins_and_dropins'   => array(
				'label'    => __( 'Must-use plugins and drop-ins', 'security-check-report' ),
				'category' => self::CATEGORY_CORE,
				'severity' => self::SEVERITY_HIGH,
				'callback' => array( $c, 'mu_plugins_and_dropins' ),
			),
			'other_wp_installs'        => array(
				'label'    => __( 'Other WordPress installations', 'security-check-report' ),
				'category' => self::CATEGORY_CORE,
				'severity' => self::SEVERITY_LOW,
				'callback' => array( $c, 'other_wp_installs' ),
			),
		);
	}

	/**
	 * @return array
	 */
	private static function config_tests() {
		$c = 'CASCR_Checks_Config';

		return array(
			'wp_debug'                 => array(
				'label'    => __( 'Debug mode', 'security-check-report' ),
				'category' => self::CATEGORY_CONFIG,
				'severity' => self::SEVERITY_MEDIUM,
				'callback' => array( $c, 'wp_debug' ),
			),
			'debug_log_exposure'       => array(
				'label'    => __( 'Debug log exposure', 'security-check-report' ),
				'category' => self::CATEGORY_CONFIG,
				'severity' => self::SEVERITY_MEDIUM,
				'callback' => array( $c, 'debug_log_exposure' ),
			),
			'file_edit'                => array(
				'label'    => __( 'Theme and plugin editor', 'security-check-report' ),
				'category' => self::CATEGORY_CONFIG,
				'severity' => self::SEVERITY_HIGH,
				'callback' => array( $c, 'file_edit' ),
			),
			'disallow_file_mods'       => array(
				'label'    => __( 'Installing code from the dashboard', 'security-check-report' ),
				'category' => self::CATEGORY_CONFIG,
				'severity' => self::SEVERITY_MEDIUM,
				'callback' => array( $c, 'disallow_file_mods' ),
			),
			'security_keys_salts'      => array(
				'label'    => __( 'Security keys and salts', 'security-check-report' ),
				'category' => self::CATEGORY_CONFIG,
				'severity' => self::SEVERITY_HIGH,
				'callback' => array( $c, 'security_keys_salts' ),
			),
			'db_prefix'                => array(
				'label'    => __( 'Database table prefix', 'security-check-report' ),
				'category' => self::CATEGORY_CONFIG,
				'severity' => self::SEVERITY_LOW,
				'callback' => array( $c, 'db_prefix' ),
			),
			'database_user_privileges' => array(
				'label'    => __( 'Database user privileges', 'security-check-report' ),
				'category' => self::CATEGORY_CONFIG,
				'severity' => self::SEVERITY_CRITICAL,
				'callback' => array( $c, 'database_user_privileges' ),
			),
			'wp_cron_health'           => array(
				'label'    => __( 'WP-Cron health', 'security-check-report' ),
				'category' => self::CATEGORY_CONFIG,
				'severity' => self::SEVERITY_MEDIUM,
				'callback' => array( $c, 'wp_cron_health' ),
			),
			'autoload_options_size'    => array(
				'label'    => __( 'Autoloaded options size', 'security-check-report' ),
				'category' => self::CATEGORY_CONFIG,
				'severity' => self::SEVERITY_LOW,
				'callback' => array( $c, 'autoload_options_size' ),
			),
			'suspicious_options'       => array(
				'label'    => __( 'Injected content in options', 'security-check-report' ),
				'category' => self::CATEGORY_CONFIG,
				'severity' => self::SEVERITY_CRITICAL,
				'callback' => array( $c, 'suspicious_options' ),
			),
			'backup'                   => array(
				'label'    => __( 'Backups', 'security-check-report' ),
				'category' => self::CATEGORY_CONFIG,
				'severity' => self::SEVERITY_LOW,
				'callback' => array( $c, 'backup' ),
			),
			'security_plugins'         => array(
				'label'    => __( 'Installed security plugins', 'security-check-report' ),
				'category' => self::CATEGORY_CONFIG,
				'severity' => self::SEVERITY_LOW,
				'weight'   => 0,
				'callback' => array( $c, 'security_plugins' ),
			),
			'brute_force'              => array(
				'label'    => __( 'Login protection', 'security-check-report' ),
				'category' => self::CATEGORY_CONFIG,
				'severity' => self::SEVERITY_HIGH,
				'callback' => array( $c, 'brute_force' ),
			),
			'password_policy'          => array(
				'label'    => __( 'Password policy', 'security-check-report' ),
				'category' => self::CATEGORY_CONFIG,
				'severity' => self::SEVERITY_MEDIUM,
				'callback' => array( $c, 'password_policy' ),
			),
		);
	}

	/**
	 * @return array
	 */
	private static function file_tests() {
		$c = 'CASCR_Checks_Files';

		return array(
			'wp_config_permissions' => array(
				'label'    => __( 'wp-config.php permissions', 'security-check-report' ),
				'category' => self::CATEGORY_FILES,
				'severity' => self::SEVERITY_CRITICAL,
				'callback' => array( $c, 'wp_config_permissions' ),
			),
			'uploads_permissions'   => array(
				'label'    => __( 'Uploads directory permissions', 'security-check-report' ),
				'category' => self::CATEGORY_FILES,
				'severity' => self::SEVERITY_MEDIUM,
				'callback' => array( $c, 'uploads_permissions' ),
			),
			'directory_permissions' => array(
				'label'    => __( 'Core directory permissions', 'security-check-report' ),
				'category' => self::CATEGORY_FILES,
				'severity' => self::SEVERITY_MEDIUM,
				'callback' => array( $c, 'directory_permissions' ),
			),
			'world_writable_paths'  => array(
				'label'    => __( 'World-writable files and folders', 'security-check-report' ),
				'category' => self::CATEGORY_FILES,
				'severity' => self::SEVERITY_HIGH,
				'callback' => array( $c, 'world_writable_paths' ),
			),
			'unallowed_files'       => array(
				'label'    => __( 'Executable files in uploads', 'security-check-report' ),
				'category' => self::CATEGORY_FILES,
				'severity' => self::SEVERITY_CRITICAL,
				'callback' => array( $c, 'unallowed_files' ),
			),
			'php_execution'         => array(
				'label'    => __( 'PHP execution in uploads', 'security-check-report' ),
				'category' => self::CATEGORY_FILES,
				'severity' => self::SEVERITY_CRITICAL,
				'callback' => array( $c, 'php_execution' ),
			),
			'exposed_config_files'  => array(
				'label'    => __( 'Publicly readable configuration files', 'security-check-report' ),
				'category' => self::CATEGORY_FILES,
				'severity' => self::SEVERITY_CRITICAL,
				'callback' => array( $c, 'exposed_config_files' ),
			),
			'exposed_repo_dirs'     => array(
				'label'    => __( 'Publicly readable repository folders', 'security-check-report' ),
				'category' => self::CATEGORY_FILES,
				'severity' => self::SEVERITY_CRITICAL,
				'callback' => array( $c, 'exposed_repo_dirs' ),
			),
			'exposed_db_dumps'      => array(
				'label'    => __( 'Publicly readable database dumps', 'security-check-report' ),
				'category' => self::CATEGORY_FILES,
				'severity' => self::SEVERITY_CRITICAL,
				'callback' => array( $c, 'exposed_db_dumps' ),
			),
			'unwanted_files_root'   => array(
				'label'    => __( 'Leftover files in the web root', 'security-check-report' ),
				'category' => self::CATEGORY_FILES,
				'severity' => self::SEVERITY_LOW,
				'callback' => array( $c, 'unwanted_files_root' ),
			),
			'upgrade_leftovers'     => array(
				'label'    => __( 'Leftovers from interrupted updates', 'security-check-report' ),
				'category' => self::CATEGORY_FILES,
				'severity' => self::SEVERITY_LOW,
				'callback' => array( $c, 'upgrade_leftovers' ),
			),
			'directory_listing'     => array(
				'label'    => __( 'Directory listing', 'security-check-report' ),
				'category' => self::CATEGORY_FILES,
				'severity' => self::SEVERITY_LOW,
				'callback' => array( $c, 'directory_listing' ),
			),
			'htaccess'              => array(
				'label'    => __( 'Server rule file', 'security-check-report' ),
				'category' => self::CATEGORY_FILES,
				'severity' => self::SEVERITY_LOW,
				'callback' => array( $c, 'htaccess' ),
			),
		);
	}

	/**
	 * @return array
	 */
	private static function account_tests() {
		$c = 'CASCR_Checks_Accounts';

		return array(
			'weak_password_users'            => array(
				'label'    => __( 'Weak passwords', 'security-check-report' ),
				'category' => self::CATEGORY_ACCOUNT,
				'severity' => self::SEVERITY_CRITICAL,
				'callback' => array( $c, 'weak_password_users' ),
			),
			'admin_username'                 => array(
				'label'    => __( 'Predictable administrator name', 'security-check-report' ),
				'category' => self::CATEGORY_ACCOUNT,
				'severity' => self::SEVERITY_HIGH,
				'callback' => array( $c, 'admin_username' ),
			),
			'admin_account_hygiene'          => array(
				'label'    => __( 'Administrator accounts', 'security-check-report' ),
				'category' => self::CATEGORY_ACCOUNT,
				'severity' => self::SEVERITY_MEDIUM,
				'callback' => array( $c, 'admin_account_hygiene' ),
			),
			'role_capability_drift'          => array(
				'label'    => __( 'Role and capability changes', 'security-check-report' ),
				'category' => self::CATEGORY_ACCOUNT,
				'severity' => self::SEVERITY_CRITICAL,
				'callback' => array( $c, 'role_capability_drift' ),
			),
			'open_registration'              => array(
				'label'    => __( 'Open registration', 'security-check-report' ),
				'category' => self::CATEGORY_ACCOUNT,
				'severity' => self::SEVERITY_MEDIUM,
				'callback' => array( $c, 'open_registration' ),
			),
			'two_factor_coverage'            => array(
				'label'    => __( 'Two-factor coverage', 'security-check-report' ),
				'category' => self::CATEGORY_ACCOUNT,
				'severity' => self::SEVERITY_HIGH,
				'callback' => array( $c, 'two_factor_coverage' ),
			),
			'application_password_inventory' => array(
				'label'    => __( 'Application passwords', 'security-check-report' ),
				'category' => self::CATEGORY_ACCOUNT,
				'severity' => self::SEVERITY_MEDIUM,
				'callback' => array( $c, 'application_password_inventory' ),
			),
		);
	}

	/**
	 * @return array
	 */
	private static function network_tests() {
		$c = 'CASCR_Checks_Network';

		return array(
			'ssl'                    => array(
				'label'    => __( 'HTTPS', 'security-check-report' ),
				'category' => self::CATEGORY_NETWORK,
				'severity' => self::SEVERITY_HIGH,
				'callback' => array( $c, 'ssl' ),
			),
			'tls_certificate'        => array(
				'label'    => __( 'TLS certificate', 'security-check-report' ),
				'category' => self::CATEGORY_NETWORK,
				'severity' => self::SEVERITY_HIGH,
				'callback' => array( $c, 'tls_certificate' ),
			),
			'security_headers'       => array(
				'label'    => __( 'Security headers', 'security-check-report' ),
				'category' => self::CATEGORY_NETWORK,
				'severity' => self::SEVERITY_MEDIUM,
				'callback' => array( $c, 'security_headers' ),
			),
			'hsts_quality'           => array(
				'label'    => __( 'HSTS configuration', 'security-check-report' ),
				'category' => self::CATEGORY_NETWORK,
				'severity' => self::SEVERITY_MEDIUM,
				'callback' => array( $c, 'hsts_quality' ),
			),
			'csp_quality'            => array(
				'label'    => __( 'Content Security Policy', 'security-check-report' ),
				'category' => self::CATEGORY_NETWORK,
				'severity' => self::SEVERITY_MEDIUM,
				'callback' => array( $c, 'csp_quality' ),
			),
			'cookie_flags'           => array(
				'label'    => __( 'Cookie flags', 'security-check-report' ),
				'category' => self::CATEGORY_NETWORK,
				'severity' => self::SEVERITY_MEDIUM,
				'callback' => array( $c, 'cookie_flags' ),
			),
			'cors_configuration'     => array(
				'label'    => __( 'CORS configuration', 'security-check-report' ),
				'category' => self::CATEGORY_NETWORK,
				'severity' => self::SEVERITY_MEDIUM,
				'callback' => array( $c, 'cors_configuration' ),
			),
			'php_version_in_headers' => array(
				'label'    => __( 'PHP version in response headers', 'security-check-report' ),
				'category' => self::CATEGORY_NETWORK,
				'severity' => self::SEVERITY_LOW,
				'callback' => array( $c, 'php_version_in_headers' ),
			),
			'legacy_meta_exposure'   => array(
				'label'    => __( 'Legacy discovery tags', 'security-check-report' ),
				'category' => self::CATEGORY_NETWORK,
				'severity' => self::SEVERITY_LOW,
				'callback' => array( $c, 'legacy_meta_exposure' ),
			),
			'xmlrpc'                 => array(
				'label'    => __( 'XML-RPC interface', 'security-check-report' ),
				'category' => self::CATEGORY_NETWORK,
				'severity' => self::SEVERITY_LOW,
				'callback' => array( $c, 'xmlrpc' ),
			),
			'user_enumeration'       => array(
				'label'    => __( 'User enumeration', 'security-check-report' ),
				'category' => self::CATEGORY_NETWORK,
				'severity' => self::SEVERITY_MEDIUM,
				'callback' => array( $c, 'user_enumeration' ),
			),
			'rest_open_routes'       => array(
				'label'    => __( 'Unauthenticated REST routes', 'security-check-report' ),
				'category' => self::CATEGORY_NETWORK,
				'severity' => self::SEVERITY_MEDIUM,
				'callback' => array( $c, 'rest_open_routes' ),
			),
			'proxy_ip_configuration' => array(
				'label'    => __( 'Client IP detection', 'security-check-report' ),
				'category' => self::CATEGORY_NETWORK,
				'severity' => self::SEVERITY_HIGH,
				'callback' => array( $c, 'proxy_ip_configuration' ),
			),
		);
	}
}
