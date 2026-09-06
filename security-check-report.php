<?php
/*
Plugin Name: CMS ADMINS Security Check Report
Plugin URI: https://wordpress.org/plugins/security-check-report
Description: Runs a series of read-only security checks against your WordPress installation and turns the findings into a graded report with a short list of what to fix first.
Version: 2.3.1
Requires at least: 7.0
Requires PHP: 7.4
Author: Patrick Schlesinger
Author URI: https://www.cms-admins.de/
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Text Domain: security-check-report
Domain Path: /languages
*/

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'CASCR_VERSION', '2.3.1' );
define( 'CASCR_PATH', plugin_dir_path( __FILE__ ) );
define( 'CASCR_URL', plugin_dir_url( __FILE__ ) );

/**
 * Wires the plugin together.
 *
 * Everything of substance lives in includes/. This class only decides what is
 * loaded and which hooks it hangs on, so the entry point stays readable.
 */
class CASCR_SecurityCheck {

	/**
	 * Files loaded on every request, in dependency order.
	 *
	 * @var string[]
	 */
	private static $files = array(
		'includes/class-cascr-result.php',
		'includes/class-cascr-http.php',
		'includes/class-cascr-store.php',
		'includes/class-cascr-registry.php',
		'includes/class-cascr-scoring.php',
		'includes/class-cascr-runner.php',
		'includes/class-cascr-rest.php',
		'includes/class-cascr-admin.php',
		'includes/checks/class-cascr-checks-base.php',
		'includes/checks/class-cascr-checks-core.php',
		'includes/checks/class-cascr-checks-config.php',
		'includes/checks/class-cascr-checks-files.php',
		'includes/checks/class-cascr-checks-accounts.php',
		'includes/checks/class-cascr-checks-network.php',
	);

	/**
	 * Loads the classes and registers the hooks.
	 */
	public function __construct() {
		foreach ( self::$files as $file ) {
			require_once CASCR_PATH . $file;
		}

		add_action( 'admin_menu', array( 'CASCR_Admin', 'register_menu' ) );
		add_action( 'admin_enqueue_scripts', array( 'CASCR_Admin', 'enqueue' ) );
		add_action( 'rest_api_init', array( 'CASCR_REST', 'register_routes' ) );

		// WordPress keeps no login history. Recording it from here is what lets
		// the account check say anything about dormant administrators.
		add_action( 'wp_login', array( 'CASCR_Checks_Accounts', 'record_login' ), 10, 2 );

		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			require_once CASCR_PATH . 'includes/class-cascr-cli.php';
			WP_CLI::add_command( 'security-check', 'CASCR_CLI' );
		}
	}
}

new CASCR_SecurityCheck();
