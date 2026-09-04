<?php
/*
Plugin Name: CMS ADMINS Security Check Report
Plugin URI: https://wordpress.org/plugins/security-check-report
Description: Performs a comprehensive series of security tests on your WordPress installation and provides an overall risk evaluation.
Version: 2.2.1
Requires at least: 6.4
Requires PHP: 8.2
Author: Patrick Schlesinger
Author URI: https://www.cms-admins.de/
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Text Domain: security-check-report
Domain Path: /languages
*/

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly
}

define( 'CASCR_VERSION', '2.2.1' );

class CASCR_SecurityCheck {

	private $config;
	private $accordion;

	public function __construct() {
		$this->config = include plugin_dir_path( __FILE__ ) . 'config/config.php';

		add_action( 'admin_menu', array( $this, 'register_admin_menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_scripts' ) );
		add_action( 'wp_ajax_run_security_check', array( $this, 'ajax_run_security_check' ) );
	}

	/**
	 * Accordion config contains translated strings, so it must not be loaded
	 * before the init hook (WP 6.7+ _load_textdomain_just_in_time notice).
	 */
	private function get_accordion() {
		if ( null === $this->accordion ) {
			$this->accordion = include plugin_dir_path( __FILE__ ) . 'config/accordion.php';
		}
		return $this->accordion;
	}

	public function register_admin_menu() {
		add_menu_page(
			__( 'Security Check Report', 'security-check-report' ),
			__( 'Security Check Report', 'security-check-report' ),
			'manage_options',
			'security-check-report',
			array( $this, 'display_security_check_results' ),
			'dashicons-shield',
			100
		);
	}

	public function display_security_check_results() {
		?>
		<div class="wrap" id="cmsadmins-security-check-admin">
			<div class="cascr-header">
				<h1><?php echo esc_html__( 'Security Check Report', 'security-check-report' ); ?></h1>
				<p class="cascr-header__subtitle"><?php echo esc_html__( 'Comprehensive security audit for your WordPress installation', 'security-check-report' ); ?></p>
			</div>
			<div id="security-check-wrap">
				<div id="security-check-loader">
					<div class="cascr-loader__header">
						<span class="cascr-loader__spinner"></span>
						<span id="loader-text"><?php echo esc_html__( 'Running security checks...', 'security-check-report' ); ?></span>
					</div>
					<div id="progress-bar"><div id="progress"></div></div>
				</div>
				<label class="disclaimer-text">
					<input type="checkbox" id="disclaimer-checkbox" />
					<span><?php echo esc_html__( 'I acknowledge that CMS ADMINS is not liable for any damages and does not guarantee the accuracy of the results.', 'security-check-report' ); ?></span>
				</label>
				<p class="text-center">
					<button id="start-tests" class="button button-primary" disabled>
						<?php echo esc_html__( 'Run Security Check!', 'security-check-report' ); ?>
					</button>
				</p>
			</div>
			<table id="security-check-results" class="widefat fixed" style="display:none;">
				<thead>
				<tr>
					<th><?php echo esc_html__( 'Test', 'security-check-report' ); ?></th>
					<th><?php echo esc_html__( 'Result', 'security-check-report' ); ?></th>
					<th><?php echo esc_html__( 'Score', 'security-check-report' ); ?></th>
					<th><?php echo esc_html__( 'Status', 'security-check-report' ); ?></th>
				</tr>
				</thead>
				<tbody id="results-body"></tbody>
				<tfoot>
				<tr>
					<th><?php echo esc_html__( 'Test', 'security-check-report' ); ?></th>
					<th><?php echo esc_html__( 'Result', 'security-check-report' ); ?></th>
					<th><?php echo esc_html__( 'Score', 'security-check-report' ); ?></th>
					<th><?php echo esc_html__( 'Status', 'security-check-report' ); ?></th>
				</tr>
				</tfoot>
			</table>
			<div id="final-report-container" style="display:none;">
				<div id="final-summary"></div>
				<div class="cascr-report-section">
					<h2><?php echo esc_html__( 'Detailed Test Results', 'security-check-report' ); ?></h2>
					<p class="cascr-report-description"><?php echo esc_html__( 'The complete test report can be copied below for documentation or sharing with your security team.', 'security-check-report' ); ?></p>
					<textarea id="final-report" readonly></textarea>
					<p>
						<button id="copy-report" class="button button-secondary">
							<?php echo esc_html__( 'Copy Report to Clipboard', 'security-check-report' ); ?>
						</button>
					</p>
				</div>
			</div>
			<div class="cascr-documentation">
				<div class="cascr-documentation__header">
					<h2><?php echo esc_html__( 'Security Test Documentation', 'security-check-report' ); ?></h2>
					<p class="cascr-documentation__subtitle"><?php echo esc_html__( 'Learn about each security test and how to improve your WordPress security.', 'security-check-report' ); ?></p>
				</div>
				<div class="cascr-search">
					<div class="cascr-search__wrapper">
						<svg class="cascr-search__icon" xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
							<circle cx="11" cy="11" r="8"></circle>
							<path d="m21 21-4.3-4.3"></path>
						</svg>
						<input type="text" id="cascr-accordion-search" class="cascr-search__input" placeholder="<?php echo esc_attr__( 'Search tests...', 'security-check-report' ); ?>" autocomplete="off">
						<button type="button" id="cascr-search-clear" class="cascr-search__clear" hidden aria-label="<?php echo esc_attr__( 'Clear search', 'security-check-report' ); ?>">
							<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
								<path d="M18 6 6 18"></path>
								<path d="m6 6 12 12"></path>
							</svg>
						</button>
					</div>
					<div class="cascr-search__stats">
						<span id="cascr-search-count"><?php echo count( $this->get_accordion() ); ?></span> <?php echo esc_html__( 'tests', 'security-check-report' ); ?>
					</div>
				</div>
				<div id="cascr-accordion" class="cascr-accordion">
					<div id="cascr-no-results" class="cascr-accordion__no-results" hidden>
						<p><?php echo esc_html__( 'No tests found matching your search.', 'security-check-report' ); ?></p>
					</div>
					<?php
					foreach ( $this->get_accordion() as $title => $description ) {
						$this->display_accordion_section( $title, $description );
					}
					?>
				</div>
			</div>
			<footer class="cascr-footer">
				<div class="cascr-footer__brand">
					<span class="cascr-footer__logo">CMS ADMINS</span>
					<span class="cascr-footer__copyright">&copy; <?php echo esc_html( gmdate( 'Y' ) ); ?> Patrick Schlesinger</span>
				</div>
				<div class="cascr-footer__links">
					<a href="https://www.cms-admins.de" target="_blank" rel="noopener noreferrer"><?php echo esc_html__( 'Website', 'security-check-report' ); ?></a>
					<span class="cascr-footer__separator">·</span>
					<a href="https://www.cms-admins.de/docs/" target="_blank" rel="noopener noreferrer"><?php echo esc_html__( 'Documentation', 'security-check-report' ); ?></a>
					<span class="cascr-footer__separator">·</span>
					<a href="https://www.cms-admins.de/support/" target="_blank" rel="noopener noreferrer"><?php echo esc_html__( 'Support', 'security-check-report' ); ?></a>
				</div>
			</footer>
		</div>
		<?php
	}

	public function enqueue_admin_scripts() {
		$screen = get_current_screen();
		if ( $screen && $screen->id === 'toplevel_page_security-check-report' ) {
			wp_enqueue_script( 'cascr-admin', plugins_url( '/assets/js/admin.js', __FILE__ ), array(), CASCR_VERSION, true );
			wp_enqueue_style( 'cascr-admin', plugins_url( '/assets/css/admin.css', __FILE__ ), array(), CASCR_VERSION );

			$tests      = array_keys( $this->get_security_tests() );
			$test_names = array(
				'wordpress_version'        => esc_html__( 'WordPress Version', 'security-check-report' ),
				'php_version'              => esc_html__( 'PHP Version Check', 'security-check-report' ),
				'wp_config'                => esc_html__( 'wp-config.php Permissions', 'security-check-report' ),
				'uploads_permissions'      => esc_html__( 'Uploads Directory Permissions', 'security-check-report' ),
				'wp_debug'                 => esc_html__( 'WP_DEBUG Mode', 'security-check-report' ),
				'weak_password_users'      => esc_html__( 'Weak Password Users', 'security-check-report' ),
				'password_policy'          => esc_html__( 'Strong Password Policies', 'security-check-report' ),
				'two_factor'               => esc_html__( 'Two-Factor Authentication', 'security-check-report' ),
				'admin_username'           => esc_html__( 'Admin Username', 'security-check-report' ),
				'outdated_plugins'         => esc_html__( 'Outdated Plugins', 'security-check-report' ),
				'deactivated_plugins'      => esc_html__( 'Deactivated Plugins', 'security-check-report' ),
				'outdated_themes'          => esc_html__( 'Outdated Themes', 'security-check-report' ),
				'htaccess'                 => esc_html__( '.htaccess File', 'security-check-report' ),
				'xmlrpc'                   => esc_html__( 'XML-RPC Interface', 'security-check-report' ),
				'xmlrpc_methods'           => esc_html__( 'XML-RPC Methods', 'security-check-report' ),
				'rest_api'                 => esc_html__( 'REST API', 'security-check-report' ),
				'file_edit'                => esc_html__( 'File Editing in Admin', 'security-check-report' ),
				'directory_indexing'       => esc_html__( 'Directory Indexing', 'security-check-report' ),
				'ssl'                      => esc_html__( 'SSL Enabled', 'security-check-report' ),
				'server_headers'           => esc_html__( 'Server Headers', 'security-check-report' ),
				'php_version_in_headers'   => esc_html__( 'PHP Version in Headers', 'security-check-report' ),
				'legacy_meta_exposure'     => esc_html__( 'Legacy Meta Exposure', 'security-check-report' ),
				'unallowed_files'          => esc_html__( 'Unallowed Files in Uploads', 'security-check-report' ),
				'backup'                   => esc_html__( 'Regular Backups', 'security-check-report' ),
				'security_plugins'         => esc_html__( 'Security Plugins Installed', 'security-check-report' ),
				'db_prefix'                => esc_html__( 'Database Prefix', 'security-check-report' ),
				'brute_force'              => esc_html__( 'Brute-Force Protection', 'security-check-report' ),
				'login_attempts'           => esc_html__( 'Login Attempts Limiting', 'security-check-report' ),
				'php_execution'            => esc_html__( 'PHP Execution in Uploads', 'security-check-report' ),
				'malware_check'            => esc_html__( 'Malware Check', 'security-check-report' ),
				'other_wp_installs'        => esc_html__( 'Other WordPress Installations', 'security-check-report' ),
				'automatic_core_updates'   => esc_html__( 'Automatic Core Updates', 'security-check-report' ),
				'security_keys_salts'      => esc_html__( 'Security Keys & Salts', 'security-check-report' ),
				'unwanted_files_root'      => esc_html__( 'Unwanted Files in Root', 'security-check-report' ),
				'directory_permissions'    => esc_html__( 'Directory Permissions', 'security-check-report' ),
				'php_version_support'      => esc_html__( 'PHP Version Support', 'security-check-report' ),
				'database_user_privileges' => esc_html__( 'Database User Privileges', 'security-check-report' ),
				'database_structure'       => esc_html__( 'Database Structure', 'security-check-report' ),
				'outdated_libraries'       => esc_html__( 'Outdated Libraries', 'security-check-report' ),
				'user_enumeration'         => esc_html__( 'User Enumeration', 'security-check-report' ),
				// New tests added in v2.1
				'application_passwords'    => esc_html__( 'Application Passwords', 'security-check-report' ),
				'wp_cron_security'         => esc_html__( 'WP-Cron Security', 'security-check-report' ),
				'debug_log_exposure'       => esc_html__( 'Debug Log Exposure', 'security-check-report' ),
				'cors_configuration'       => esc_html__( 'CORS Configuration', 'security-check-report' ),
				'core_file_integrity'      => esc_html__( 'Core File Integrity', 'security-check-report' ),
			);

			wp_localize_script(
				'cascr-admin',
				'cascr',
				array(
					'ajaxUrl' => admin_url( 'admin-ajax.php' ),
					'nonce'   => wp_create_nonce( 'cascr_security_nonce' ),
					'i18n'    => array(
						'runningCheck' => esc_html__( 'Running security check', 'security-check-report' ),
						'errorMessage' => esc_html__( 'An error occurred while running the test.', 'security-check-report' ),
						'copySuccess'  => esc_html__( 'Report copied to clipboard!', 'security-check-report' ),
						'copyError'    => esc_html__( 'Failed to copy to clipboard.', 'security-check-report' ),
					),
					'tests'   => array(
						'list'  => $tests,
						'names' => $test_names,
					),
				)
			);
		}
	}

	public function ajax_run_security_check() {
		check_ajax_referer( 'cascr_security_nonce', 'security_nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized access.', 'security-check-report' ) ), 403 );
		}

		$test_name = isset( $_REQUEST['test_name'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['test_name'] ) ) : '';
		$tests     = $this->get_security_tests();
		if ( isset( $tests[ $test_name ] ) ) {
			$result = call_user_func( $tests[ $test_name ] );
			wp_send_json_success( $result );
		} else {
			wp_send_json_error( array( 'result' => __( 'Invalid test name.', 'security-check-report' ) ) );
		}
	}

	private function display_accordion_section( $title, $description ) {
		$slug = sanitize_title( $title );
		?>
		<details class="cascr-accordion__item" data-search-text="<?php echo esc_attr( strtolower( wp_strip_all_tags( $title . ' ' . $description ) ) ); ?>">
			<summary class="cascr-accordion__header" id="accordion-<?php echo esc_attr( $slug ); ?>">
				<span class="cascr-accordion__title"><?php echo esc_html( $title ); ?></span>
				<span class="cascr-accordion__icon" aria-hidden="true"></span>
			</summary>
			<div class="cascr-accordion__content">
				<div class="cascr-accordion__description"><?php echo wp_kses_post( $description ); ?></div>
			</div>
		</details>
		<?php
	}

	/**
	 * Returns all security tests.
	 *
	 * @return array<string, callable> Test ID => callback pairs
	 */
	private function get_security_tests() {
		return array(
			'wordpress_version'        => array( $this, 'check_wordpress_version' ),
			'php_version'              => array( $this, 'check_php_version' ),
			'wp_config'                => array( $this, 'check_wp_config' ),
			'uploads_permissions'      => array( $this, 'check_uploads_permissions' ),
			'wp_debug'                 => array( $this, 'check_wp_debug' ),
			'weak_password_users'      => array( $this, 'check_weak_password_users' ),
			'password_policy'          => array( $this, 'check_password_policy' ),
			'two_factor'               => array( $this, 'check_two_factor' ),
			'admin_username'           => array( $this, 'check_admin_username' ),
			'outdated_plugins'         => array( $this, 'check_outdated_plugins' ),
			'deactivated_plugins'      => array( $this, 'check_deactivated_plugins' ),
			'outdated_themes'          => array( $this, 'check_outdated_themes' ),
			'htaccess'                 => array( $this, 'check_htaccess' ),
			'xmlrpc'                   => array( $this, 'check_xmlrpc' ),
			'xmlrpc_methods'           => array( $this, 'check_xmlrpc_methods' ),
			'rest_api'                 => array( $this, 'check_rest_api' ),
			'file_edit'                => array( $this, 'check_file_edit' ),
			'directory_indexing'       => array( $this, 'check_directory_indexing' ),
			'ssl'                      => array( $this, 'check_ssl' ),
			'server_headers'           => array( $this, 'check_server_headers' ),
			'php_version_in_headers'   => array( $this, 'check_php_version_in_headers' ),
			'legacy_meta_exposure'     => array( $this, 'check_legacy_meta_exposure' ),
			'unallowed_files'          => array( $this, 'check_unallowed_files' ),
			'backup'                   => array( $this, 'check_backup' ),
			'security_plugins'         => array( $this, 'check_security_plugins' ),
			'db_prefix'                => array( $this, 'check_db_prefix' ),
			'brute_force'              => array( $this, 'check_brute_force' ),
			'login_attempts'           => array( $this, 'check_login_attempts' ),
			'php_execution'            => array( $this, 'check_php_execution' ),
			'malware_check'            => array( $this, 'check_for_malware' ),
			'other_wp_installs'        => array( $this, 'check_other_wp_installs' ),
			'automatic_core_updates'   => array( $this, 'check_automatic_core_updates' ),
			'security_keys_salts'      => array( $this, 'check_security_keys_salts' ),
			'unwanted_files_root'      => array( $this, 'check_unwanted_files_root' ),
			'directory_permissions'    => array( $this, 'check_directory_permissions' ),
			'php_version_support'      => array( $this, 'check_php_version_support' ),
			'database_user_privileges' => array( $this, 'check_database_user_privileges' ),
			'database_structure'       => array( $this, 'check_database_structure' ),
			'outdated_libraries'       => array( $this, 'check_outdated_libraries' ),
			// New tests added in v2.1
			'application_passwords'    => array( $this, 'check_application_passwords' ),
			'wp_cron_security'         => array( $this, 'check_wp_cron_security' ),
			'debug_log_exposure'       => array( $this, 'check_debug_log_exposure' ),
			'cors_configuration'       => array( $this, 'check_cors_configuration' ),
			'core_file_integrity'      => array( $this, 'check_core_file_integrity' ),
			'user_enumeration'         => array( $this, 'check_user_enumeration' ),
		);
	}

	private function check_wordpress_version() {
		global $wp_version;
		$latest_version = $this->get_latest_wordpress_version();
		if ( is_wp_error( $latest_version ) ) {
			return array(
				'result' => __( 'Could not fetch the latest WordPress version.', 'security-check-report' ),
				'score'  => 0,
			);
		}
		if ( version_compare( $wp_version, $latest_version, '<' ) ) {
			return array(
				/* translators: %1$s: current WordPress version, %2$s: latest WordPress version */
				'result' => sprintf( __( 'WordPress is outdated. Current: %1$s. Latest: %2$s.', 'security-check-report' ), $wp_version, $latest_version ),
				'score'  => 10,
			);
		} else {
			return array(
				'result' => __( 'WordPress is up to date.', 'security-check-report' ),
				'score'  => 0,
			);
		}
	}

	private function check_php_version() {
		$current     = phpversion();
		$recommended = '8.2';
		$minimum     = '7.4';

		if ( version_compare( $current, $recommended, '>=' ) ) {
			return array(
				/* translators: %s: PHP version number */
				'result' => sprintf( __( 'PHP version %s is current and recommended.', 'security-check-report' ), $current ),
				'score'  => 0,
			);
		}

		if ( version_compare( $current, $minimum, '>=' ) ) {
			return array(
				/* translators: %1$s: current PHP version, %2$s: recommended PHP version */
				'result' => sprintf( __( 'PHP version %1$s is acceptable but upgrading to %2$s is recommended.', 'security-check-report' ), $current, $recommended ),
				'score'  => 4,
			);
		}

		return array(
			/* translators: %1$s: current PHP version, %2$s: minimum required PHP version */
			'result' => sprintf( __( 'PHP version %1$s is outdated and insecure. Upgrade to at least %2$s.', 'security-check-report' ), $current, $minimum ),
			'score'  => 9,
		);
	}

	private function check_wp_config() {
		$file        = ABSPATH . 'wp-config.php';
		$is_writable = wp_is_writable( $file );
		$score       = $is_writable ? 10 : 0;
		$result      = $is_writable
			? __( 'wp-config.php is writable. This is a security risk!', 'security-check-report' )
			: __( 'wp-config.php permissions are secure.', 'security-check-report' );
		return array(
			'result' => $result,
			'score'  => $score,
		);
	}

	private function check_uploads_permissions() {
		$dir    = wp_upload_dir()['basedir'];
		$perm   = substr( sprintf( '%o', fileperms( $dir ) ), -4 );
		$score  = ( $perm !== '0755' ) ? 7 : 0;
		$result = ( $perm !== '0755' )
			? __( 'Uploads directory has insecure permissions.', 'security-check-report' )
			: __( 'Uploads directory permissions are secure.', 'security-check-report' );
		return array(
			'result' => $result,
			'score'  => $score,
		);
	}

	private function check_wp_debug() {
		$enabled = defined( 'WP_DEBUG' ) && WP_DEBUG;
		return array(
			'result' => $enabled
				? __( 'WP_DEBUG is enabled. This may expose sensitive information.', 'security-check-report' )
				: __( 'WP_DEBUG is disabled.', 'security-check-report' ),
			'score'  => $enabled ? 7 : 0,
		);
	}

	private function check_weak_password_users() {
		// Common weak passwords to check
		$weak_passwords = array(
			'password',
			'123456',
			'12345678',
			'123456789',
			'1234567890',
			'qwerty',
			'abc123',
			'password1',
			'password123',
			'admin',
			'admin123',
			'letmein',
			'welcome',
			'monkey',
			'root',
			'toor',
			'pass',
			'test',
			'guest',
			'master',
			'changeme',
			'qwerty123',
			'111111',
			'iloveyou',
			'dragon',
		);

		$users = get_users( array( 'fields' => array( 'ID', 'user_login', 'user_pass' ) ) );
		$weak  = array();

		foreach ( $users as $user ) {
			$found_weak = false;

			// Check against common weak passwords
			foreach ( $weak_passwords as $pwd ) {
				if ( wp_check_password( $pwd, $user->user_pass, $user->ID ) ) {
					$weak[]     = $user->user_login;
					$found_weak = true;
					break;
				}
			}

			// Also check if password equals username (very common weak pattern)
			if ( ! $found_weak && wp_check_password( $user->user_login, $user->user_pass, $user->ID ) ) {
				$weak[]     = $user->user_login;
				$found_weak = true;
			}

			// Check if password equals username with common suffixes
			if ( ! $found_weak ) {
				$username_variants = array(
					$user->user_login . '123',
					$user->user_login . '1',
					$user->user_login . '!',
					$user->user_login . '@123',
				);
				foreach ( $username_variants as $variant ) {
					if ( wp_check_password( $variant, $user->user_pass, $user->ID ) ) {
						$weak[] = $user->user_login;
						break;
					}
				}
			}
		}

		// Calculate score based on number of weak passwords found
		$count = count( $weak );
		if ( $count === 0 ) {
			$score = 0;
		} elseif ( $count === 1 ) {
			$score = 7;
		} elseif ( $count <= 3 ) {
			$score = 8;
		} else {
			$score = 9;
		}

		if ( ! empty( $weak ) ) {
			$display_users = array_slice( $weak, 0, 5 );
			$more_count    = $count - 5;
			$result        = sprintf(
				/* translators: %1$d: number of users with weak passwords, %2$s: list of usernames */
				__( 'Users with weak passwords (%1$d found): %2$s', 'security-check-report' ),
				$count,
				implode( ', ', $display_users ) . ( $more_count > 0 ? sprintf( ' +%d more', $more_count ) : '' )
			);
		} else {
			$result = __( 'No users with common weak passwords found.', 'security-check-report' );
		}

		return array(
			'result' => $result,
			'score'  => $score,
		);
	}

	private function check_password_policy() {
		$enforced = $this->is_strong_passwords_enforced();
		return array(
			'result' => $enforced
				? __( 'Strong password policies are enforced.', 'security-check-report' )
				: __( 'Strong password policies are not enforced. This is a security risk.', 'security-check-report' ),
			'score'  => $enforced ? 0 : 8,
		);
	}

	private function check_two_factor() {
		$enabled = $this->is_two_factor_enabled();
		return array(
			'result' => $enabled
				? __( 'Two-factor authentication is enabled.', 'security-check-report' )
				: __( 'Two-factor authentication is not enabled. This is a security risk.', 'security-check-report' ),
			'score'  => $enabled ? 0 : 9,
		);
	}

	private function check_admin_username() {
		$admin = get_user_by( 'login', 'admin' );
		$score = $admin ? 9 : 0;
		return array(
			'result' => $admin
				? sprintf( __( 'User "admin" exists. This is a common target.', 'security-check-report' ), 'admin' )
				: __( 'No user "admin" found.', 'security-check-report' ),
			'score'  => $score,
		);
	}

	private function check_outdated_plugins() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$plugins  = get_plugins();
		$outdated = array();
		foreach ( $plugins as $plugin_file => $plugin_data ) {
			if ( is_plugin_active( $plugin_file ) ) {
				$path = WP_PLUGIN_DIR . '/' . $plugin_file;
				if ( ! $this->is_plugin_up_to_date( $plugin_file ) || $this->is_file_outdated( $path ) ) {
					$outdated[] = $plugin_data['Name'];
				}
			}
		}
		$score  = ! empty( $outdated ) ? 8 : 0;
		$result = ! empty( $outdated )
			? __( 'Outdated plugins: ', 'security-check-report' ) . implode( ', ', $outdated )
			: __( 'All plugins are up to date.', 'security-check-report' );
		return array(
			'result' => $result,
			'score'  => $score,
		);
	}

	private function check_deactivated_plugins() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$plugins     = get_plugins();
		$deactivated = array();
		foreach ( $plugins as $plugin_file => $plugin_data ) {
			if ( ! is_plugin_active( $plugin_file ) ) {
				$deactivated[] = $plugin_data['Name'];
			}
		}
		$score  = ! empty( $deactivated ) ? 5 : 0;
		$result = ! empty( $deactivated )
			? __( 'Deactivated plugins: ', 'security-check-report' ) . implode( ', ', $deactivated )
			: __( 'No deactivated plugins found.', 'security-check-report' );
		return array(
			'result' => $result,
			'score'  => $score,
		);
	}

	private function check_outdated_themes() {
		$themes   = wp_get_themes();
		$outdated = array();
		foreach ( $themes as $theme_name => $theme_data ) {
			$path = get_theme_root() . '/' . $theme_data->get_stylesheet();
			if ( ! $this->is_theme_up_to_date( $theme_data ) || $this->is_file_outdated( $path ) ) {
				$outdated[] = $theme_name;
			}
		}
		$score  = ! empty( $outdated ) ? 7 : 0;
		$result = ! empty( $outdated )
			? __( 'Outdated themes: ', 'security-check-report' ) . implode( ', ', $outdated )
			: __( 'All themes are up to date.', 'security-check-report' );
		return array(
			'result' => $result,
			'score'  => $score,
		);
	}

	private function check_htaccess() {
		$server = isset( $_SERVER['SERVER_SOFTWARE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) : '';
		if ( strpos( strtolower( $server ), 'nginx' ) !== false ) {
			$response = wp_remote_get( site_url( '/wp-admin/' ), array( 'timeout' => 10 ) );
			if ( is_wp_error( $response ) ) {
				return array(
					'result' => __( 'Could not verify Nginx configuration.', 'security-check-report' ),
					'score'  => 0,
				);
			}
			$body       = wp_remote_retrieve_body( $response );
			$vulnerable = strpos( $body, 'Index of /wp-admin' ) !== false;
			return array(
				'result' => $vulnerable
					? __( 'Nginx security rules may be missing.', 'security-check-report' )
					: __( 'Nginx security rules are properly configured.', 'security-check-report' ),
				'score'  => $vulnerable ? 5 : 0,
			);
		} else {
			$file       = ABSPATH . '.htaccess';
			$vulnerable = ! file_exists( $file );
			return array(
				'result' => $vulnerable
					? __( '.htaccess file is missing.', 'security-check-report' )
					: __( '.htaccess file is present.', 'security-check-report' ),
				'score'  => $vulnerable ? 5 : 0,
			);
		}
	}

	private function check_xmlrpc() {
		// Make an actual request to test if XML-RPC is responding
		$response = wp_remote_post(
			site_url( '/xmlrpc.php' ),
			array(
				'timeout' => 10,
				'body'    => '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>',
				'headers' => array( 'Content-Type' => 'text/xml' ),
			)
		);

		if ( is_wp_error( $response ) ) {
			return array(
				'result' => __( 'XML-RPC endpoint not accessible.', 'security-check-report' ),
				'score'  => 0,
			);
		}

		$code = wp_remote_retrieve_response_code( $response );
		$body = wp_remote_retrieve_body( $response );

		// 405 = Method Not Allowed (blocked)
		// 403 = Forbidden (blocked)
		// 200 with methodResponse = active and responding
		if ( $code === 405 || $code === 403 ) {
			return array(
				'result' => __( 'XML-RPC is blocked by server configuration.', 'security-check-report' ),
				'score'  => 0,
			);
		}

		$enabled = $code === 200 && strpos( $body, 'methodResponse' ) !== false;

		return array(
			'result' => $enabled
				? __( 'XML-RPC is enabled and responding to requests. Consider disabling if not needed.', 'security-check-report' )
				: __( 'XML-RPC is disabled or not responding.', 'security-check-report' ),
			'score'  => $enabled ? 5 : 0,
		);
	}

	private function check_xmlrpc_methods() {
		$enabled = $this->is_xmlrpc_methods_enabled();
		return array(
			'result' => $enabled
				? __( 'XML-RPC methods are enabled. This may be a security risk.', 'security-check-report' )
				: __( 'XML-RPC methods are disabled.', 'security-check-report' ),
			'score'  => $enabled ? 6 : 0,
		);
	}

	private function check_rest_api() {
		// Check if REST API exposes user information publicly
		$response = wp_remote_get(
			rest_url( 'wp/v2/users' ),
			array(
				'timeout' => 10,
				'headers' => array( 'Accept' => 'application/json' ),
			)
		);

		if ( is_wp_error( $response ) ) {
			return array(
				'result' => __( 'Could not check REST API status.', 'security-check-report' ),
				'score'  => 2,
			);
		}

		$code = wp_remote_retrieve_response_code( $response );
		$body = wp_remote_retrieve_body( $response );

		// Check if users endpoint returns data
		if ( $code === 200 ) {
			$users = json_decode( $body, true );
			if ( is_array( $users ) && ! empty( $users ) ) {
				$user_count = count( $users );
				return array(
					'result' => sprintf(
						/* translators: %d: number of users exposed */
						__( 'REST API exposes user information publicly (%d users visible). This allows user enumeration.', 'security-check-report' ),
						$user_count
					),
					'score'  => 6,
				);
			}
		}

		// 401/403 means protected
		if ( $code === 401 || $code === 403 ) {
			return array(
				'result' => __( 'REST API is active but user endpoint is properly protected.', 'security-check-report' ),
				'score'  => 0,
			);
		}

		// 404 or other - REST API might be disabled
		if ( $code === 404 ) {
			return array(
				'result' => __( 'REST API appears to be disabled or restricted.', 'security-check-report' ),
				'score'  => 0,
			);
		}

		return array(
			'result' => __( 'REST API is active. Ensure sensitive endpoints are properly protected.', 'security-check-report' ),
			'score'  => 2,
		);
	}

	private function check_file_edit() {
		$disabled = defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT;
		return array(
			'result' => $disabled
				? __( 'File editing in admin is disabled.', 'security-check-report' )
				: __( 'File editing in admin is enabled. This is a security risk.', 'security-check-report' ),
			'score'  => $disabled ? 0 : 8,
		);
	}

	private function check_directory_indexing() {
		$url      = site_url( '/wp-content/' );
		$response = wp_remote_get( $url, array( 'timeout' => 10 ) );
		if ( is_wp_error( $response ) ) {
			return array(
				'result' => __( 'Could not check directory indexing.', 'security-check-report' ),
				'score'  => 4,
			);
		}
		$body     = wp_remote_retrieve_body( $response );
		$disabled = strpos( $body, 'Index of /wp-content/' ) === false;
		return array(
			'result' => $disabled
				? __( 'Directory indexing is disabled.', 'security-check-report' )
				: __( 'Directory indexing is enabled.', 'security-check-report' ),
			'score'  => $disabled ? 0 : 4,
		);
	}

	private function check_ssl() {
		$enabled = is_ssl();
		return array(
			'result' => $enabled
				? __( 'SSL is enabled.', 'security-check-report' )
				: __( 'SSL is not enabled. This is a security risk.', 'security-check-report' ),
			'score'  => $enabled ? 0 : 8,
		);
	}

	private function check_server_headers() {
		$response = wp_remote_get( home_url() );
		if ( is_wp_error( $response ) ) {
			return array(
				'result' => __( 'Could not retrieve server headers.', 'security-check-report' ),
				'score'  => 9,
			);
		}
		$headers = wp_remote_retrieve_headers( $response );
		$missing = array();
		foreach ( $this->config['security_headers'] as $header ) {
			if ( empty( $headers[ $header ] ) ) {
				$missing[] = $header;
			}
		}
		return array(
			'result' => ! empty( $missing )
				? __( 'Missing security headers: ', 'security-check-report' ) . implode( ', ', $missing )
				: __( 'All critical security headers are present.', 'security-check-report' ),
			'score'  => ! empty( $missing ) ? 7 : 0,
		);
	}

	private function check_php_version_in_headers() {
		$response = wp_remote_get( home_url() );
		if ( is_wp_error( $response ) ) {
			return array(
				'result' => __( 'Could not retrieve response headers.', 'security-check-report' ),
				'score'  => 3,
			);
		}
		$headers = wp_remote_retrieve_headers( $response );
		$exposes = ! empty( $headers['x-powered-by'] ) && stripos( $headers['x-powered-by'], 'php' ) !== false;
		return array(
			'result' => $exposes
				? __( 'Response headers expose PHP version details. This is a security risk.', 'security-check-report' )
				: __( 'Response headers do not expose PHP version information.', 'security-check-report' ),
			'score'  => $exposes ? 8 : 0,
		);
	}

	private function check_legacy_meta_exposure() {
		$response = wp_remote_get( home_url(), array( 'timeout' => 10 ) );

		if ( is_wp_error( $response ) ) {
			return array(
				'result' => __( 'Could not fetch homepage to check meta information.', 'security-check-report' ),
				'score'  => 2,
			);
		}

		$body    = wp_remote_retrieve_body( $response );
		$exposed = array();

		// Check for Windows Live Writer manifest link
		if ( strpos( $body, 'wlwmanifest' ) !== false ) {
			$exposed[] = __( 'Windows Live Writer', 'security-check-report' );
		}

		// Check for RSD (Really Simple Discovery) link
		if ( strpos( $body, 'EditURI' ) !== false || strpos( $body, 'RSD' ) !== false ) {
			$exposed[] = __( 'RSD (Really Simple Discovery)', 'security-check-report' );
		}

		// Check for WordPress Generator meta tag
		if ( preg_match( '/<meta[^>]+name=["\']generator["\'][^>]+WordPress/i', $body ) ||
			preg_match( '/<meta[^>]+content=["\']WordPress[^"\']*["\'][^>]+name=["\']generator["\']/i', $body ) ) {
			$exposed[] = __( 'WordPress Generator Tag', 'security-check-report' );
		}

		// Check for shortlink
		if ( preg_match( '/<link[^>]+rel=["\']shortlink["\']/i', $body ) ) {
			$exposed[] = __( 'Shortlink', 'security-check-report' );
		}

		// Check for REST API discovery link
		if ( preg_match( '/<link[^>]+rel=["\']https:\/\/api\.w\.org\/["\']/i', $body ) ) {
			$exposed[] = __( 'REST API Discovery Link', 'security-check-report' );
		}

		if ( empty( $exposed ) ) {
			return array(
				'result' => __( 'No legacy meta information exposed. Site fingerprinting is minimized.', 'security-check-report' ),
				'score'  => 0,
			);
		}

		// Score based on number of exposed items (max 5)
		$score = min( count( $exposed ) * 1, 5 );

		return array(
			'result' => sprintf(
				/* translators: %s: list of exposed meta information */
				__( 'Exposed meta information: %s. This reveals WordPress installation details.', 'security-check-report' ),
				implode( ', ', $exposed )
			),
			'score'  => $score,
		);
	}

	private function check_unallowed_files() {
		$upload_dir = wp_upload_dir();
		$basedir    = $upload_dir['basedir'];

		if ( ! is_dir( $basedir ) || ! is_readable( $basedir ) ) {
			return array(
				'result' => __( 'Could not access uploads directory.', 'security-check-report' ),
				'score'  => 5,
			);
		}

		$dangerous_extensions = array( 'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar', 'htaccess', 'sh', 'cgi', 'pl' );
		$found                = array();
		$max_files            = 500;
		$checked              = 0;

		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $basedir, RecursiveDirectoryIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::SELF_FIRST
			);

			foreach ( $iterator as $file ) {
				if ( $checked >= $max_files ) {
					break;
				}

				if ( $file->isFile() ) {
					$extension = strtolower( $file->getExtension() );
					if ( in_array( $extension, $dangerous_extensions, true ) ) {
						$found[] = str_replace( $basedir . '/', '', $file->getPathname() );
					}
					++$checked;
				}
			}
		} catch ( Exception $e ) {
			return array(
				'result' => __( 'Could not complete uploads directory scan.', 'security-check-report' ),
				'score'  => 3,
			);
		}

		if ( ! empty( $found ) ) {
			/* translators: %d: number of additional files */
			$more_text = count( $found ) > 5 ? sprintf( __( ' and %d more', 'security-check-report' ), count( $found ) - 5 ) : '';
			$message   = sprintf(
				/* translators: %s: list of file names */
				__( 'Potentially dangerous files found in uploads: %s', 'security-check-report' ),
				implode( ', ', array_slice( $found, 0, 5 ) ) . $more_text
			);
			return array(
				'result' => $message,
				'score'  => 9,
			);
		}

		return array(
			'result' => __( 'No dangerous files found in uploads directory.', 'security-check-report' ),
			'score'  => 0,
		);
	}

	private function check_backup() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$backup_plugins = $this->config['backup_plugins'] ?? array();
		$active_backup  = array();

		foreach ( $backup_plugins as $plugin ) {
			if ( is_plugin_active( $plugin ) ) {
				$plugin_data     = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin );
				$active_backup[] = $plugin_data['Name'] ?? basename( $plugin );
			}
		}

		if ( ! empty( $active_backup ) ) {
			return array(
				/* translators: %s: name(s) of active backup plugin(s) */
				'result' => sprintf( __( 'Backup plugin active: %s', 'security-check-report' ), implode( ', ', $active_backup ) ),
				'score'  => 0,
			);
		}

		return array(
			'result' => __( 'No backup plugin detected. Regular backups are essential for recovery.', 'security-check-report' ),
			'score'  => 7,
		);
	}

	private function check_security_plugins() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$security_plugins = $this->config['security_plugins'] ?? array();
		$active_security  = array();

		foreach ( $security_plugins as $plugin ) {
			if ( is_plugin_active( $plugin ) ) {
				$plugin_data       = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin );
				$active_security[] = $plugin_data['Name'] ?? basename( $plugin );
			}
		}

		if ( ! empty( $active_security ) ) {
			return array(
				/* translators: %s: name(s) of active security plugin(s) */
				'result' => sprintf( __( 'Security plugin active: %s', 'security-check-report' ), implode( ', ', $active_security ) ),
				'score'  => 0,
			);
		}

		return array(
			'result' => __( 'No security plugin detected. Consider installing a security plugin.', 'security-check-report' ),
			'score'  => 6,
		);
	}

	private function check_db_prefix() {
		global $wpdb;
		$prefix = $wpdb->prefix;

		if ( $prefix === 'wp_' ) {
			return array(
				'result' => __( 'Default database prefix "wp_" is in use. Consider using a custom prefix for better security.', 'security-check-report' ),
				'score'  => 5,
			);
		}

		return array(
			/* translators: %s: database table prefix */
			'result' => sprintf( __( 'Custom database prefix "%s" is in use.', 'security-check-report' ), esc_html( $prefix ) ),
			'score'  => 0,
		);
	}

	private function check_brute_force() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$brute_force_plugins = $this->config['brute_force_plugins'] ?? array();
		$active_protection   = array();

		foreach ( $brute_force_plugins as $plugin ) {
			if ( is_plugin_active( $plugin ) ) {
				$plugin_data         = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin );
				$active_protection[] = $plugin_data['Name'] ?? basename( $plugin );
			}
		}

		if ( ! empty( $active_protection ) ) {
			return array(
				/* translators: %s: name(s) of active brute-force protection plugin(s) */
				'result' => sprintf( __( 'Brute-force protection active via: %s', 'security-check-report' ), implode( ', ', array_slice( $active_protection, 0, 2 ) ) ),
				'score'  => 0,
			);
		}

		return array(
			'result' => __( 'No brute-force protection detected. Consider implementing login protection.', 'security-check-report' ),
			'score'  => 8,
		);
	}

	private function check_login_attempts() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$login_plugins     = $this->config['login_protection_plugins'] ?? array();
		$active_protection = array();

		foreach ( $login_plugins as $plugin ) {
			if ( is_plugin_active( $plugin ) ) {
				$plugin_data         = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin );
				$active_protection[] = $plugin_data['Name'] ?? basename( $plugin );
			}
		}

		if ( ! empty( $active_protection ) ) {
			return array(
				/* translators: %s: name(s) of active login protection plugin(s) */
				'result' => sprintf( __( 'Login attempt limiting active via: %s', 'security-check-report' ), implode( ', ', array_slice( $active_protection, 0, 2 ) ) ),
				'score'  => 0,
			);
		}

		return array(
			'result' => __( 'No login attempt limiting detected. Consider limiting failed login attempts.', 'security-check-report' ),
			'score'  => 7,
		);
	}

	private function check_for_malware() {
		$wp_filesystem = $this->get_wp_filesystem();
		if ( ! $wp_filesystem ) {
			return array(
				'result' => __( 'Could not initialize filesystem for malware scan.', 'security-check-report' ),
				'score'  => 5,
			);
		}

		$signatures = $this->config['malware_signatures'];
		$core_files = array_map(
			function ( $file ) {
				return realpath( ABSPATH . $file );
			},
			$this->config['ignore_wp_core_files']
		);
		$core_files = array_filter( $core_files );

		$paths = array(
			ABSPATH . 'index.php',
			ABSPATH . 'wp-config.php',
			ABSPATH . 'wp-includes/',
			ABSPATH . 'wp-admin/',
		);

		$found     = array();
		$max_files = 1000;
		$scanned   = 0;

		foreach ( $paths as $path ) {
			if ( $scanned >= $max_files ) {
				break;
			}

			if ( is_dir( $path ) ) {
				try {
					$iterator = new RecursiveIteratorIterator(
						new RecursiveDirectoryIterator( $path, RecursiveDirectoryIterator::SKIP_DOTS ),
						RecursiveIteratorIterator::SELF_FIRST
					);

					foreach ( $iterator as $file ) {
						if ( $scanned >= $max_files ) {
							break;
						}

						$fpath = realpath( $file->getPathname() );
						if ( $file->isFile() && $file->getExtension() === 'php' && ! in_array( $fpath, $core_files, true ) ) {
							$contents = $wp_filesystem->get_contents( $fpath );
							if ( $contents !== false ) {
								foreach ( $signatures as $sig ) {
									if ( strpos( $contents, $sig ) !== false ) {
										$found[] = str_replace( ABSPATH, '', $fpath );
										break;
									}
								}
							}
							++$scanned;
						}
					}
				} catch ( Exception $e ) {
					continue;
				}
			} elseif ( is_file( $path ) ) {
				$fpath = realpath( $path );
				if ( ! in_array( $fpath, $core_files, true ) ) {
					$contents = $wp_filesystem->get_contents( $fpath );
					if ( $contents !== false ) {
						foreach ( $signatures as $sig ) {
							if ( strpos( $contents, $sig ) !== false ) {
								$found[] = str_replace( ABSPATH, '', $path );
								break;
							}
						}
					}
					++$scanned;
				}
			}
		}

		if ( ! empty( $found ) ) {
			$more_text = count( $found ) > 10
				/* translators: %d: number of additional files with malware signatures */
				? sprintf( __( ' and %d more files', 'security-check-report' ), count( $found ) - 10 )
				: '';
			$message = __( 'Potential malware signatures found in: ', 'security-check-report' )
				. implode( ', ', array_slice( $found, 0, 10 ) ) . $more_text;
			return array(
				'result' => $message,
				'score'  => 9,
			);
		}

		return array(
			'result' => __( 'No malware signatures found.', 'security-check-report' ),
			'score'  => 0,
		);
	}

	private function get_wp_filesystem() {
		global $wp_filesystem;

		if ( ! function_exists( 'WP_Filesystem' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}

		if ( ! WP_Filesystem() ) {
			return null;
		}

		return $wp_filesystem;
	}

	private function check_other_wp_installs() {
		$parent_dir      = dirname( ABSPATH );
		$current_abspath = realpath( ABSPATH );
		$installs        = array();

		if ( ! is_dir( $parent_dir ) || ! is_readable( $parent_dir ) ) {
			return array(
				'result' => __( 'Could not scan for other WordPress installations.', 'security-check-report' ),
				'score'  => 0,
			);
		}

		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $parent_dir, RecursiveDirectoryIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::SELF_FIRST
			);
			$iterator->setMaxDepth( 3 );

			foreach ( $iterator as $file ) {
				if ( $file->isFile() && $file->getFilename() === 'wp-config.php' ) {
					$install_path = realpath( dirname( $file->getPathname() ) );
					if ( $install_path !== $current_abspath ) {
						$installs[] = $install_path;
					}
				}
			}
		} catch ( Exception $e ) {
			return array(
				'result' => __( 'Could not complete scan for other WordPress installations.', 'security-check-report' ),
				'score'  => 0,
			);
		}

		$count = count( $installs );
		if ( $count > 0 ) {
			$message = sprintf(
				/* translators: %d: number of other WordPress installations found */
				_n(
					'%d other WordPress installation found. Please ensure all installations are secured and updated.',
					'%d other WordPress installations found. Please ensure all installations are secured and updated.',
					$count,
					'security-check-report'
				),
				$count
			);
			return array(
				'result' => $message,
				'score'  => min( $count * 2, 6 ),
			);
		}

		return array(
			'result' => __( 'No other WordPress installations found.', 'security-check-report' ),
			'score'  => 0,
		);
	}

	private function check_automatic_core_updates() {
		$update = defined( 'WP_AUTO_UPDATE_CORE' ) ? WP_AUTO_UPDATE_CORE : 'minor';
		return array(
			'result' => $update === 'minor'
				? __( 'Automatic core updates are enabled.', 'security-check-report' )
				: __( 'Automatic core updates are not enabled. This is a security risk.', 'security-check-report' ),
			'score'  => $update === 'minor' ? 0 : 8,
		);
	}

	private function check_security_keys_salts() {
		$wp_filesystem = $this->get_wp_filesystem();
		$file          = ABSPATH . 'wp-config.php';

		$keys = array(
			'AUTH_KEY',
			'SECURE_AUTH_KEY',
			'LOGGED_IN_KEY',
			'NONCE_KEY',
			'AUTH_SALT',
			'SECURE_AUTH_SALT',
			'LOGGED_IN_SALT',
			'NONCE_SALT',
		);

		$pattern = "/define\(\s*['\"](%s)['\"]\s*,\s*['\"](.+)['\"]\s*\)/";
		$values  = array();

		foreach ( $keys as $key ) {
			$values[ $key ] = '';
		}

		if ( ! file_exists( $file ) ) {
			return array(
				'result' => __( 'wp-config.php not found.', 'security-check-report' ),
				'score'  => 10,
			);
		}

		$contents = $wp_filesystem ? $wp_filesystem->get_contents( $file ) : false;
		if ( $contents === false ) {
			return array(
				'result' => __( 'Could not read wp-config.php for security keys check.', 'security-check-report' ),
				'score'  => 5,
			);
		}

		foreach ( $keys as $key ) {
			if ( preg_match( sprintf( $pattern, preg_quote( $key, '/' ) ), $contents, $matches ) ) {
				$values[ $key ] = trim( $matches[2] );
			}
		}

		$weak_patterns = array(
			'put your unique phrase here',
			'',
		);

		$incorrect = array();
		foreach ( $keys as $key ) {
			$value = $values[ $key ];
			if ( empty( $value ) || strlen( $value ) < 32 ) {
				$incorrect[] = $key;
			} else {
				foreach ( $weak_patterns as $weak ) {
					if ( ! empty( $weak ) && stripos( $value, $weak ) !== false ) {
						$incorrect[] = $key;
						break;
					}
				}
			}
		}

		$modified = filemtime( $file );
		$age      = time() - $modified;
		$max_age  = 6 * 30 * 24 * 60 * 60;
		$score    = ! empty( $incorrect ) ? 8 : 0;

		if ( $age > $max_age ) {
			$score = max( $score, 5 );
		}

		$result = ! empty( $incorrect )
			? __( 'Weak or missing security keys: ', 'security-check-report' ) . implode( ', ', $incorrect )
			: __( 'Security keys and salts are properly set.', 'security-check-report' );

		$result .= $age > $max_age
			? ' ' . __( 'Keys have not been updated in over 6 months.', 'security-check-report' )
			: ' ' . __( 'Keys have been updated recently.', 'security-check-report' );

		return array(
			'result' => $result,
			'score'  => $score,
		);
	}

	private function check_unwanted_files_root() {
		$files = $this->config['unwanted_files'];
		$found = array();
		foreach ( $files as $file ) {
			if ( file_exists( ABSPATH . $file ) ) {
				$found[] = $file;
			}
		}
		return array(
			'result' => ! empty( $found )
				? __( 'Unwanted files in root: ', 'security-check-report' ) . implode( ', ', $found )
				: __( 'No unwanted files found in root.', 'security-check-report' ),
			'score'  => ! empty( $found ) ? 3 : 0,
		);
	}

	private function check_directory_permissions() {
		$dirs     = array( 'wp-content', 'wp-includes', 'wp-admin' );
		$insecure = array();
		foreach ( $dirs as $dir ) {
			$path = ABSPATH . $dir;
			if ( is_dir( $path ) && substr( sprintf( '%o', fileperms( $path ) ), -4 ) !== '0755' ) {
				$insecure[] = $dir;
			}
		}
		return array(
			'result' => ! empty( $insecure )
				? __( 'Insecure permissions for: ', 'security-check-report' ) . implode( ', ', $insecure )
				: __( 'All critical directories have secure permissions.', 'security-check-report' ),
			'score'  => ! empty( $insecure ) ? 7 : 0,
		);
	}

	private function check_php_version_support() {
		$current   = phpversion();
		$supported = version_compare( $current, '8.2', '>=' );

		if ( $supported ) {
			return array(
				'result' => __( 'PHP version is supported.', 'security-check-report' ),
				'score'  => 0,
			);
		}

		return array(
			/* translators: %s: current PHP version */
			'result' => sprintf( __( 'PHP version %s is not supported. Upgrade to at least 8.2.', 'security-check-report' ), $current ),
			'score'  => 8,
		);
	}

	private function check_database_user_privileges() {
		global $wpdb;

		$cache_key = 'cascr_db_grants';
		$grants    = wp_cache_get( $cache_key );

		if ( false === $grants ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Necessary for checking user privileges
			$grants = $wpdb->get_results( 'SHOW GRANTS FOR CURRENT_USER', ARRAY_A );
			wp_cache_set( $cache_key, $grants, '', 300 );
		}

		$insecure = false;
		foreach ( $grants as $grant ) {
			foreach ( $grant as $line ) {
				if ( strpos( $line, 'ALL PRIVILEGES' ) !== false || strpos( $line, 'GRANT OPTION' ) !== false ) {
					$insecure = true;
					break 2;
				}
			}
		}
		return array(
			'result' => $insecure
				? __( 'Database user has excessive privileges.', 'security-check-report' )
				: __( 'Database user privileges are secure.', 'security-check-report' ),
			'score'  => $insecure ? 9 : 0,
		);
	}

	private function check_database_structure() {
		global $wpdb;

		$cache_key = 'cascr_table_status';
		$tables    = wp_cache_get( $cache_key );

		if ( false === $tables ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Necessary for checking table engines
			$tables = $wpdb->get_results( 'SHOW TABLE STATUS', ARRAY_A );
			wp_cache_set( $cache_key, $tables, '', 300 );
		}

		$insecure = array();
		foreach ( $tables as $table ) {
			if ( $table['Engine'] !== 'InnoDB' ) {
				$insecure[] = $table['Name'];
			}
		}
		return array(
			'result' => ! empty( $insecure )
				? __( 'Tables not using InnoDB: ', 'security-check-report' ) . implode( ', ', $insecure )
				: __( 'All tables use InnoDB.', 'security-check-report' ),
			'score'  => ! empty( $insecure ) ? 6 : 0,
		);
	}

	private function check_outdated_libraries() {
		global $wp_scripts;
		$jquery_version = isset( $wp_scripts->registered['jquery']->ver ) ? $wp_scripts->registered['jquery']->ver : 'unknown';
		$outdated       = array();
		if ( version_compare( $jquery_version, '3.5.1', '<' ) ) {
			$outdated[] = 'jQuery';
		}
		return array(
			'result' => ! empty( $outdated )
				? __( 'Outdated libraries: ', 'security-check-report' ) . implode( ', ', $outdated )
				: __( 'All libraries are up to date.', 'security-check-report' ),
			'score'  => ! empty( $outdated ) ? 7 : 0,
		);
	}

	private function check_user_enumeration() {
		$methods    = array();
		$vulnerable = false;

		// Method 1: ?author=1 Redirect check
		$response = wp_remote_get(
			home_url( '?author=1' ),
			array(
				'timeout'     => 10,
				'redirection' => 0, // Don't follow redirects
			)
		);

		if ( ! is_wp_error( $response ) ) {
			$code     = wp_remote_retrieve_response_code( $response );
			$location = wp_remote_retrieve_header( $response, 'location' );

			// 301/302 redirect to /author/username = enumeration possible
			if ( ( $code === 301 || $code === 302 ) && ! empty( $location ) && strpos( $location, '/author/' ) !== false ) {
				$methods[]  = __( '?author=N parameter', 'security-check-report' );
				$vulnerable = true;
			}
		}

		// Method 2: REST API /wp/v2/users endpoint
		$response = wp_remote_get(
			rest_url( 'wp/v2/users' ),
			array(
				'timeout' => 10,
				'headers' => array( 'Accept' => 'application/json' ),
			)
		);

		if ( ! is_wp_error( $response ) ) {
			$code = wp_remote_retrieve_response_code( $response );
			if ( $code === 200 ) {
				$body  = wp_remote_retrieve_body( $response );
				$users = json_decode( $body, true );
				if ( is_array( $users ) && ! empty( $users ) ) {
					$methods[]  = __( 'REST API /users endpoint', 'security-check-report' );
					$vulnerable = true;
				}
			}
		}

		// Method 3: oEmbed endpoint
		$response = wp_remote_get(
			home_url( '?rest_route=/oembed/1.0/embed&url=' . rawurlencode( home_url() ) ),
			array( 'timeout' => 10 )
		);

		if ( ! is_wp_error( $response ) ) {
			$code = wp_remote_retrieve_response_code( $response );
			if ( $code === 200 ) {
				$body = wp_remote_retrieve_body( $response );
				if ( strpos( $body, 'author_name' ) !== false || strpos( $body, 'author_url' ) !== false ) {
					$methods[]  = __( 'oEmbed endpoint', 'security-check-report' );
					$vulnerable = true;
				}
			}
		}

		// Calculate score based on number of enumeration methods available
		if ( ! $vulnerable ) {
			return array(
				'result' => __( 'User enumeration is protected. No common enumeration methods are available.', 'security-check-report' ),
				'score'  => 0,
			);
		}

		$method_count = count( $methods );
		$score        = $method_count >= 3 ? 8 : ( $method_count >= 2 ? 7 : 6 );

		return array(
			'result' => sprintf(
				/* translators: %s: list of enumeration methods */
				__( 'User enumeration possible via: %s. Attackers can discover valid usernames.', 'security-check-report' ),
				implode( ', ', $methods )
			),
			'score'  => $score,
		);
	}

	private function get_latest_wordpress_version() {
		$response = wp_remote_get( 'https://api.wordpress.org/core/version-check/1.7/' );
		if ( is_wp_error( $response ) ) {
			return '5.8.1';
		}
		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );
		return isset( $data['offers'][0]['version'] ) ? $data['offers'][0]['version'] : '5.8.1';
	}

	private function is_plugin_up_to_date( $plugin_file ) {
		$data    = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin_file );
		$current = $data['Version'];
		$latest  = $this->get_latest_plugin_version( $data['TextDomain'] );
		return version_compare( $current, $latest, '>=' );
	}

	private function is_theme_up_to_date( $theme_data ) {
		$current = $theme_data->get( 'Version' );
		$latest  = $this->get_latest_theme_version( $theme_data->get( 'TextDomain' ) );
		return version_compare( $current, $latest, '>=' );
	}

	private function get_latest_plugin_version( $text_domain ) {
		$response = wp_remote_get( 'https://api.wordpress.org/plugins/info/1.0/' . $text_domain . '.json' );
		if ( is_wp_error( $response ) ) {
			return '1.0.0';
		}
		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );
		return isset( $data['version'] ) ? $data['version'] : '1.0.0';
	}

	private function get_latest_theme_version( $text_domain ) {
		$response = wp_remote_get( 'https://api.wordpress.org/themes/info/1.0/' . $text_domain . '.json' );
		if ( is_wp_error( $response ) ) {
			return '1.0.0';
		}
		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );
		return isset( $data['version'] ) ? $data['version'] : '1.0.0';
	}

	private function is_file_outdated( $file, $months = 6 ) {
		$modified  = filemtime( $file );
		$threshold = $months * 30 * 24 * 60 * 60;
		return ( time() - $modified ) > $threshold;
	}

	private function check_php_execution() {
		$wp_filesystem = $this->get_wp_filesystem();
		if ( ! $wp_filesystem ) {
			return array(
				'result' => __( 'Could not initialize filesystem for PHP execution check.', 'security-check-report' ),
				'score'  => 5,
			);
		}

		$upload_dir = wp_upload_dir();
		$dir        = $upload_dir['basedir'];
		$url        = $upload_dir['baseurl'];

		$unique_id    = wp_generate_password( 12, false );
		$test_php     = $dir . '/cascr-test-' . $unique_id . '.php';
		$test_php_url = $url . '/cascr-test-' . $unique_id . '.php';
		$php_content  = '<?php echo "CASCR_PHP_EXEC_TEST"; ?>';

		$created = $wp_filesystem->put_contents( $test_php, $php_content, FS_CHMOD_FILE );
		if ( ! $created ) {
			return array(
				'result' => __( 'Could not create test file for PHP execution check.', 'security-check-report' ),
				'score'  => 3,
			);
		}

		$php_response = wp_remote_get(
			$test_php_url,
			array(
				'timeout' => 10,
			)
		);

		$wp_filesystem->delete( $test_php );

		if ( is_wp_error( $php_response ) ) {
			return array(
				'result' => __( 'PHP execution in uploads is blocked (file not accessible).', 'security-check-report' ),
				'score'  => 0,
			);
		}

		$status_code = wp_remote_retrieve_response_code( $php_response );
		if ( $status_code === 403 || $status_code === 404 ) {
			return array(
				'result' => __( 'PHP execution in uploads is blocked.', 'security-check-report' ),
				'score'  => 0,
			);
		}

		$body         = wp_remote_retrieve_body( $php_response );
		$php_executed = strpos( $body, 'CASCR_PHP_EXEC_TEST' ) !== false;

		return array(
			'result' => $php_executed
				? __( 'PHP execution is allowed in uploads directory. This is a security risk!', 'security-check-report' )
				: __( 'PHP execution in uploads is blocked.', 'security-check-report' ),
			'score'  => $php_executed ? 9 : 0,
		);
	}

	private function is_xmlrpc_methods_enabled() {
		$response = wp_remote_get( site_url( '/xmlrpc.php' ) );
		if ( is_wp_error( $response ) ) {
			return false;
		}
		$body = wp_remote_retrieve_body( $response );
		return strpos( $body, 'XML-RPC server accepts POST requests only' ) !== false;
	}

	private function is_strong_passwords_enforced() {
		$plugins = $this->config['password_plugins'];
		foreach ( $plugins as $plugin ) {
			if ( is_plugin_active( $plugin ) ) {
				return true;
			}
		}
		return false;
	}

	private function is_two_factor_enabled() {
		$plugins = $this->config['two_factor_plugins'];
		foreach ( $plugins as $plugin ) {
			if ( is_plugin_active( $plugin ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Check for Application Passwords usage (WordPress 5.6+).
	 *
	 * Application Passwords provide programmatic access to WordPress and should be monitored.
	 */
	private function check_application_passwords() {
		// Check if Application Passwords feature is available (WP 5.6+)
		if ( ! function_exists( 'wp_is_application_passwords_available' ) ) {
			return array(
				'result' => __( 'Application Passwords feature not available (requires WordPress 5.6+).', 'security-check-report' ),
				'score'  => 0,
			);
		}

		if ( ! wp_is_application_passwords_available() ) {
			return array(
				'result' => __( 'Application Passwords are disabled on this site.', 'security-check-report' ),
				'score'  => 0,
			);
		}

		// Check for users with Application Passwords (admins and editors)
		$users              = get_users( array( 'role__in' => array( 'administrator', 'editor' ) ) );
		$with_app_passwords = array();

		foreach ( $users as $user ) {
			if ( class_exists( 'WP_Application_Passwords' ) ) {
				$passwords = WP_Application_Passwords::get_user_application_passwords( $user->ID );
				if ( ! empty( $passwords ) ) {
					$with_app_passwords[] = $user->user_login . ' (' . count( $passwords ) . ')';
				}
			}
		}

		if ( empty( $with_app_passwords ) ) {
			return array(
				'result' => __( 'No Application Passwords in use by administrators or editors.', 'security-check-report' ),
				'score'  => 0,
			);
		}

		return array(
			'result' => sprintf(
				/* translators: %s: list of users with Application Passwords and count */
				__( 'Users with Application Passwords: %s. Monitor these for security.', 'security-check-report' ),
				implode( ', ', array_slice( $with_app_passwords, 0, 5 ) )
			),
			'score'  => 4, // Informational - not critical but should be monitored
		);
	}

	/**
	 * Check WP-Cron security configuration.
	 *
	 * Examines whether WP-Cron is properly configured and looks for suspicious cron jobs.
	 */
	private function check_wp_cron_security() {
		$issues = array();

		// Check if DISABLE_WP_CRON is set (recommended for production with server cron)
		if ( ! defined( 'DISABLE_WP_CRON' ) || ! DISABLE_WP_CRON ) {
			$issues[] = __( 'WP-Cron runs on page loads (consider using server cron for better performance)', 'security-check-report' );
		}

		// Check for suspicious cron jobs
		$crons            = _get_cron_array();
		$suspicious_hooks = array();

		if ( is_array( $crons ) ) {
			foreach ( $crons as $timestamp => $hooks ) {
				if ( ! is_array( $hooks ) ) {
					continue;
				}
				foreach ( $hooks as $hook => $args ) {
					// Suspicious: random-looking hook names (8-12 lowercase letters only)
					if ( preg_match( '/^[a-z]{8,12}$/', $hook ) ) {
						$suspicious_hooks[] = $hook;
					}
					// Suspicious: hooks with base64 or eval in name
					if ( stripos( $hook, 'base64' ) !== false || stripos( $hook, 'eval' ) !== false ) {
						$suspicious_hooks[] = $hook;
					}
				}
			}
		}

		if ( ! empty( $suspicious_hooks ) ) {
			$issues[] = sprintf(
				/* translators: %s: list of suspicious cron hooks */
				__( 'Suspicious cron jobs detected: %s', 'security-check-report' ),
				implode( ', ', array_slice( array_unique( $suspicious_hooks ), 0, 3 ) )
			);
		}

		if ( empty( $issues ) ) {
			return array(
				'result' => __( 'WP-Cron configuration is secure. No suspicious scheduled tasks found.', 'security-check-report' ),
				'score'  => 0,
			);
		}

		// Calculate score based on issues
		$score = count( $issues ) > 1 ? 7 : 4;
		if ( ! empty( $suspicious_hooks ) ) {
			$score = max( $score, 8 ); // Suspicious cron jobs are more serious
		}

		return array(
			'result' => implode( '; ', $issues ),
			'score'  => $score,
		);
	}

	/**
	 * Check if debug.log is publicly accessible.
	 *
	 * The debug.log file can contain sensitive information and should not be publicly accessible.
	 */
	private function check_debug_log_exposure() {
		$log_file = WP_CONTENT_DIR . '/debug.log';
		$log_url  = content_url( '/debug.log' );

		// Check if the file exists
		if ( ! file_exists( $log_file ) ) {
			return array(
				'result' => __( 'No debug.log file found. This is the recommended state for production.', 'security-check-report' ),
				'score'  => 0,
			);
		}

		// Check if file is publicly accessible
		$response = wp_remote_head( $log_url, array( 'timeout' => 5 ) );

		if ( is_wp_error( $response ) ) {
			return array(
				'result' => __( 'debug.log exists but accessibility could not be verified.', 'security-check-report' ),
				'score'  => 3,
			);
		}

		$code = wp_remote_retrieve_response_code( $response );

		if ( $code === 200 ) {
			// Get file size for additional context
			$file_size = filesize( $log_file );
			$size_text = $file_size > 1048576
				? sprintf( '%.1f MB', $file_size / 1048576 )
				: sprintf( '%.1f KB', $file_size / 1024 );

			return array(
				'result' => sprintf(
					/* translators: %s: file size */
					__( 'CRITICAL: debug.log (%s) is publicly accessible! This exposes sensitive error information, file paths, and potentially credentials.', 'security-check-report' ),
					$size_text
				),
				'score'  => 9,
			);
		}

		if ( $code === 403 || $code === 404 ) {
			return array(
				'result' => __( 'debug.log exists but is properly protected from public access. Consider deleting it periodically.', 'security-check-report' ),
				'score'  => 2,
			);
		}

		return array(
			'result' => __( 'debug.log exists. Ensure it is not publicly accessible and delete regularly.', 'security-check-report' ),
			'score'  => 3,
		);
	}

	/**
	 * Check CORS (Cross-Origin Resource Sharing) configuration.
	 *
	 * Overly permissive CORS settings can be a security risk.
	 */
	private function check_cors_configuration() {
		$response = wp_remote_get( home_url(), array( 'timeout' => 10 ) );

		if ( is_wp_error( $response ) ) {
			return array(
				'result' => __( 'Could not check CORS configuration.', 'security-check-report' ),
				'score'  => 2,
			);
		}

		$headers = wp_remote_retrieve_headers( $response );
		$acao    = isset( $headers['access-control-allow-origin'] ) ? $headers['access-control-allow-origin'] : '';
		$acac    = isset( $headers['access-control-allow-credentials'] ) ? $headers['access-control-allow-credentials'] : '';

		// Wildcard origin with credentials is the most dangerous
		if ( $acao === '*' && strtolower( $acac ) === 'true' ) {
			return array(
				'result' => __( 'CRITICAL: CORS allows all origins (*) with credentials. This is a severe security misconfiguration.', 'security-check-report' ),
				'score'  => 9,
			);
		}

		// Wildcard origin without credentials is still risky
		if ( $acao === '*' ) {
			return array(
				'result' => __( 'CORS allows all origins (*). This may expose your site to cross-origin attacks.', 'security-check-report' ),
				'score'  => 6,
			);
		}

		// Specific origin configured
		if ( ! empty( $acao ) ) {
			return array(
				'result' => sprintf(
					/* translators: %s: allowed origin domain */
					__( 'CORS is configured for specific origin: %s', 'security-check-report' ),
					esc_html( $acao )
				),
				'score'  => 0,
			);
		}

		// No CORS headers - this is fine for most sites
		return array(
			'result' => __( 'No CORS headers configured. This is secure for most use cases.', 'security-check-report' ),
			'score'  => 0,
		);
	}

	/**
	 * Check WordPress core file integrity using official checksums.
	 *
	 * Compares core files against WordPress.org checksums to detect modifications.
	 */
	private function check_core_file_integrity() {
		global $wp_version;

		$locale = get_locale();

		// Fetch checksums from WordPress.org API
		$response = wp_remote_get(
			sprintf(
				'https://api.wordpress.org/core/checksums/1.0/?version=%s&locale=%s',
				$wp_version,
				$locale
			),
			array( 'timeout' => 15 )
		);

		if ( is_wp_error( $response ) ) {
			return array(
				'result' => __( 'Could not connect to WordPress.org to verify file integrity.', 'security-check-report' ),
				'score'  => 3,
			);
		}

		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );

		if ( empty( $data['checksums'] ) ) {
			// Try without locale (fallback to en_US)
			$response = wp_remote_get(
				sprintf( 'https://api.wordpress.org/core/checksums/1.0/?version=%s', $wp_version ),
				array( 'timeout' => 15 )
			);

			if ( is_wp_error( $response ) ) {
				return array(
					'result' => __( 'Could not retrieve checksums for this WordPress version.', 'security-check-report' ),
					'score'  => 3,
				);
			}

			$body = wp_remote_retrieve_body( $response );
			$data = json_decode( $body, true );

			if ( empty( $data['checksums'] ) ) {
				return array(
					'result' => __( 'No checksums available for this WordPress version.', 'security-check-report' ),
					'score'  => 2,
				);
			}
		}

		$modified  = array();
		$missing   = array();
		$checked   = 0;
		$max_check = 500; // Limit to prevent timeout

		foreach ( $data['checksums'] as $file => $checksum ) {
			if ( $checked >= $max_check ) {
				break;
			}

			$path = ABSPATH . $file;

			// Skip wp-content files (themes/plugins are checked separately)
			if ( strpos( $file, 'wp-content/' ) === 0 ) {
				continue;
			}

			if ( ! file_exists( $path ) ) {
				// Only flag missing core files, not optional ones
				if ( strpos( $file, 'wp-admin/' ) === 0 || strpos( $file, 'wp-includes/' ) === 0 ) {
					$missing[] = $file;
				}
				continue;
			}

			$file_hash = md5_file( $path );
			if ( $file_hash !== $checksum ) {
				$modified[] = $file;
			}

			++$checked;
		}

		$total_issues = count( $modified ) + count( $missing );

		if ( $total_issues === 0 ) {
			return array(
				'result' => sprintf(
					/* translators: %d: number of files checked */
					__( 'WordPress core file integrity verified. %d files checked against official checksums.', 'security-check-report' ),
					$checked
				),
				'score'  => 0,
			);
		}

		$issues = array();

		if ( ! empty( $modified ) ) {
			$display_files = array_slice( $modified, 0, 5 );
			$more_count    = count( $modified ) - 5;
			$issues[]      = sprintf(
				/* translators: %1$d: number of modified files, %2$s: list of files */
				__( '%1$d modified: %2$s', 'security-check-report' ),
				count( $modified ),
				implode( ', ', $display_files ) . ( $more_count > 0 ? sprintf( ' +%d more', $more_count ) : '' )
			);
		}

		if ( ! empty( $missing ) ) {
			$display_files = array_slice( $missing, 0, 3 );
			$issues[]      = sprintf(
				/* translators: %1$d: number of missing files, %2$s: list of files */
				__( '%1$d missing: %2$s', 'security-check-report' ),
				count( $missing ),
				implode( ', ', $display_files )
			);
		}

		// Score based on number and type of issues
		$score = min( 9, 5 + $total_issues );
		if ( count( $modified ) > 5 ) {
			$score = 9; // Many modified files is very concerning
		}

		return array(
			'result' => sprintf(
				/* translators: %s: list of integrity issues */
				__( 'Core file integrity issues detected: %s. This may indicate tampering or incomplete updates.', 'security-check-report' ),
				implode( '; ', $issues )
			),
			'score'  => $score,
		);
	}
}

new CASCR_SecurityCheck();
