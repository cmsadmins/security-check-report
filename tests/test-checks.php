<?php
/**
 * Behaviour of the individual checks.
 *
 * The old suite only asserted that a score was numeric and between 0 and 10,
 * which a check returning a constant would also have satisfied. These tests set
 * a state and assert the verdict that follows from it.
 *
 * @package CmsAdmins\SecurityCheck
 */

class Test_CASCR_Checks extends WP_UnitTestCase {

	public function set_up() {
		parent::set_up();
		CASCR_Http::reset();
		add_filter( 'pre_http_request', array( $this, 'mock_http' ), 10, 3 );
	}

	public function tear_down() {
		remove_filter( 'pre_http_request', array( $this, 'mock_http' ), 10 );
		CASCR_Http::reset();
		CASCR_Registry::reset();

		foreach ( CASCR_Store::option_names() as $option ) {
			delete_option( $option );
		}

		parent::tear_down();
	}

	/**
	 * Answers every outbound request with an empty 200, so the suite is offline
	 * and deterministic.
	 *
	 * @param mixed  $preempt Short circuit value.
	 * @param array  $args    Request arguments.
	 * @param string $url     Requested URL.
	 * @return array
	 */
	public function mock_http( $preempt, $args, $url ) {
		unset( $preempt, $args, $url );

		return array(
			'headers'  => array(),
			'body'     => '',
			'response' => array(
				'code'    => 200,
				'message' => 'OK',
			),
			'cookies'  => array(),
			'filename' => null,
		);
	}

	/* ---------------------------------------------------------------------
	 * Shape
	 * ------------------------------------------------------------------- */

	public function test_every_check_returns_a_valid_result() {
		foreach ( CASCR_Registry::ids() as $id ) {
			$result = CASCR_Runner::run( $id );

			$this->assertIsArray( $result, "Check '{$id}' returned no array." );
			$this->assertContains(
				$result['status'],
				array( 'pass', 'warn', 'fail', 'inconclusive' ),
				"Check '{$id}' returned an unknown status."
			);
			$this->assertIsString( $result['summary'], "Check '{$id}' has a non-string summary." );
			$this->assertNotSame( '', $result['summary'], "Check '{$id}' has an empty summary." );
			$this->assertIsArray( $result['items'], "Check '{$id}' has non-array items." );
			$this->assertGreaterThanOrEqual( 0, $result['score'] );
			$this->assertLessThanOrEqual( 10, $result['score'] );
		}
	}

	/**
	 * The score and the status must always agree, otherwise the grade and the
	 * badge tell the reader two different things.
	 */
	public function test_status_and_score_never_contradict_each_other() {
		$cases = array(
			CASCR_Result::pass( 'ok' ),
			CASCR_Result::warn( 'hmm', 5 ),
			CASCR_Result::fail( 'bad', 9 ),
			CASCR_Result::inconclusive( 'unknown' ),
		);

		foreach ( $cases as $result ) {
			if ( in_array( $result['status'], array( 'pass', 'inconclusive' ), true ) ) {
				$this->assertSame( 0, $result['score'] );
			}
		}

		$this->assertSame( 0, CASCR_Result::pass( 'ok' )['score'] );
		$this->assertSame( 10, CASCR_Result::fail( 'bad', 99 )['score'], 'Scores are clamped to 10.' );
		$this->assertSame( 0, CASCR_Result::warn( 'hmm', -5 )['score'], 'Scores are clamped to 0.' );
	}

	public function test_a_check_that_throws_is_reported_as_inconclusive() {
		add_filter(
			'cascr_registry',
			function ( $tests ) {
				$tests['wp_debug']['callback'] = function () {
					throw new RuntimeException( 'boom' );
				};

				return $tests;
			}
		);

		CASCR_Registry::reset();

		$result = CASCR_Runner::run( 'wp_debug' );

		$this->assertSame( 'inconclusive', $result['status'] );
	}

	public function test_results_can_be_filtered() {
		add_filter(
			'cascr_test_result',
			function ( $result, $id ) {
				return 'wp_debug' === $id ? CASCR_Result::pass( 'overridden' ) : $result;
			},
			10,
			2
		);

		$this->assertSame( 'overridden', CASCR_Runner::run( 'wp_debug' )['summary'] );
	}

	/* ---------------------------------------------------------------------
	 * Configuration
	 * ------------------------------------------------------------------- */

	public function test_debug_mode_is_reported_when_it_is_on() {
		$result = CASCR_Checks_Config::wp_debug();

		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			$this->assertNotSame( 'pass', $result['status'] );
			$this->assertContains( 'WP_DEBUG', $result['items'] );
		} else {
			$this->assertSame( 'pass', $result['status'] );
		}
	}

	public function test_the_editor_is_reported_according_to_the_constant() {
		$result = CASCR_Checks_Config::file_edit();

		if ( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT ) {
			$this->assertSame( 'pass', $result['status'] );
		} else {
			$this->assertSame( 'fail', $result['status'] );
			$this->assertNotSame( '', $result['fix'] );
		}
	}

	public function test_a_custom_table_prefix_passes() {
		global $wpdb;

		$result = CASCR_Checks_Config::db_prefix();

		if ( 'wp_' === $wpdb->prefix ) {
			$this->assertSame( 'warn', $result['status'] );
		} else {
			$this->assertSame( 'pass', $result['status'] );
		}
	}

	/**
	 * WP_AUTO_UPDATE_CORE set to true means more coverage than 'minor', not
	 * less. The previous version reported it as a risk.
	 */
	public function test_automatic_updates_pass_when_the_constant_is_absent() {
		if ( defined( 'WP_AUTO_UPDATE_CORE' ) ) {
			$this->markTestSkipped( 'The test environment defines WP_AUTO_UPDATE_CORE.' );
		}

		$this->assertSame( 'pass', CASCR_Checks_Core::automatic_core_updates()['status'] );
	}

	public function test_injected_script_tags_in_options_are_found() {
		add_option( 'cascr_probe_option', '<script src="https://evil.example.com/x.js"></script>', '', 'yes' );
		wp_cache_delete( 'alloptions', 'options' );

		$result = CASCR_Checks_Config::suspicious_options();

		delete_option( 'cascr_probe_option' );
		wp_cache_delete( 'alloptions', 'options' );

		$this->assertSame( 'fail', $result['status'] );
		$this->assertNotEmpty( $result['items'] );
	}

	public function test_clean_options_pass() {
		wp_cache_delete( 'alloptions', 'options' );

		$this->assertSame( 'pass', CASCR_Checks_Config::suspicious_options()['status'] );
	}

	/* ---------------------------------------------------------------------
	 * Accounts
	 * ------------------------------------------------------------------- */

	/**
	 * The WordPress test suite ships an administrator called admin whose
	 * password is "password", which is exactly what two of these checks look
	 * for. Tests that assert a clean site have to neutralise it first.
	 */
	private function neutralise_default_admin() {
		foreach ( get_users( array( 'fields' => array( 'ID', 'user_login' ) ) ) as $user ) {
			wp_set_password( 'Q4#zv8Rm!pLt2xNe', $user->ID );

			$object = new WP_User( $user->ID );
			$object->set_role( 'subscriber' );

			// On multisite a network administrator keeps every capability no
			// matter which role the site gives them.
			if ( is_multisite() && is_super_admin( $user->ID ) ) {
				revoke_super_admin( $user->ID );
			}
		}
	}

	public function test_a_predictable_administrator_name_is_reported() {
		self::factory()->user->create(
			array(
				'user_login' => 'administrator',
				'role'       => 'administrator',
			)
		);

		$result = CASCR_Checks_Accounts::admin_username();

		$this->assertSame( 'fail', $result['status'] );
		$this->assertContains( 'administrator', $result['items'] );
	}

	public function test_a_normal_administrator_name_passes() {
		$this->neutralise_default_admin();

		self::factory()->user->create(
			array(
				'user_login' => 'ps-maintenance',
				'role'       => 'administrator',
			)
		);

		$this->assertSame( 'pass', CASCR_Checks_Accounts::admin_username()['status'] );
	}

	public function test_a_guessable_password_is_found_without_logging_in() {
		$this->neutralise_default_admin();

		self::factory()->user->create(
			array(
				'user_login' => 'editor-one',
				'user_pass'  => 'password',
				'role'       => 'editor',
			)
		);

		$result = CASCR_Checks_Accounts::weak_password_users();

		$this->assertSame( 'fail', $result['status'] );
		$this->assertContains( 'editor-one', $result['items'] );
	}

	public function test_a_strong_password_passes() {
		$this->neutralise_default_admin();

		self::factory()->user->create(
			array(
				'user_login' => 'editor-two',
				'user_pass'  => 'K7#tq2Lm!vZr9wXe',
				'role'       => 'editor',
			)
		);

		$this->assertSame( 'pass', CASCR_Checks_Accounts::weak_password_users()['status'] );
	}

	public function test_escalated_capabilities_below_administrator_are_reported() {
		$role = get_role( 'subscriber' );
		$role->add_cap( 'install_plugins' );

		$result = CASCR_Checks_Accounts::role_capability_drift();

		$role->remove_cap( 'install_plugins' );

		$this->assertSame( 'fail', $result['status'] );
		$this->assertNotEmpty( $result['items'] );
	}

	public function test_default_roles_pass() {
		$this->assertSame( 'pass', CASCR_Checks_Accounts::role_capability_drift()['status'] );
	}

	public function test_closed_registration_passes() {
		if ( is_multisite() ) {
			update_site_option( 'registration', 'none' );
		}
		update_option( 'users_can_register', 0 );

		$this->assertSame( 'pass', CASCR_Checks_Accounts::open_registration()['status'] );
	}

	/**
	 * Multisite ignores users_can_register entirely: sign-up is a network
	 * setting. Reading the per-site option there reported "closed" on a network
	 * that let anyone register, which is the worst kind of wrong answer.
	 *
	 * @group multisite
	 */
	public function test_open_network_registration_is_reported_on_multisite() {
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Only meaningful on multisite.' );
		}

		update_option( 'users_can_register', 0 );
		update_site_option( 'registration', 'all' );

		$result = CASCR_Checks_Accounts::open_registration();

		update_site_option( 'registration', 'none' );

		$this->assertNotSame( 'pass', $result['status'] );
		$this->assertNotEmpty( $result['items'] );
	}

	/**
	 * A network administrator holds every capability regardless of the role the
	 * current site gives them, so a role query alone would miss them.
	 *
	 * @group multisite
	 */
	public function test_super_admins_are_included_in_account_checks() {
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Only meaningful on multisite.' );
		}

		$this->neutralise_default_admin();

		$id = self::factory()->user->create(
			array(
				'user_login' => 'e2e-network-owner',
				'user_pass'  => 'password',
				'role'       => 'subscriber',
			)
		);
		grant_super_admin( $id );

		$result = CASCR_Checks_Accounts::weak_password_users();

		revoke_super_admin( $id );

		$this->assertSame( 'fail', $result['status'] );
		$this->assertContains( 'e2e-network-owner', $result['items'] );
	}

	public function test_open_registration_handing_out_administrator_fails_hard() {
		if ( is_multisite() ) {
			update_site_option( 'registration', 'all' );
		}
		update_option( 'users_can_register', 1 );
		update_option( 'default_role', 'administrator' );

		$result = CASCR_Checks_Accounts::open_registration();

		if ( is_multisite() ) {
			update_site_option( 'registration', 'none' );
		}
		update_option( 'users_can_register', 0 );
		update_option( 'default_role', 'subscriber' );

		$this->assertSame( 'fail', $result['status'] );
		$this->assertSame( 10, $result['score'] );
	}

	public function test_open_registration_with_subscriber_is_only_a_warning() {
		if ( is_multisite() ) {
			update_site_option( 'registration', 'user' );
		}
		update_option( 'users_can_register', 1 );
		update_option( 'default_role', 'subscriber' );

		$result = CASCR_Checks_Accounts::open_registration();

		if ( is_multisite() ) {
			update_site_option( 'registration', 'none' );
		}
		update_option( 'users_can_register', 0 );

		$this->assertSame( 'warn', $result['status'] );
	}

	public function test_the_login_timestamp_is_recorded() {
		$user_id = self::factory()->user->create( array( 'role' => 'administrator' ) );
		$user    = get_user_by( 'id', $user_id );

		CASCR_Checks_Accounts::record_login( $user->user_login, $user );

		$this->assertGreaterThan( 0, (int) get_user_meta( $user_id, CASCR_Checks_Accounts::META_LAST_LOGIN, true ) );
	}

	/* ---------------------------------------------------------------------
	 * Drift baselines
	 * ------------------------------------------------------------------- */

	public function test_the_first_run_records_the_baseline_instead_of_reporting() {
		$first = CASCR_Checks_Core::mu_plugins_and_dropins();

		$this->assertNotSame( 'fail', $first['status'] );

		$second = CASCR_Checks_Core::mu_plugins_and_dropins();

		$this->assertNotSame( 'fail', $second['status'], 'An unchanged set must not be reported.' );
	}

	public function test_a_new_plugin_author_is_reported_after_the_baseline_exists() {
		$first = CASCR_Checks_Core::plugin_ownership_change();

		$this->assertSame( 'pass', $first['status'], 'The first run only records the baseline.' );

		$baseline = CASCR_Store::baseline( 'plugin_authors', array() );

		if ( empty( $baseline ) ) {
			$this->markTestSkipped( 'No plugins are installed in the test environment.' );
		}

		// Pretend the recorded author was somebody else, which is what a plugin
		// handover looks like from the site's point of view.
		$file              = key( $baseline );
		$baseline[ $file ] = 'Somebody Else Entirely';
		CASCR_Store::rebase( 'plugin_authors', $baseline );

		$result = CASCR_Checks_Core::plugin_ownership_change();

		$this->assertSame( 'fail', $result['status'] );
		$this->assertNotEmpty( $result['items'] );
	}

	/* ---------------------------------------------------------------------
	 * Network
	 * ------------------------------------------------------------------- */

	public function test_a_site_on_plain_http_fails() {
		add_filter( 'home_url', array( $this, 'force_http' ), 99 );

		$result = CASCR_Checks_Network::ssl();

		remove_filter( 'home_url', array( $this, 'force_http' ), 99 );

		$this->assertSame( 'fail', $result['status'] );
	}

	/**
	 * @param string $url Home URL.
	 * @return string
	 */
	public function force_http( $url ) {
		return set_url_scheme( $url, 'http' );
	}

	public function test_missing_security_headers_are_listed_individually() {
		$result = CASCR_Checks_Network::security_headers();

		$this->assertNotSame( 'pass', $result['status'] );
		$this->assertContains( 'X-Content-Type-Options', $result['items'] );
		$this->assertNotContains( 'Cross-Origin-Embedder-Policy', $result['items'], 'Cross-origin isolation headers are optional.' );
	}

	/**
	 * A network failure says nothing about the site and must not be graded.
	 */
	public function test_a_failing_request_yields_inconclusive_rather_than_a_finding() {
		remove_filter( 'pre_http_request', array( $this, 'mock_http' ), 10 );
		CASCR_Http::reset();

		add_filter(
			'pre_http_request',
			function () {
				return new WP_Error( 'http_request_failed', 'no route to host' );
			}
		);

		foreach ( array( 'security_headers', 'cors_configuration', 'php_version_in_headers', 'legacy_meta_exposure' ) as $check ) {
			$this->assertSame(
				'inconclusive',
				CASCR_Checks_Network::$check()['status'],
				"Check '{$check}' turned a network failure into a finding."
			);
		}
	}

	public function test_write_routes_without_a_permission_callback_are_reported() {
		add_action(
			'rest_api_init',
			function () {
				register_rest_route(
					'cascr-test/v1',
					'/wide-open',
					array(
						'methods'             => 'POST',
						'callback'            => '__return_empty_array',
						'permission_callback' => '__return_true',
					)
				);
			}
		);

		do_action( 'rest_api_init', rest_get_server() );

		$result = CASCR_Checks_Network::rest_open_routes();

		$this->assertSame( 'fail', $result['status'] );
		$this->assertNotEmpty(
			array_filter(
				$result['items'],
				function ( $item ) {
					return false !== strpos( $item, 'wide-open' );
				}
			)
		);
	}
}
