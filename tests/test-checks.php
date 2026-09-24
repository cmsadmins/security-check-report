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

	/**
	 * A check hands the link to the interface, which turns it into an anchor.
	 * An unvalidated value would end up in the document as a link target.
	 */
	public function test_only_well_formed_links_survive() {
		$good = CASCR_Result::fail(
			'bad',
			8,
			array(),
			'fix',
			array(
				'url'   => 'https://example.com/help',
				'label' => 'Help',
			)
		);
		$this->assertSame( 'https://example.com/help', $good['link']['url'] );

		foreach ( array(
			array(
				'url'   => 'javascript:alert(1)',
				'label' => 'Bad',
			),
			array(
				'url'   => 'data:text/html,<script>',
				'label' => 'Bad',
			),
			array( 'url' => 'https://example.com' ),
			array( 'label' => 'no url' ),
			'not an array',
		) as $candidate ) {
			$result = CASCR_Result::fail( 'bad', 8, array(), 'fix', $candidate );
			$this->assertSame( array(), $result['link'], 'A malformed link must be dropped.' );
		}
	}

	public function test_every_result_carries_a_link_key() {
		foreach ( CASCR_Registry::ids() as $id ) {
			$this->assertArrayHasKey( 'link', CASCR_Runner::run( $id ), "Check '{$id}' has no link key." );
		}
	}

	/**
	 * The suggestion has to be a real second factor, otherwise the finding
	 * points somewhere that does not solve it.
	 */
	public function test_the_two_factor_finding_suggests_something_when_nothing_is_installed() {
		$result = CASCR_Checks_Accounts::two_factor_coverage();

		if ( 'fail' !== $result['status'] || '' === $result['fix'] ) {
			$this->markTestSkipped( 'A two-factor plugin is active in this environment.' );
		}

		$this->assertNotEmpty( $result['link'] );
		$this->assertStringStartsWith( 'https://', $result['link']['url'] );
		$this->assertStringContainsString( 'Two Factor', $result['fix'], 'The free option must be named first.' );
	}

	public function test_an_installed_two_factor_plugin_nobody_uses_is_a_finding() {
		self::factory()->user->create( array( 'role' => 'administrator' ) );

		$previous = get_option( 'active_plugins', array() );
		update_option( 'active_plugins', array( 'two-factor/two-factor.php' ) );

		$result = CASCR_Checks_Accounts::two_factor_coverage();

		update_option( 'active_plugins', $previous );

		$this->assertSame( 'fail', $result['status'], 'An unfinished setup is the same exposure as no second factor.' );
		$this->assertNotEmpty( $result['items'] );
		$this->assertNotEmpty( $result['link'] );
	}

	public function test_a_two_factor_plugin_with_unknown_storage_stays_inconclusive() {
		self::factory()->user->create( array( 'role' => 'administrator' ) );

		$previous = get_option( 'active_plugins', array() );
		update_option( 'active_plugins', array( 'rublon/rublon.php' ) );

		$result = CASCR_Checks_Accounts::two_factor_coverage();

		update_option( 'active_plugins', $previous );

		$this->assertSame( 'inconclusive', $result['status'], 'Without a known meta key the check must not guess.' );
	}

	/* ---------------------------------------------------------------------
	 * Transparency
	 * ------------------------------------------------------------------- */

	public function test_ai_disclosure_warns_when_nothing_labels_ai_content() {
		$result = CASCR_Checks_Transparency::ai_content_disclosure();

		$this->assertSame( 'warn', $result['status'], 'A site with no AI content must not be failed for this.' );
		$this->assertNotEmpty( $result['fix'] );
		$this->assertNotEmpty( $result['link'] );
		$this->assertStringStartsWith( 'https://', $result['link']['url'] );
	}

	public function test_a_configured_disclosure_plugin_passes() {
		$previous = get_option( 'active_plugins', array() );
		update_option( 'active_plugins', array( 'transparai/transparai.php' ) );
		update_option( 'transparai_settings', array( 'enabled' => true ) );

		$result = CASCR_Checks_Transparency::ai_content_disclosure();

		update_option( 'active_plugins', $previous );
		delete_option( 'transparai_settings' );

		$this->assertSame( 'pass', $result['status'] );
		$this->assertNotEmpty( $result['items'], 'The passing result must name what is doing the labelling.' );
	}

	public function test_an_installed_disclosure_plugin_nobody_set_up_is_not_a_pass() {
		$previous = get_option( 'active_plugins', array() );
		update_option( 'active_plugins', array( 'transparai/transparai.php' ) );

		$result = CASCR_Checks_Transparency::ai_content_disclosure();

		update_option( 'active_plugins', $previous );

		$this->assertSame( 'warn', $result['status'], 'A folder on disk labels nothing.' );
		$this->assertNotEmpty( $result['items'] );
	}

	/**
	 * The check must stay inside the site. Anything else would add an endpoint
	 * the readme does not list.
	 */
	public function test_ai_disclosure_makes_no_outbound_request() {
		$calls = 0;

		add_filter(
			'pre_http_request',
			function ( $preempt ) use ( &$calls ) {
				++$calls;

				return $preempt;
			},
			1
		);

		CASCR_Checks_Transparency::ai_content_disclosure();

		$this->assertSame( 0, $calls );
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

	/**
	 * A log at a path of its own used to get the same vague warning wherever it
	 * sat: above the web root, where nothing can fetch it, and next to the
	 * uploads, where anyone can. Core always defines WP_DEBUG_LOG, so the test
	 * asks the resolution directly instead of rewriting the constant.
	 */
	public function test_where_a_debug_log_sits_decides_whether_it_can_be_fetched() {
		$inside = wp_normalize_path( WP_CONTENT_DIR ) . '/cascr-log-probe.log';
		$root   = wp_normalize_path( ABSPATH ) . 'cascr-log-probe.log';
		$away   = rtrim( wp_normalize_path( get_temp_dir() ), '/' ) . '/cascr-log-probe.log';
		$probes = array( $inside, $root, $away );

		foreach ( $probes as $path ) {
			if ( false === file_put_contents( $path, "probe\n" ) ) { // phpcs:ignore
				$this->markTestSkipped( 'The probe files cannot be written here.' );
			}
		}

		$urls = array_map( array( 'CASCR_Config_Probe', 'url' ), $probes );

		array_map( 'unlink', $probes );

		$this->assertSame( content_url( '/cascr-log-probe.log' ), $urls[0] );
		$this->assertSame( site_url( '/cascr-log-probe.log' ), $urls[1] );
		$this->assertSame( '', $urls[2], 'Above the web root there is nothing to fetch.' );
	}

	public function test_the_editor_is_reported_according_to_the_constant() {
		$result = CASCR_Checks_Config::file_edit();

		$locked = ( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT )
			|| ( defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS );

		if ( $locked ) {
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
		if ( defined( 'WP_AUTO_UPDATE_CORE' ) || ! wp_is_file_mod_allowed( 'automatic_updater' ) ) {
			$this->markTestSkipped( 'The test environment already decides whether the updater may run.' );
		}

		$this->assertSame( 'pass', $this->automatic_core_updates_with_the_updater_allowed()['status'] );
	}

	/**
	 * A script tag in an option is what an analytics or consent plugin stores
	 * on purpose, so it is worth a look and not a critical finding.
	 */
	public function test_a_foreign_script_tag_in_an_option_is_a_warning() {
		add_option( 'cascr_probe_option', '<script src="https://cdn.example.com/x.js"></script>', '', 'yes' );
		wp_cache_delete( 'alloptions', 'options' );

		$result = CASCR_Checks_Config::suspicious_options();

		delete_option( 'cascr_probe_option' );
		wp_cache_delete( 'alloptions', 'options' );

		$this->assertSame( 'warn', $result['status'] );
		$this->assertNotEmpty( $result['items'] );
		$this->assertLessThan( 7, $result['score'] );
	}

	public function test_a_code_fragment_in_an_option_still_fails() {
		add_option( 'cascr_probe_option', 'eval( base64_decode( "ZWNobyAx" ) );', '', 'yes' );
		wp_cache_delete( 'alloptions', 'options' );

		$result = CASCR_Checks_Config::suspicious_options();

		delete_option( 'cascr_probe_option' );
		wp_cache_delete( 'alloptions', 'options' );

		$this->assertSame( 'fail', $result['status'] );
		$this->assertNotEmpty( $result['items'] );
	}

	/**
	 * Running WordPress from its own subdirectory is a documented setup, so
	 * differing siteurl and home options say nothing about an intrusion.
	 */
	public function test_wordpress_in_its_own_directory_is_not_a_finding() {
		$siteurl = get_option( 'siteurl' );

		update_option( 'siteurl', untrailingslashit( $siteurl ) . '/wordpress' );
		wp_cache_delete( 'alloptions', 'options' );

		$result = CASCR_Checks_Config::suspicious_options();

		update_option( 'siteurl', $siteurl );
		wp_cache_delete( 'alloptions', 'options' );

		$this->assertSame( 'pass', $result['status'] );
	}

	public function test_clean_options_pass() {
		wp_cache_delete( 'alloptions', 'options' );

		$this->assertSame( 'pass', CASCR_Checks_Config::suspicious_options()['status'] );
	}

	/**
	 * A grant option that only covers the site database hands out nothing the
	 * account does not already hold there. Some hosts ship it that way.
	 */
	public function test_a_grant_option_limited_to_one_database_is_not_excessive() {
		$this->fake_grants( "GRANT ALL PRIVILEGES ON `sitedb`.* TO `site`@`localhost` WITH GRANT OPTION" );

		$result = CASCR_Checks_Config::database_user_privileges();

		$this->assertSame( 'pass', $result['status'] );
	}

	public function test_a_grant_option_on_every_database_is_excessive() {
		$this->fake_grants( "GRANT ALL PRIVILEGES ON *.* TO `site`@`localhost` WITH GRANT OPTION" );

		$result = CASCR_Checks_Config::database_user_privileges();

		$this->assertSame( 'fail', $result['status'] );
		$this->assertNotEmpty( $result['items'] );
	}

	/**
	 * SHOW GRANTS cannot be steered from a test, so the statement is swapped
	 * for a SELECT that returns the line under test in the same shape.
	 */
	private function fake_grants( $line ) {
		add_filter(
			'query',
			function ( $query ) use ( $line ) {
				if ( false === stripos( $query, 'SHOW GRANTS' ) ) {
					return $query;
				}

				global $wpdb;

				return 'SELECT ' . $wpdb->prepare( '%s', $line );
			}
		);
	}

	/**
	 * The keys carry no date of their own. Only the file they live in has one,
	 * and the wording has to stay with that.
	 */
	public function test_the_key_rotation_hint_reports_the_age_of_the_file() {
		// wp-tests-config.php ships the placeholder keys, so on the continuous
		// integration run the check never gets past the fail branch. On an
		// installation with a real set of keys this case does run.
		if ( 'fail' === CASCR_Checks_Config::security_keys_salts()['status'] ) {
			$this->markTestSkipped( 'This installation has no valid set of keys to age.' );
		}

		$config = ABSPATH . 'wp-config.php';

		if ( ! file_exists( $config ) || ! is_writable( $config ) ) {
			$this->markTestSkipped( 'wp-config.php cannot be touched in this environment.' );
		}

		$previous = filemtime( $config );
		touch( $config, time() - 2 * YEAR_IN_SECONDS );

		$result = CASCR_Checks_Config::security_keys_salts();

		touch( $config, $previous );

		$this->assertSame( 'warn', $result['status'] );
		$this->assertNotEmpty( $result['items'], 'The finding must name what was actually measured.' );
		$this->assertStringContainsString( 'wp-config.php', $result['items'][0] );
		$this->assertStringContainsString( 'secret-key', $result['fix'], 'The warning must say how to rotate.' );
	}

	/**
	 * There is no dashboard screen listing scheduled events, so the suggestion
	 * must not send anyone to Site Health looking for one.
	 */
	public function test_the_scheduler_finding_points_somewhere_that_exists() {
		// An empty schedule with a single future event leaves the orphan as the
		// only issue, so the advice cannot come from the overdue branch.
		$previous = _get_cron_array();
		_set_cron_array( array() );
		wp_schedule_single_event( time() + HOUR_IN_SECONDS, 'cascr_probe_orphan_hook' );

		$result = CASCR_Checks_Config::wp_cron_health();

		_set_cron_array( $previous );

		$this->assertNotSame( 'pass', $result['status'] );
		$this->assertStringContainsString( 'wp cron event list', $result['fix'] );
		$this->assertStringNotContainsString( 'Site Health', $result['fix'] );
		$this->assertStringContainsString(
			'this request',
			implode( ' ', $result['items'] ),
			'has_action() only sees the current request, and the item has to say so.'
		);
	}

	/**
	 * Both checks read a list of plugin names. Neither can see a limit that a
	 * server, a firewall or an identity provider enforces.
	 */
	public function test_the_login_checks_say_that_they_only_see_plugins() {
		$previous = get_option( 'active_plugins', array() );
		update_option( 'active_plugins', array() );

		$brute  = CASCR_Checks_Config::brute_force();
		$policy = CASCR_Checks_Config::password_policy();

		update_option( 'active_plugins', $previous );

		$this->assertStringContainsString( 'only see plugins', $brute['summary'] );
		$this->assertStringContainsString( 'only see plugins', $policy['summary'] );
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
	 * Files
	 * ------------------------------------------------------------------- */

	/**
	 * The shapes an upload folder guard actually takes in the wild, none of
	 * which is worth reporting.
	 *
	 * @return array<string, string[]>
	 */
	public function guard_files() {
		return array(
			'silence'    => array( "<?php\n// Silence is golden.\n" ),
			'bare tag'   => array( "<?php\n" ),
			'exit'       => array( "<?php exit;\n" ),
			'forbidden'  => array( "<?php\nheader( 'HTTP/1.0 403 Forbidden' );\nexit;\n" ),
			'abspath'    => array( "<?php\nif ( ! defined( 'ABSPATH' ) ) {\n\texit;\n}\n" ),
			'doc block'  => array( "<?php\n/**\n * Nothing to see here.\n */\n" ),
			'protocol'   => array( "<?php header( \$_SERVER['SERVER_PROTOCOL'] . ' 403 Forbidden' ); exit;\n" ),
		);
	}

	/**
	 * @dataProvider guard_files
	 *
	 * @param string $contents File contents to write.
	 */
	public function test_guard_files_in_uploads_are_not_a_finding( $contents ) {
		$dir = wp_upload_dir();

		if ( empty( $dir['basedir'] ) || ! wp_mkdir_p( $dir['basedir'] . '/cascr-probe' ) ) {
			$this->markTestSkipped( 'The uploads directory is not writable here.' );
		}

		$guard = $dir['basedir'] . '/cascr-probe/index.php';
		file_put_contents( $guard, $contents ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Fixture.

		$result = CASCR_Checks_Files::unallowed_files();

		unlink( $guard );
		rmdir( $dir['basedir'] . '/cascr-probe' );

		$this->assertNotSame( 'fail', $result['status'], 'A guard file is what stops directory listing, not a finding.' );
	}

	/**
	 * Files that must survive the guard filter, however they are named.
	 *
	 * @return array<string, string[]>
	 */
	public function shell_files() {
		return array(
			'request data'   => array( 'index.php', "<?php system( \$_GET['c'] );\n" ),
			'eval'           => array( 'index.php', "<?php eval( 'phpinfo();' );\n" ),
			'encoded'        => array( 'index.php', "<?php echo base64_decode( 'aGk=' );\n" ),
			'backtick'       => array( 'index.php', "<?php echo `ls`;\n" ),
			'variable call'  => array( 'index.php', "<?php \$f = 'phpinfo'; \$f();\n" ),
			'plain php file' => array( 'notes.php', "<?php echo 'hello';\n" ),
			'server echo'    => array( 'index.php', "<?php echo \$_SERVER['DOCUMENT_ROOT'];\n" ),
			'cookie read'    => array( 'index.php', "<?php if ( ! empty( \$_COOKIE['x'] ) ) { header( 'Location: /' ); }\n" ),
		);
	}

	/**
	 * @dataProvider shell_files
	 *
	 * @param string $name     File name to write.
	 * @param string $contents File contents to write.
	 */
	public function test_executable_uploads_are_still_reported( $name, $contents ) {
		$dir = wp_upload_dir();

		if ( empty( $dir['basedir'] ) || ! wp_mkdir_p( $dir['basedir'] . '/cascr-probe' ) ) {
			$this->markTestSkipped( 'The uploads directory is not writable here.' );
		}

		$file = $dir['basedir'] . '/cascr-probe/' . $name;
		file_put_contents( $file, $contents ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Fixture.

		$result = CASCR_Checks_Files::unallowed_files();

		unlink( $file );
		rmdir( $dir['basedir'] . '/cascr-probe' );

		$this->assertSame( 'fail', $result['status'], 'A file that can do something must still be reported.' );
		$this->assertNotEmpty( $result['items'] );
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

	/**
	 * A route that is meant to be public is registered exactly this way, so
	 * the finding may name it, but it may not read as a verdict.
	 */
	public function test_a_route_that_is_open_on_purpose_is_a_question_not_a_failure() {
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

		$this->assertSame( 'warn', $result['status'] );
		$this->assertNotEmpty(
			array_filter(
				$result['items'],
				function ( $item ) {
					return false !== strpos( $item, 'wide-open' );
				}
			)
		);
	}

	/**
	 * No permission callback at all is the case WordPress itself complains
	 * about, and that one stays a failure.
	 */
	public function test_a_write_route_without_any_permission_callback_still_fails() {
		$this->add_route(
			'/cascr-test/v1/no-callback',
			array(
				'methods'  => 'POST',
				'callback' => '__return_empty_array',
			)
		);

		$result = CASCR_Checks_Network::rest_open_routes();

		$this->assertSame( 'fail', $result['status'] );
		$this->assertStringContainsString( 'no-callback', implode( ' | ', $result['items'] ) );
	}

	/**
	 * The Store API serves a shop to visitors who are not logged in and
	 * authorises inside the callback. Reporting it would hit every shop.
	 */
	public function test_the_store_api_is_not_reported() {
		$this->add_route(
			'/wc/store/v1/cart/add-item',
			array(
				'methods'             => 'POST',
				'callback'            => '__return_empty_array',
				'permission_callback' => '__return_true',
			)
		);

		$this->assertSame( 'pass', CASCR_Checks_Network::rest_open_routes()['status'] );
	}

	/**
	 * The widely published strict policy carries 'unsafe-inline' next to a
	 * nonce on purpose, for browsers that understand neither nonces nor
	 * 'strict-dynamic'. Reporting it sends people to remove the fallback.
	 */
	public function test_a_strict_policy_with_its_fallback_is_not_reported() {
		$this->answer(
			home_url( '/' ),
			array( 'headers' => array( 'content-security-policy' => "object-src 'none'; base-uri 'none'; script-src 'nonce-r4nd0m' 'strict-dynamic' 'unsafe-inline' https:" ) )
		);

		$this->assertSame( 'pass', CASCR_Checks_Network::csp_quality()['status'] );
	}

	public function test_a_host_wildcard_is_not_a_wildcard_source() {
		$this->answer(
			home_url( '/' ),
			array( 'headers' => array( 'content-security-policy' => "default-src 'self'; script-src 'self' *.cdn.example.com" ) )
		);

		$this->assertSame( 'pass', CASCR_Checks_Network::csp_quality()['status'] );
	}

	public function test_a_bare_wildcard_is_still_reported() {
		$this->answer(
			home_url( '/' ),
			array( 'headers' => array( 'content-security-policy' => "default-src 'self'; script-src 'self' *" ) )
		);

		$result = CASCR_Checks_Network::csp_quality();

		$this->assertSame( 'warn', $result['status'] );
		$this->assertStringContainsString( 'wildcard', implode( ' | ', $result['items'] ) );
	}

	/**
	 * Attributes start behind the first semicolon. A cookie whose name happens
	 * to contain "secure" carries no flag.
	 */
	public function test_cookie_attributes_are_read_from_the_attribute_part_only() {
		add_filter( 'home_url', array( $this, 'force_https' ), 99 );

		$this->answer( 'wp-login.php', array( 'headers' => array( 'set-cookie' => 'secure_session=abc; path=/' ) ) );

		$result = CASCR_Checks_Network::cookie_flags();

		remove_filter( 'home_url', array( $this, 'force_https' ), 99 );

		$items = implode( ' | ', $result['items'] );

		$this->assertSame( 'warn', $result['status'] );
		$this->assertStringContainsString( 'not marked Secure', $items );
		$this->assertStringContainsString( 'HttpOnly', $items, 'HttpOnly matters most for a cookie and was never looked at.' );
	}

	public function test_a_fully_marked_cookie_passes() {
		$this->answer(
			'wp-login.php',
			array( 'headers' => array( 'set-cookie' => 'wordpress_test_cookie=WP+Cookie+check; path=/; HttpOnly; SameSite=Lax' ) )
		);

		$this->assertSame( 'pass', CASCR_Checks_Network::cookie_flags()['status'] );
	}

	/**
	 * Seconds are how the header is written, not how anybody reads it, and the
	 * threshold the check applies belongs next to the value.
	 */
	public function test_the_hsts_finding_names_the_threshold_in_readable_units() {
		add_filter( 'home_url', array( $this, 'force_https' ), 99 );

		$this->answer( 'example.org', array( 'headers' => array( 'strict-transport-security' => 'max-age=100' ) ) );

		$result = CASCR_Checks_Network::hsts_quality();

		remove_filter( 'home_url', array( $this, 'force_https' ), 99 );

		$items = implode( ' | ', $result['items'] );

		$this->assertSame( 'warn', $result['status'] );
		$this->assertStringNotContainsString( '100 second', $items );
		$this->assertStringContainsString( '6 months', $items );
	}

	/**
	 * Since WordPress 4.4 the first failed login ends the rest of a multicall,
	 * so the finding must not promise password amplification.
	 */
	public function test_the_multicall_finding_no_longer_claims_amplification() {
		$this->answer_xmlrpc( 'system.multicall' );

		$result = CASCR_Checks_Network::xmlrpc();
		$items  = implode( ' | ', $result['items'] );

		$this->assertSame( 'warn', $result['status'] );
		$this->assertLessThanOrEqual( 5, $result['score'] );
		$this->assertStringContainsString( 'system.multicall', $items );
		$this->assertStringNotContainsString( 'many passwords', $items );
	}

	public function test_the_filter_that_disables_xmlrpc_logins_is_reported() {
		add_filter( 'xmlrpc_enabled', '__return_false' );

		$this->answer_xmlrpc( 'system.multicall' );

		$result = CASCR_Checks_Network::xmlrpc();
		$items  = implode( ' | ', $result['items'] );

		$this->assertStringContainsString( 'xmlrpc_enabled', $items );
		$this->assertStringNotContainsString( 'system.multicall', $items, 'The method is listed, but the filter turns it away.' );
	}

	/**
	 * Without pretty permalinks there is no redirect to notice, and author 1
	 * may have been deleted years ago.
	 */
	public function test_an_author_archive_answering_directly_is_still_a_finding() {
		$result = CASCR_Checks_Network::user_enumeration();

		$this->assertSame( 'warn', $result['status'] );
		$this->assertStringContainsString( 'author archive', implode( ' | ', $result['items'] ) );
	}

	public function test_the_author_redirect_is_found_for_a_user_other_than_the_first() {
		$id = self::factory()->user->create();

		$this->answer(
			'?author=' . $id,
			array(
				'response' => array(
					'code'    => 301,
					'message' => 'Moved Permanently',
				),
				'headers'  => array( 'location' => home_url( '/author/somebody/' ) ),
			)
		);

		$result = CASCR_Checks_Network::user_enumeration();

		$this->assertStringContainsString( 'login name', implode( ' | ', $result['items'] ) );
	}

	/**
	 * A content delivery network connects from its own public addresses, so a
	 * public REMOTE_ADDR is no proof that a visitor faked the header.
	 */
	public function test_a_forwarded_header_from_a_public_address_is_not_a_verdict() {
		$restore                          = $_SERVER['REMOTE_ADDR'];
		$_SERVER['REMOTE_ADDR']           = '104.16.0.1';
		$_SERVER['HTTP_CF_CONNECTING_IP'] = '203.0.113.9';

		$result = CASCR_Checks_Network::proxy_ip_configuration();

		$_SERVER['REMOTE_ADDR'] = $restore;
		unset( $_SERVER['HTTP_CF_CONNECTING_IP'] );

		$this->assertSame( 'inconclusive', $result['status'] );
	}

	public function test_a_confirmed_edge_passes() {
		$restore                          = $_SERVER['REMOTE_ADDR'];
		$_SERVER['REMOTE_ADDR']           = '172.64.0.1';
		$_SERVER['HTTP_CF_CONNECTING_IP'] = '203.0.113.9';

		$this->answer( home_url( '/' ), array( 'headers' => array( 'cf-ray' => '8d1f0000abcd0001-FRA' ) ) );

		$result = CASCR_Checks_Network::proxy_ip_configuration();

		$_SERVER['REMOTE_ADDR'] = $restore;
		unset( $_SERVER['HTTP_CF_CONNECTING_IP'] );

		$this->assertSame( 'pass', $result['status'] );
	}

	/**
	 * Under WP-CLI there is no request to read, and the friendly branch would
	 * report a clean result for a measurement that never happened.
	 */
	public function test_the_proxy_check_needs_a_request_to_look_at() {
		$restore = $_SERVER['REMOTE_ADDR'];
		unset( $_SERVER['REMOTE_ADDR'] );

		$result = CASCR_Checks_Network::proxy_ip_configuration();

		$_SERVER['REMOTE_ADDR'] = $restore;

		$this->assertSame( 'inconclusive', $result['status'] );
	}

	/**
	 * The certificate is graded by its dates alone, so there is a step between
	 * the all clear and the two week failure, and no wording may suggest that
	 * a browser would trust the certificate.
	 */
	public function test_the_certificate_grade_follows_the_remaining_lifetime() {
		$verdict = new ReflectionMethod( 'CASCR_Checks_Network', 'certificate_result' );
		$verdict->setAccessible( true );

		$statuses = array();

		foreach ( array( 90, 20, 5, -1 ) as $days ) {
			$result     = $verdict->invoke( null, time() + $days * DAY_IN_SECONDS, 'TLSv1.3' );
			$statuses[] = $result['status'];
		}

		$this->assertSame( array( 'pass', 'warn', 'fail', 'fail' ), $statuses );

		$result = $verdict->invoke( null, time() + 90 * DAY_IN_SECONDS, 'TLSv1.3' );

		$this->assertStringContainsString( 'not checked here', implode( ' | ', $result['items'] ) );
	}

	/* ---------------------------------------------------------------------
	 * Network helpers
	 * ------------------------------------------------------------------- */

	/**
	 * @param string $url Home URL.
	 * @return string
	 */
	public function force_https( $url ) {
		return set_url_scheme( $url, 'https' );
	}

	/**
	 * Answers requests whose URL contains a given string with a canned
	 * response, and leaves every other request to the default mock.
	 *
	 * @param string $needle   Substring the URL has to contain.
	 * @param array  $response Parts of the response to override.
	 */
	private function answer( $needle, $response ) {
		add_filter(
			'pre_http_request',
			function ( $preempt, $args, $url ) use ( $needle, $response ) {
				unset( $args );

				if ( false === strpos( $url, $needle ) ) {
					return $preempt;
				}

				return array_merge(
					array(
						'headers'  => array(),
						'body'     => '',
						'response' => array(
							'code'    => 200,
							'message' => 'OK',
						),
						'cookies'  => array(),
						'filename' => null,
					),
					$response
				);
			},
			20,
			3
		);
	}

	/**
	 * Lets the XML-RPC endpoint answer with a method list.
	 *
	 * @param string $method Method name the endpoint reports.
	 */
	private function answer_xmlrpc( $method ) {
		$this->answer(
			'xmlrpc.php',
			array( 'body' => '<?xml version="1.0"?><methodResponse><params><param><value><array><data><value><string>' . $method . '</string></value></data></array></value></param></params></methodResponse>' )
		);
	}

	/**
	 * Puts a route on the server without registering it, which keeps the case
	 * WordPress warns about out of the test log.
	 *
	 * @param string $route   Route path.
	 * @param array  $handler Single route handler.
	 */
	private function add_route( $route, $handler ) {
		// A route registered by an earlier test stays on the server object for
		// the rest of the run, so the server is rebuilt before the filter runs.
		$GLOBALS['wp_rest_server'] = null;

		add_filter(
			'rest_endpoints',
			function ( $endpoints ) use ( $route, $handler ) {
				$endpoints[ $route ] = array( $handler );

				return $endpoints;
			}
		);
	}

	/* ---------------------------------------------------------------------
	 * Automatic core updates
	 * ------------------------------------------------------------------- */

	/**
	 * WP_AUTO_UPDATE_CORE is only one of four switches. DISALLOW_FILE_MODS is
	 * the one disallow_file_mods recommends, so a site that followed that
	 * advice must not be told its updates are fine.
	 */
	public function test_blocked_file_modifications_are_not_a_pass_for_automatic_updates() {
		if ( defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS ) {
			$this->assertSame( 'fail', CASCR_Checks_Core::automatic_core_updates()['status'] );

			return;
		}

		add_filter( 'file_mod_allowed', '__return_false' );

		$result = $this->automatic_core_updates_with_the_updater_allowed();

		remove_filter( 'file_mod_allowed', '__return_false' );

		$this->assertSame( 'fail', $result['status'] );
		$this->assertContains( 'DISALLOW_FILE_MODS', $result['items'] );
	}

	/**
	 * The test suite itself switches the updater off through the filter and
	 * sets no constant, which is exactly the case the constant check missed.
	 */
	public function test_a_filter_that_switches_the_updater_off_is_reported() {
		$result = CASCR_Checks_Core::automatic_core_updates();

		$this->assertSame( 'fail', $result['status'] );
		$this->assertContains( 'automatic_updater_disabled', $result['items'] );
	}

	/**
	 * branch-development installs every core update. Leaving it out of the list
	 * reported the widest setting there is as no updates at all.
	 */
	public function test_every_pre_release_channel_is_recognised() {
		$this->assertSame(
			array( 'beta', 'rc', 'development', 'branch-development' ),
			CASCR_Checks_Core::PRE_RELEASE_CHANNELS
		);
	}

	public function test_minor_updates_switched_off_by_site_option_are_reported() {
		if ( defined( 'WP_AUTO_UPDATE_CORE' ) || ! wp_is_file_mod_allowed( 'automatic_updater' ) ) {
			$this->markTestSkipped( 'The environment already settles this case elsewhere.' );
		}

		update_site_option( 'auto_update_core_minor', 'disabled' );

		$result = $this->automatic_core_updates_with_the_updater_allowed();

		delete_site_option( 'auto_update_core_minor' );

		$this->assertSame( 'fail', $result['status'], 'The constant is not the only switch.' );
		$this->assertContains( 'auto_update_core_minor', $result['items'] );
	}

	/**
	 * The WordPress test suite disables the automatic updater for the whole
	 * run, so every case below that switch needs it lifted for the call.
	 *
	 * @return array
	 */
	private function automatic_core_updates_with_the_updater_allowed() {
		remove_filter( 'automatic_updater_disabled', '__return_true' );

		$result = CASCR_Checks_Core::automatic_core_updates();

		add_filter( 'automatic_updater_disabled', '__return_true' );

		return $result;
	}

	/* ---------------------------------------------------------------------
	 * Core file scan
	 * ------------------------------------------------------------------- */

	/**
	 * A scan that gave up says nothing about the files it never opened, so it
	 * must not end in the passing branch.
	 */
	public function test_a_core_scan_that_hits_its_limit_stays_inconclusive() {
		$property = new ReflectionProperty( 'CASCR_Checks_Core', 'checksums' );
		$property->setAccessible( true );
		$previous = $property->getValue();
		$property->setValue( null, $this->core_file_list() );

		$truncated = CASCR_Checks_Core::unknown_core_files( 5 );
		$complete  = CASCR_Checks_Core::unknown_core_files();

		$property->setValue( null, $previous );

		$this->assertSame( 'inconclusive', $truncated['status'], 'A partial scan must not read as an all clear.' );
		$this->assertSame( 'pass', $complete['status'] );
	}

	/**
	 * Every file below wp-admin and wp-includes, in the relative form the
	 * published checksum list uses.
	 *
	 * @return array
	 */
	private function core_file_list() {
		$known = array();
		$root  = wp_normalize_path( ABSPATH );

		foreach ( array( 'wp-admin', 'wp-includes' ) as $dir ) {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( ABSPATH . $dir, RecursiveDirectoryIterator::SKIP_DOTS )
			);

			foreach ( $iterator as $file ) {
				if ( $file->isFile() ) {
					$known[ substr( wp_normalize_path( $file->getPathname() ), strlen( $root ) ) ] = '';
				}
			}
		}

		return $known;
	}

	/* ---------------------------------------------------------------------
	 * Closed plugin listings
	 * ------------------------------------------------------------------- */

	/**
	 * The directory serves a closed listing as HTTP 404 with the flag in the
	 * same body, and plugins_api() turns any 404 into a WP_Error. Reading it
	 * that way skipped over exactly the case this check exists for.
	 */
	public function test_a_closed_plugin_listing_is_reported() {
		$result = $this->directory_check( array( $this, 'mock_closed_listing' ) );

		if ( null === $result ) {
			$this->markTestSkipped( 'No plugin with a directory slug is installed.' );
		}

		$this->assertSame( 'fail', $result['status'] );
		$this->assertNotEmpty( $result['items'] );
	}

	public function test_an_open_plugin_listing_is_not_a_finding() {
		$result = $this->directory_check( array( $this, 'mock_open_listing' ) );

		if ( null === $result ) {
			$this->markTestSkipped( 'No plugin with a directory slug is installed.' );
		}

		$this->assertSame( 'pass', $result['status'] );
	}

	/**
	 * Not reaching the directory is not the same as the directory saying the
	 * listing is open.
	 */
	public function test_an_unreachable_plugin_directory_is_not_an_all_clear() {
		$result = $this->directory_check( array( $this, 'mock_directory_failure' ) );

		if ( null === $result ) {
			$this->markTestSkipped( 'No plugin with a directory slug is installed.' );
		}

		$this->assertSame( 'inconclusive', $result['status'] );
	}

	/**
	 * Runs plugin_removed_from_repo with a single installed plugin active and
	 * the directory answering the way the given handler says.
	 *
	 * @param callable $mock pre_http_request handler.
	 * @return array|null Null when the environment has no plugin to work with.
	 */
	private function directory_check( $mock ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';

		$files = array_filter(
			array_keys( get_plugins() ),
			function ( $file ) {
				return '.' !== dirname( $file );
			}
		);

		if ( empty( $files ) ) {
			return null;
		}

		$file      = reset( $files );
		$transient = 'cascr_plugin_' . md5( dirname( $file ) );
		$previous  = get_option( 'active_plugins', array() );

		update_option( 'active_plugins', array( $file ) );
		delete_transient( $transient );
		CASCR_Http::reset();

		// The blanket mock answers every request with an empty 200 regardless
		// of what ran before it, so it has to step aside rather than be
		// out-prioritised.
		remove_filter( 'pre_http_request', array( $this, 'mock_http' ), 10 );
		add_filter( 'pre_http_request', $mock, 10, 3 );

		$result = CASCR_Checks_Core::plugin_removed_from_repo();

		remove_filter( 'pre_http_request', $mock, 10 );
		add_filter( 'pre_http_request', array( $this, 'mock_http' ), 10, 3 );
		CASCR_Http::reset();
		delete_transient( $transient );
		update_option( 'active_plugins', $previous );

		return $result;
	}

	/**
	 * @param mixed  $preempt Short circuit value.
	 * @param array  $args    Request arguments.
	 * @param string $url     Requested URL.
	 * @return mixed
	 */
	public function mock_closed_listing( $preempt, $args, $url ) {
		unset( $args );

		return $this->directory_response( $preempt, $url, 404, '{"error":"closed","slug":"probe","closed":true,"closed_date":"2024-02-23"}' );
	}

	/**
	 * @param mixed  $preempt Short circuit value.
	 * @param array  $args    Request arguments.
	 * @param string $url     Requested URL.
	 * @return mixed
	 */
	public function mock_open_listing( $preempt, $args, $url ) {
		unset( $args );

		return $this->directory_response( $preempt, $url, 200, '{"slug":"probe","last_updated":"2026-09-01 10:00am GMT","tested":"7.0"}' );
	}

	/**
	 * @param mixed  $preempt Short circuit value.
	 * @param array  $args    Request arguments.
	 * @param string $url     Requested URL.
	 * @return mixed
	 */
	public function mock_directory_failure( $preempt, $args, $url ) {
		unset( $args );

		if ( false === strpos( $url, 'plugins/info/1.2' ) ) {
			return $preempt;
		}

		return new WP_Error( 'http_request_failed', 'no route to host' );
	}

	/**
	 * @param mixed  $preempt Short circuit value.
	 * @param string $url     Requested URL.
	 * @param int    $code    HTTP status code to answer with.
	 * @param string $body    Response body.
	 * @return mixed
	 */
	private function directory_response( $preempt, $url, $code, $body ) {
		if ( false === strpos( $url, 'plugins/info/1.2' ) ) {
			return $preempt;
		}

		return array(
			'headers'  => array(),
			'body'     => $body,
			'response' => array(
				'code'    => $code,
				'message' => '',
			),
			'cookies'  => array(),
			'filename' => null,
		);
	}

	/**
	 * DISALLOW_FILE_MODS takes the editor down with it, which map_meta_cap()
	 * settles for edit_plugins and edit_themes. Reporting a failure here after
	 * someone followed the neighbouring recommendation would be wrong.
	 *
	 * The constant stays defined for the rest of the run, which is why this
	 * case sits at the end of the class.
	 */
	public function test_disallow_file_mods_alone_closes_the_editor() {
		if ( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT ) {
			$this->markTestSkipped( 'This environment already disables the editor outright.' );
		}

		if ( ! defined( 'DISALLOW_FILE_MODS' ) ) {
			define( 'DISALLOW_FILE_MODS', true );
		}

		$result = CASCR_Checks_Config::file_edit();

		$this->assertSame( 'pass', $result['status'] );
		$this->assertNotEmpty( $result['items'], 'The result must say which constant closed the editor.' );
	}
}

/**
 * Reaches the path resolution of the debug log check.
 *
 * WP_DEBUG_LOG is defined by core on every request, so the only way into that
 * resolution from a test is through the class that owns it.
 */
class CASCR_Config_Probe extends CASCR_Checks_Config {

	/**
	 * @param string $path File path.
	 * @return string
	 */
	public static function url( $path ) {
		return self::served_url( $path );
	}
}
