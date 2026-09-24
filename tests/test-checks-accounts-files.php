<?php
/**
 * Behaviour of the account and file checks that used to answer the wrong way.
 *
 * Each case here stands for a report a real site got: a second factor that was
 * present and reported missing, a switched-off factor reported as protection,
 * a new role reported as full control, a file the server handed out as text
 * reported as executed. They live apart from test-checks.php only so several
 * people can work on the check groups at once.
 *
 * @package CmsAdmins\SecurityCheck
 */

class Test_CASCR_Checks_Accounts_Files extends WP_UnitTestCase {

	/**
	 * Body every mocked request answers with.
	 *
	 * @var string
	 */
	private $body = '';

	/**
	 * Whether mocked requests fail instead of answering.
	 *
	 * @var bool
	 */
	private $fails = false;

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
	 * @param mixed  $preempt Short circuit value.
	 * @param array  $args    Request arguments.
	 * @param string $url     Requested URL.
	 * @return array|WP_Error
	 */
	public function mock_http( $preempt, $args, $url ) {
		unset( $preempt, $args, $url );

		if ( $this->fails ) {
			return new WP_Error( 'http_request_failed', 'Mocked failure.' );
		}

		return array(
			'headers'  => array(),
			'body'     => $this->body,
			'response' => array(
				'code'    => 200,
				'message' => 'OK',
			),
			'cookies'  => array(),
			'filename' => null,
		);
	}

	/**
	 * Runs a check with a plugin marked active, then restores the option.
	 *
	 * @param string   $plugin   Plugin file, folder and all.
	 * @param callable $callback Check to run.
	 * @return array
	 */
	private function with_plugin( $plugin, $callback ) {
		$previous = get_option( 'active_plugins', array() );
		update_option( 'active_plugins', array( $plugin ) );

		$result = call_user_func( $callback );

		update_option( 'active_plugins', $previous );

		return $result;
	}

	/* ---------------------------------------------------------------------
	 * Second factor
	 * ------------------------------------------------------------------- */

	/**
	 * The iThemes family writes the same meta as the Two Factor plugin it is
	 * built on. The key this check looked for never existed, so every site
	 * running it was told its administrators were unprotected.
	 */
	public function test_the_ithemes_family_meta_key_counts_as_a_second_factor() {
		self::factory()->user->create( array( 'role' => 'administrator' ) );
		$this->give_everyone( '_two_factor_enabled_providers', array( 'Two_Factor_Totp' ) );

		$result = $this->with_plugin(
			'better-wp-security/better-wp-security.php',
			array( 'CASCR_Checks_Accounts', 'two_factor_coverage' )
		);

		$this->assertSame( 'pass', $result['status'], 'A configured second factor must not be reported as missing.' );
	}

	/**
	 * Google Authenticator stores the string "disabled", which an emptiness
	 * test reads as protection.
	 */
	public function test_a_switched_off_second_factor_is_not_a_second_factor() {
		self::factory()->user->create( array( 'role' => 'administrator' ) );
		$this->give_everyone( 'googleauthenticator_enabled', 'disabled' );

		$result = $this->with_plugin(
			'google-authenticator/google-authenticator.php',
			array( 'CASCR_Checks_Accounts', 'two_factor_coverage' )
		);

		$this->assertSame( 'fail', $result['status'], 'The value "disabled" means the account has no second factor.' );
	}

	public function test_an_enabled_google_authenticator_account_passes() {
		self::factory()->user->create( array( 'role' => 'administrator' ) );
		$this->give_everyone( 'googleauthenticator_enabled', 'enabled' );

		$result = $this->with_plugin(
			'google-authenticator/google-authenticator.php',
			array( 'CASCR_Checks_Accounts', 'two_factor_coverage' )
		);

		$this->assertSame( 'pass', $result['status'] );
	}

	/**
	 * Hive Light has no second factor to read, so the folder must not put the
	 * check into the "installed but nobody set it up" branch.
	 */
	public function test_hive_light_alone_does_not_claim_an_unfinished_setup() {
		self::factory()->user->create( array( 'role' => 'administrator' ) );

		$result = $this->with_plugin(
			'reportedip-hive/reportedip-hive.php',
			array( 'CASCR_Checks_Accounts', 'two_factor_coverage' )
		);

		$this->assertSame( 'inconclusive', $result['status'] );
	}

	/* ---------------------------------------------------------------------
	 * Administrators
	 * ------------------------------------------------------------------- */

	/**
	 * The summary is the whole finding in the list of open items, in every
	 * export and on the command line. "Worth reviewing" said nothing there.
	 */
	public function test_the_administrator_finding_says_what_was_found() {
		for ( $i = 0; $i < 6; $i++ ) {
			self::factory()->user->create( array( 'role' => 'administrator' ) );
		}

		$result = CASCR_Checks_Accounts::admin_account_hygiene();

		$this->assertSame( 'warn', $result['status'] );
		$this->assertStringContainsString( 'administrator rights', $result['summary'] );
		$this->assertMatchesRegularExpression( '/\d/', $result['summary'], 'The summary carries the number, not only that something turned up.' );
	}

	/* ---------------------------------------------------------------------
	 * Roles
	 * ------------------------------------------------------------------- */

	/**
	 * A shop or membership plugin adds roles on activation. That is a change
	 * worth naming, not full control below administrator.
	 */
	public function test_a_new_role_alone_is_not_an_escalation() {
		CASCR_Checks_Accounts::role_capability_drift();

		add_role( 'cascr_test_role', 'CASCR Test Role', array( 'read' => true ) );

		$result = CASCR_Checks_Accounts::role_capability_drift();

		remove_role( 'cascr_test_role' );

		$this->assertSame( 'warn', $result['status'], 'A role that appeared is not administrator-level access.' );
		$this->assertNotEmpty( $result['items'] );
		$this->assertLessThan( CASCR_Result::THRESHOLD_FAIL, $result['score'] );
	}

	/**
	 * Muting says the new state is accepted, so it has to become the point the
	 * next run compares against. Without that, a role changed on purpose can
	 * only be quietened by muting the check for good, which takes its
	 * escalation findings with it.
	 */
	public function test_muting_a_drift_finding_moves_the_baseline_with_it() {
		CASCR_Checks_Accounts::role_capability_drift();

		add_role( 'cascr_accepted_role', 'CASCR Accepted Role', array( 'read' => true ) );

		$drift = CASCR_Checks_Accounts::role_capability_drift();

		CASCR_Store::ignore( 'role_capability_drift', $drift );
		CASCR_Store::unignore( 'role_capability_drift' );

		$after = CASCR_Checks_Accounts::role_capability_drift();

		remove_role( 'cascr_accepted_role' );

		$this->assertSame( 'warn', $drift['status'], 'The change is reported before it is accepted.' );
		$this->assertSame( 'pass', $after['status'], 'The accepted state is the new comparison point.' );
	}

	public function test_an_escalated_role_still_fails_after_the_split() {
		CASCR_Checks_Accounts::role_capability_drift();

		$role = get_role( 'subscriber' );
		$role->add_cap( 'install_plugins' );

		$result = CASCR_Checks_Accounts::role_capability_drift();

		$role->remove_cap( 'install_plugins' );

		$this->assertSame( 'fail', $result['status'] );
	}

	/* ---------------------------------------------------------------------
	 * Application passwords
	 * ------------------------------------------------------------------- */

	/**
	 * Without HTTPS the core function is false on every site, so reading it as
	 * "switched off" passed a check that had looked at nothing.
	 */
	public function test_application_passwords_over_plain_http_are_inconclusive() {
		if ( ! function_exists( 'wp_is_application_passwords_available' ) || wp_is_application_passwords_available() ) {
			$this->markTestSkipped( 'Application passwords are available in this environment.' );
		}

		$result = CASCR_Checks_Accounts::application_password_inventory();

		$this->assertSame( 'inconclusive', $result['status'] );
		$this->assertNotSame( '', $result['fix'] );
	}

	/* ---------------------------------------------------------------------
	 * Uploads
	 * ------------------------------------------------------------------- */

	/**
	 * An installer handed out through the media library is a questionable
	 * upload. The web server does not run it, so it is not code execution.
	 */
	public function test_a_file_the_server_cannot_run_is_only_a_warning() {
		$file = $this->write_upload( 'setup.exe', 'MZ' );

		$result = CASCR_Checks_Files::unallowed_files();

		$this->clean_uploads( $file );

		$this->assertSame( 'warn', $result['status'] );
		$this->assertNotEmpty( $result['items'] );
	}

	public function test_a_php_file_in_uploads_is_still_a_failure() {
		$file = $this->write_upload( 'shell.php', "<?php system( \$_GET['c'] );\n" );

		$result = CASCR_Checks_Files::unallowed_files();

		$this->clean_uploads( $file );

		$this->assertSame( 'fail', $result['status'] );
	}

	/* ---------------------------------------------------------------------
	 * Permissions
	 * ------------------------------------------------------------------- */

	/**
	 * wp-content is scored by directory_permissions and was scored again by
	 * the sweep, so a single chmod cost the grade twice. It has to leave the
	 * sweep and stay in the check that names it.
	 */
	public function test_a_directory_with_its_own_check_is_not_counted_twice() {
		$dir = ABSPATH . 'wp-content';

		if ( ! is_dir( $dir ) ) {
			$this->markTestSkipped( 'The content directory does not sit below ABSPATH here.' );
		}

		$before = fileperms( $dir ) & 0777;

		if ( ! @chmod( $dir, 0777 ) ) { // phpcs:ignore
			$this->markTestSkipped( 'The permissions of the content directory cannot be changed here.' );
		}

		clearstatcache();

		$sweep = CASCR_Checks_Files::world_writable_paths();
		$core  = CASCR_Checks_Files::directory_permissions();

		chmod( $dir, $before );
		clearstatcache();

		$this->assertNotContains( 'wp-content', $sweep['items'], 'The sweep leaves it to the check that scores it.' );
		$this->assertSame( 'fail', $core['status'], 'And that check still reports it, so nothing falls through.' );
	}

	/* ---------------------------------------------------------------------
	 * PHP handling
	 * ------------------------------------------------------------------- */

	/**
	 * A server that returns the probe verbatim did not run it. Saying it did
	 * sends the reader after a problem they do not have and hides the one they
	 * do.
	 */
	public function test_php_source_handed_out_as_text_is_told_apart_from_execution() {
		$this->body = '<?php echo "CASCR_PHP_EXEC_TEST";';

		$served = CASCR_Checks_Files::php_execution();

		if ( 'inconclusive' === $served['status'] ) {
			$this->markTestSkipped( 'The uploads directory is not writable here.' );
		}

		CASCR_Http::reset();
		$this->body = 'CASCR_PHP_EXEC_TEST';

		$executed = CASCR_Checks_Files::php_execution();

		$this->assertSame( 'fail', $served['status'] );
		$this->assertSame( 'fail', $executed['status'] );
		$this->assertNotSame( $served['summary'], $executed['summary'], 'Served and executed need their own finding.' );
		$this->assertNotSame( $served['fix'], $executed['fix'], 'Served and executed need their own remediation.' );
	}

	/* ---------------------------------------------------------------------
	 * Database dumps
	 * ------------------------------------------------------------------- */

	/**
	 * A request that failed says nothing about whether the dump is reachable,
	 * and "sits there but is not served" is the wrong half to guess.
	 */
	public function test_an_unreachable_dump_is_not_declared_safe() {
		$dump = WP_CONTENT_DIR . '/cascr-probe.sql';

		if ( false === file_put_contents( $dump, "-- probe\n" ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Fixture.
			$this->markTestSkipped( 'wp-content is not writable here.' );
		}

		$this->fails = true;

		$result = CASCR_Checks_Files::exposed_db_dumps();

		unlink( $dump );

		$this->assertSame( 'inconclusive', $result['status'] );
	}

	/* ---------------------------------------------------------------------
	 * Rule files
	 * ------------------------------------------------------------------- */

	/**
	 * IIS is served from web.config; WordPress never writes an .htaccess
	 * there, so the missing file cannot be a standing warning.
	 */
	public function test_iis_does_not_get_the_htaccess_warning() {
		$previous                   = isset( $_SERVER['SERVER_SOFTWARE'] ) ? $_SERVER['SERVER_SOFTWARE'] : null;
		$_SERVER['SERVER_SOFTWARE'] = 'Microsoft-IIS/10.0';

		$result = CASCR_Checks_Files::htaccess();

		if ( null === $previous ) {
			unset( $_SERVER['SERVER_SOFTWARE'] );
		} else {
			$_SERVER['SERVER_SOFTWARE'] = $previous;
		}

		$this->assertSame( 'pass', $result['status'], 'A warning nothing can clear is noise.' );
		$this->assertSame( 0, $result['score'] );
	}

	/* ---------------------------------------------------------------------
	 * Helpers
	 * ------------------------------------------------------------------- */

	/**
	 * Every account gets the meta, so no administrator is left uncovered.
	 *
	 * The test installation already has an administrator of its own, and a
	 * multisite run adds the network administrator on top.
	 *
	 * @param string $key   Meta key.
	 * @param mixed  $value Meta value.
	 */
	private function give_everyone( $key, $value ) {
		foreach ( get_users( array( 'fields' => 'ID' ) ) as $id ) {
			update_user_meta( $id, $key, $value );
		}
	}

	/**
	 * @param string $name     File name below the uploads directory.
	 * @param string $contents File contents.
	 * @return string Absolute path.
	 */
	private function write_upload( $name, $contents ) {
		$dir = wp_upload_dir();

		if ( empty( $dir['basedir'] ) || ! wp_mkdir_p( $dir['basedir'] . '/cascr-probe' ) ) {
			$this->markTestSkipped( 'The uploads directory is not writable here.' );
		}

		$path = $dir['basedir'] . '/cascr-probe/' . $name;
		file_put_contents( $path, $contents ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Fixture.

		return $path;
	}

	/**
	 * @param string $path Absolute path returned by write_upload().
	 */
	private function clean_uploads( $path ) {
		unlink( $path );
		rmdir( dirname( $path ) );
	}
}
