<?php
/**
 * Integration tests for CASCR_SecurityCheck.
 *
 * All outgoing HTTP requests are short-circuited so the suite runs offline
 * and deterministic.
 *
 * @package CmsAdmins\SecurityCheck
 */

class Test_CASCR_SecurityCheck extends WP_UnitTestCase {

	/**
	 * @var CASCR_SecurityCheck
	 */
	private $plugin;

	public function set_up() {
		parent::set_up();
		$this->plugin = new CASCR_SecurityCheck();
		add_filter( 'pre_http_request', array( $this, 'mock_http_response' ) );
	}

	public function tear_down() {
		remove_filter( 'pre_http_request', array( $this, 'mock_http_response' ) );
		parent::tear_down();
	}

	public function mock_http_response() {
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

	private function call_private( $method, ...$args ) {
		$ref = new ReflectionMethod( CASCR_SecurityCheck::class, $method );
		$ref->setAccessible( true );
		return $ref->invoke( $this->plugin, ...$args );
	}

	public function test_exactly_45_security_tests_are_registered() {
		$tests = $this->call_private( 'get_security_tests' );

		$this->assertCount( 45, $tests );
		foreach ( $tests as $id => $callback ) {
			$this->assertIsString( $id );
			$this->assertIsArray( $callback, "Callback for test '{$id}' is not an instance callback." );
			$this->assertTrue(
				method_exists( $callback[0], $callback[1] ),
				"Callback method for test '{$id}' does not exist."
			);
		}
	}

	public function test_accordion_documents_every_test() {
		$accordion = $this->call_private( 'get_accordion' );
		$tests     = $this->call_private( 'get_security_tests' );

		$this->assertSameSize( $tests, $accordion );
	}

	public function test_config_contains_all_required_lists() {
		$ref = new ReflectionProperty( CASCR_SecurityCheck::class, 'config' );
		$ref->setAccessible( true );
		$config = $ref->getValue( $this->plugin );

		$required = array(
			'security_plugins',
			'brute_force_plugins',
			'login_protection_plugins',
			'security_headers',
			'malware_signatures',
			'ignore_wp_core_files',
			'backup_plugins',
			'password_plugins',
			'two_factor_plugins',
			'unwanted_files',
		);

		foreach ( $required as $key ) {
			$this->assertArrayHasKey( $key, $config );
			$this->assertIsArray( $config[ $key ] );
			$this->assertNotEmpty( $config[ $key ], "Config list '{$key}' is empty." );
		}
	}

	public function test_every_check_returns_result_string_and_bounded_score() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$tests = $this->call_private( 'get_security_tests' );

		foreach ( $tests as $id => $callback ) {
			// The check methods are private, so invoke them via reflection.
			$outcome = $this->call_private( $callback[1] );

			$this->assertIsArray( $outcome, "Test '{$id}' did not return an array." );
			$this->assertArrayHasKey( 'result', $outcome, "Test '{$id}' has no 'result'." );
			$this->assertArrayHasKey( 'score', $outcome, "Test '{$id}' has no 'score'." );
			$this->assertIsString( $outcome['result'], "Test '{$id}' result is not a string." );
			$this->assertNotSame( '', $outcome['result'], "Test '{$id}' result is empty." );
			$this->assertIsNumeric( $outcome['score'], "Test '{$id}' score is not numeric." );
			$this->assertGreaterThanOrEqual( 0, $outcome['score'], "Test '{$id}' score below 0." );
			$this->assertLessThanOrEqual( 10, $outcome['score'], "Test '{$id}' score above 10." );
		}
	}

	public function test_admin_menu_is_registered_for_admins() {
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );
		do_action( 'admin_menu' );

		$this->assertNotSame( '', menu_page_url( 'security-check-report', false ) );
	}
}
