<?php
/**
 * The REST routes and their permission gates.
 *
 * @package CmsAdmins\SecurityCheck
 */

class Test_CASCR_REST extends WP_UnitTestCase {

	/**
	 * @var WP_REST_Server
	 */
	private $server;

	public function set_up() {
		parent::set_up();

		global $wp_rest_server;
		$wp_rest_server = new WP_REST_Server();
		$this->server   = $wp_rest_server;

		do_action( 'rest_api_init', $this->server );

		add_filter( 'pre_http_request', array( $this, 'mock_http' ) );
	}

	public function tear_down() {
		remove_filter( 'pre_http_request', array( $this, 'mock_http' ) );

		global $wp_rest_server;
		$wp_rest_server = null;

		foreach ( CASCR_Store::option_names() as $option ) {
			delete_option( $option );
		}

		CASCR_Http::reset();
		parent::tear_down();
	}

	/**
	 * @return array
	 */
	public function mock_http() {
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

	/**
	 * @param string $method HTTP method.
	 * @param string $route  Route below the namespace.
	 * @param array  $body   Request body.
	 * @return WP_REST_Response
	 */
	private function call( $method, $route, $body = array() ) {
		$request = new WP_REST_Request( $method, '/' . CASCR_REST::NAMESPACE_V1 . $route );

		foreach ( $body as $key => $value ) {
			$request->set_param( $key, $value );
		}

		return $this->server->dispatch( $request );
	}

	public function test_all_routes_are_registered() {
		$routes = $this->server->get_routes();

		foreach ( array( '/tests', '/run/(?P<id>[a-z0-9_]+)', '/report', '/ignore' ) as $route ) {
			$this->assertArrayHasKey( '/' . CASCR_REST::NAMESPACE_V1 . $route, $routes );
		}
	}

	public function test_a_logged_out_visitor_is_rejected_on_every_route() {
		wp_set_current_user( 0 );

		$this->assertSame( 401, $this->call( 'GET', '/tests' )->get_status() );
		$this->assertSame( 401, $this->call( 'POST', '/run/wp_debug' )->get_status() );
		$this->assertSame( 401, $this->call( 'GET', '/report' )->get_status() );
		$this->assertSame( 401, $this->call( 'POST', '/ignore', array( 'id' => 'wp_debug' ) )->get_status() );
	}

	public function test_a_subscriber_is_rejected() {
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'subscriber' ) ) );

		$this->assertSame( 403, $this->call( 'POST', '/run/wp_debug' )->get_status() );
	}

	public function test_an_administrator_can_list_the_checks() {
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );

		$response = $this->call( 'GET', '/tests' );
		$data     = $response->get_data();

		$this->assertSame( 200, $response->get_status() );
		$this->assertCount( count( CASCR_Registry::ids() ), $data['tests'] );
		$this->assertArrayHasKey( 'categories', $data );
	}

	public function test_an_administrator_can_run_a_single_check() {
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );

		$response = $this->call( 'POST', '/run/wp_debug' );
		$data     = $response->get_data();

		$this->assertSame( 200, $response->get_status() );
		$this->assertSame( 'wp_debug', $data['id'] );
		$this->assertArrayHasKey( 'status', $data );
		$this->assertArrayHasKey( 'items', $data );
	}

	public function test_an_unknown_check_is_rejected_before_it_is_dispatched() {
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );

		$this->assertSame( 400, $this->call( 'POST', '/run/does_not_exist' )->get_status() );
	}

	/**
	 * The grade is computed on the server. A browser that posts a made-up score
	 * for an unknown identifier must not be able to influence it.
	 */
	public function test_only_known_checks_are_scored() {
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );

		$results = array(
			'wp_debug'      => CASCR_Result::pass( 'ok' ),
			'made_up_check' => CASCR_Result::fail( 'nonsense', 10 ),
		);

		$response = $this->call( 'POST', '/report', array( 'results' => $results ) );
		$data     = $response->get_data();

		$this->assertSame( 200, $response->get_status() );
		$this->assertSame( 1, $data['summary']['counts']['total'] );
		$this->assertSame( 'A', $data['summary']['grade'] );
	}

	public function test_a_report_can_be_read_back() {
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );

		$this->call( 'POST', '/report', array( 'results' => array( 'wp_debug' => CASCR_Result::pass( 'ok' ) ) ) );

		$data = $this->call( 'GET', '/report' )->get_data();

		$this->assertNotNull( $data['run'] );
		$this->assertSame( 'A', $data['run']['grade'] );
	}

	public function test_muting_and_unmuting_through_the_api() {
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );

		$this->assertTrue( $this->call( 'POST', '/ignore', array( 'id' => 'wp_debug' ) )->get_data()['ignored'] );
		$this->assertArrayHasKey( 'wp_debug', CASCR_Store::ignored() );

		$this->assertFalse(
			$this->call( 'POST', '/ignore', array( 'id' => 'wp_debug', 'ignore' => false ) )->get_data()['ignored']
		);
		$this->assertArrayNotHasKey( 'wp_debug', CASCR_Store::ignored() );
	}
}
