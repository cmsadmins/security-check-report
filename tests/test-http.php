<?php
/**
 * The request layer and the checks that decide on what a URL serves.
 *
 * Every exposed_* check trusts CASCR_Http::is_public. A mistake there turns a
 * readable .git folder into a quiet "pass", so the answer is pinned per case.
 *
 * @package CmsAdmins\SecurityCheck
 */

class Test_CASCR_Http extends WP_UnitTestCase {

	/**
	 * Canned answers keyed by URL path, anything else gets a 404.
	 *
	 * @var array
	 */
	private $routes = array();

	/**
	 * Number of requests that reached the network layer.
	 *
	 * @var int
	 */
	private $requests = 0;

	public function set_up() {
		parent::set_up();
		CASCR_Http::reset();
		$this->routes   = array();
		$this->requests = 0;
		add_filter( 'pre_http_request', array( $this, 'mock_http' ), 10, 3 );
	}

	public function tear_down() {
		remove_filter( 'pre_http_request', array( $this, 'mock_http' ), 10 );
		CASCR_Http::reset();
		parent::tear_down();
	}

	/**
	 * @param mixed  $preempt Short circuit value.
	 * @param array  $args    Request arguments.
	 * @param string $url     Requested URL.
	 * @return array
	 */
	public function mock_http( $preempt, $args, $url ) {
		unset( $preempt, $args );
		++$this->requests;

		$path   = (string) wp_parse_url( $url, PHP_URL_PATH );
		$answer = isset( $this->routes[ $path ] ) ? $this->routes[ $path ] : array( 404, 'Not Found' );

		return array(
			'headers'  => array(),
			'body'     => $answer[1],
			'response' => array(
				'code'    => $answer[0],
				'message' => '',
			),
			'cookies'  => array(),
			'filename' => null,
		);
	}

	/**
	 * @param string $path Path below the site root.
	 * @param int    $code Status code.
	 * @param string $body Response body.
	 */
	private function serve( $path, $code, $body ) {
		$this->routes[ (string) wp_parse_url( home_url( '/' . $path ), PHP_URL_PATH ) ] = array( $code, $body );
	}

	public function test_a_body_served_with_200_or_206_is_public() {
		$this->serve( 'a', 200, 'content' );
		$this->serve( 'b', 206, 'content' );

		$this->assertTrue( CASCR_Http::is_public( home_url( '/a' ) ) );
		$this->assertTrue( CASCR_Http::is_public( home_url( '/b' ) ) );
	}

	public function test_an_empty_200_or_an_error_status_is_not_public() {
		$this->serve( 'empty', 200, "  \n" );

		$this->assertFalse( CASCR_Http::is_public( home_url( '/empty' ) ) );
		$this->assertFalse( CASCR_Http::is_public( home_url( '/missing' ) ) );
	}

	/**
	 * Hosts that answer every path with their own 200 page must not count.
	 */
	public function test_the_needle_must_be_in_the_body() {
		$this->serve( 'soft404', 200, '<html>Page not found</html>' );
		$this->serve( 'real', 200, "[core]\n\trepositoryformatversion = 0" );

		$this->assertFalse( CASCR_Http::is_public( home_url( '/soft404' ), '[core]' ) );
		$this->assertTrue( CASCR_Http::is_public( home_url( '/real' ), '[core]' ) );
	}

	public function test_a_failed_request_is_undeterminable() {
		remove_filter( 'pre_http_request', array( $this, 'mock_http' ), 10 );
		add_filter(
			'pre_http_request',
			function () {
				return new WP_Error( 'http_request_failed', 'down' );
			}
		);

		$this->assertNull( CASCR_Http::is_public( home_url( '/x' ) ) );
	}

	public function test_identical_get_requests_hit_the_network_once() {
		CASCR_Http::get( home_url( '/same' ) );
		CASCR_Http::get( home_url( '/same' ) );

		$this->assertSame( 1, $this->requests );
	}

	public function test_post_requests_are_never_cached() {
		CASCR_Http::post( home_url( '/form' ) );
		CASCR_Http::post( home_url( '/form' ) );

		$this->assertSame( 2, $this->requests );
	}

	public function test_a_readable_git_folder_fails() {
		$this->serve( '.git/HEAD', 200, 'ref: refs/heads/main' );

		$result = CASCR_Checks_Files::exposed_repo_dirs();

		$this->assertSame( 'fail', $result['status'] );
		$this->assertContains( '.git/HEAD', $result['items'] );
	}

	public function test_no_readable_repository_passes() {
		$this->assertSame( 'pass', CASCR_Checks_Files::exposed_repo_dirs()['status'] );
	}

	public function test_an_autoindex_page_is_reported() {
		$this->serve( 'wp-content/uploads/', 200, '<html><head><title>Index of /wp-content/uploads</title></head></html>' );

		$result = CASCR_Checks_Files::directory_listing();

		$this->assertSame( 'warn', $result['status'] );
		$this->assertSame( array( 'wp-content/uploads/' ), $result['items'] );
	}

	public function test_a_server_that_hides_directories_passes() {
		$this->assertSame( 'pass', CASCR_Checks_Files::directory_listing()['status'] );
	}
}
