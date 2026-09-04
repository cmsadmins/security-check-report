<?php
/**
 * Security gate tests for the AJAX endpoint: nonce and capability checks
 * must reject unauthorized callers.
 *
 * @package CmsAdmins\SecurityCheck
 */

class Test_CASCR_Ajax_Security extends WP_Ajax_UnitTestCase {

	public function set_up() {
		parent::set_up();
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

	public function test_request_without_nonce_is_rejected() {
		$this->_setRole( 'administrator' );
		$_POST['test_name'] = 'wp_debug';

		$this->expectException( 'WPAjaxDieStopException' );
		$this->expectExceptionMessage( '-1' );
		$this->_handleAjax( 'run_security_check' );
	}

	public function test_subscriber_with_valid_nonce_is_rejected() {
		$this->_setRole( 'subscriber' );
		$_POST['security_nonce'] = wp_create_nonce( 'cascr_security_nonce' );
		$_POST['test_name']      = 'wp_debug';

		try {
			$this->_handleAjax( 'run_security_check' );
		} catch ( WPAjaxDieContinueException $e ) {
			// wp_send_json_error() stops execution this way in tests.
			unset( $e );
		}

		$response = json_decode( $this->_last_response, true );
		$this->assertIsArray( $response );
		$this->assertFalse( $response['success'] );
	}

	public function test_admin_with_valid_nonce_gets_test_result() {
		$this->_setRole( 'administrator' );
		$_POST['security_nonce'] = wp_create_nonce( 'cascr_security_nonce' );
		$_POST['test_name']      = 'wp_debug';

		try {
			$this->_handleAjax( 'run_security_check' );
		} catch ( WPAjaxDieContinueException $e ) {
			unset( $e );
		}

		$response = json_decode( $this->_last_response, true );
		$this->assertIsArray( $response );
		$this->assertTrue( $response['success'] );
		$this->assertArrayHasKey( 'result', $response['data'] );
		$this->assertArrayHasKey( 'score', $response['data'] );
	}

	public function test_invalid_test_name_is_rejected() {
		$this->_setRole( 'administrator' );
		$_POST['security_nonce'] = wp_create_nonce( 'cascr_security_nonce' );
		$_POST['test_name']      = 'does_not_exist';

		try {
			$this->_handleAjax( 'run_security_check' );
		} catch ( WPAjaxDieContinueException $e ) {
			unset( $e );
		}

		$response = json_decode( $this->_last_response, true );
		$this->assertIsArray( $response );
		$this->assertFalse( $response['success'] );
	}
}
