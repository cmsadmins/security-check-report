<?php
/**
 * The report as a WordPress ability.
 *
 * @package CmsAdmins\SecurityCheck
 */

class Test_CASCR_Abilities extends WP_UnitTestCase {

	public function tear_down() {
		foreach ( CASCR_Store::option_names() as $option ) {
			delete_option( $option );
		}

		wp_set_current_user( 0 );
		parent::tear_down();
	}

	/**
	 * @return WP_Ability
	 */
	private function ability() {
		$ability = wp_get_ability( CASCR_Abilities::GET_REPORT );
		$this->assertInstanceOf( 'WP_Ability', $ability );

		return $ability;
	}

	private function admin() {
		$user = self::factory()->user->create( array( 'role' => 'administrator' ) );
		if ( is_multisite() ) {
			grant_super_admin( $user );
		}
		wp_set_current_user( $user );
	}

	private function store_run() {
		$results = array();
		foreach ( CASCR_Registry::ids() as $id ) {
			$results[ $id ] = CASCR_Result::pass( 'ok' );
		}
		$results['wp_debug'] = CASCR_Result::fail( 'debug is on', 8, array( 'secret-admin' ) );

		CASCR_Runner::finish( $results );
	}

	public function test_the_ability_is_registered_as_read_only() {
		$ability = $this->ability();

		$this->assertTrue( $ability->get_meta()['annotations']['readonly'] );
		$this->assertTrue( $ability->get_meta()['show_in_rest'] );
	}

	public function test_a_subscriber_may_not_read_the_report() {
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'subscriber' ) ) );

		$this->assertInstanceOf( 'WP_Error', $this->ability()->execute() );
	}

	public function test_before_the_first_run_there_is_nothing_to_read() {
		$this->admin();

		$this->assertSame( array( 'run' => null ), $this->ability()->execute() );
	}

	public function test_the_report_carries_the_grade_but_no_raw_findings() {
		$this->store_run();
		$this->admin();

		$out = $this->ability()->execute();

		$this->assertNotInstanceOf( 'WP_Error', $out );
		$this->assertSame( CASCR_Store::last_run()['grade'], $out['run']['grade'] );
		$this->assertSame( 'wp_debug', $out['run']['tasks'][0]['id'] );
		$this->assertSame( array( 'wp_debug' ), wp_list_pluck( $out['run']['open'], 'id' ) );
		$this->assertStringNotContainsString( 'secret-admin', wp_json_encode( $out ) );
	}
}
