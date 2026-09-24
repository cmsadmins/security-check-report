<?php
/**
 * The reminders outside the plugin screen.
 *
 * @package CmsAdmins\SecurityCheck
 */

class Test_CASCR_Nudges extends WP_UnitTestCase {

	public function set_up() {
		parent::set_up();

		if ( ! function_exists( 'wp_add_dashboard_widget' ) ) {
			require_once ABSPATH . 'wp-admin/includes/dashboard.php';
		}
	}

	public function tear_down() {
		foreach ( CASCR_Store::option_names() as $option ) {
			delete_option( $option );
		}

		parent::tear_down();
	}

	/**
	 * Writes a stored run with the given counts and age.
	 *
	 * @param array $counts Status counts, missing keys default to zero.
	 * @param int   $age    How long ago the run finished, in seconds.
	 */
	private function store_run( $counts, $age = 0 ) {
		update_option(
			CASCR_Store::OPTION_LAST,
			array(
				'generated' => time() - $age,
				'grade'     => 'C',
				'risk'      => 38.5,
				'counts'    => array_merge(
					array(
						'pass'         => 0,
						'warn'         => 0,
						'fail'         => 0,
						'inconclusive' => 0,
						'ignored'      => 0,
						'total'        => 60,
					),
					$counts
				),
				'tests'     => array(
					'wp_debug' => array(
						'status'  => CASCR_Result::STATUS_FAIL,
						'score'   => 8,
						'summary' => '',
						'ignored' => false,
					),
				),
			),
			false
		);

		// Written by CASCR_Store on every real write, and the only thing the
		// bubble reads.
		update_option( CASCR_Store::OPTION_BADGE, isset( $counts['fail'] ) ? (int) $counts['fail'] : 0 );
	}

	/**
	 * Registers the widget on a fresh dashboard and returns what was registered.
	 *
	 * @return array Widget identifiers mapped to their box definition.
	 */
	private function dashboard_widgets() {
		global $wp_meta_boxes;

		set_current_screen( 'dashboard' );
		$wp_meta_boxes = array();

		CASCR_Nudges::add_widget();

		return isset( $wp_meta_boxes['dashboard']['normal']['core'] )
			? $wp_meta_boxes['dashboard']['normal']['core']
			: array();
	}

	public function test_the_menu_title_stays_untouched_without_a_run() {
		$this->assertSame( 'Security Check', CASCR_Nudges::menu_title( 'Security Check' ) );
	}

	public function test_failures_add_a_bubble_with_their_number() {
		$this->store_run( array( 'fail' => 3 ) );

		$title = CASCR_Nudges::menu_title( 'Security Check' );

		$this->assertStringContainsString( 'update-plugins count-3', $title );
		$this->assertStringContainsString( '>3<', $title );
		$this->assertStringContainsString( 'screen-reader-text', $title );
	}

	/**
	 * Straight after an update the count has not been written yet. The bubble
	 * stays dark instead of pulling the whole run in to draw itself.
	 */
	public function test_the_bubble_stays_dark_until_the_count_is_written() {
		$this->store_run( array( 'fail' => 3 ) );
		delete_option( CASCR_Store::OPTION_BADGE );

		$this->assertSame( 'Security Check', CASCR_Nudges::menu_title( 'Security Check' ) );
	}

	public function test_warnings_alone_do_not_light_the_bubble() {
		$this->store_run( array( 'warn' => 7 ) );

		$this->assertSame( 'Security Check', CASCR_Nudges::menu_title( 'Security Check' ) );
	}

	public function test_a_recent_run_needs_no_reminder() {
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );
		$this->store_run( array( 'fail' => 1 ), 3 * DAY_IN_SECONDS );

		$this->assertFalse( CASCR_Nudges::is_due() );
	}

	public function test_a_run_older_than_thirty_days_is_due() {
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );
		$this->store_run( array( 'fail' => 1 ), 31 * DAY_IN_SECONDS );

		$this->assertTrue( CASCR_Nudges::is_due() );
	}

	public function test_a_dismissed_reminder_stays_dismissed() {
		$user = self::factory()->user->create( array( 'role' => 'administrator' ) );
		wp_set_current_user( $user );
		$this->store_run( array( 'fail' => 1 ), 31 * DAY_IN_SECONDS );

		update_user_meta( $user, CASCR_Nudges::META_DISMISSED, time() );

		$this->assertFalse( CASCR_Nudges::is_due() );
	}

	public function test_without_the_capability_there_is_neither_widget_nor_notice() {
		$this->store_run( array( 'fail' => 1 ), 31 * DAY_IN_SECONDS );

		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );
		$this->assertTrue( CASCR_Nudges::is_due() );
		$this->assertArrayHasKey( CASCR_Nudges::WIDGET_ID, $this->dashboard_widgets() );

		wp_set_current_user( self::factory()->user->create( array( 'role' => 'subscriber' ) ) );
		$this->assertFalse( CASCR_Nudges::is_due() );
		$this->assertArrayNotHasKey( CASCR_Nudges::WIDGET_ID, $this->dashboard_widgets() );
	}
}
