<?php
/**
 * Milestones and the monthly streak.
 *
 * @package CmsAdmins\SecurityCheck
 */

class Test_CASCR_Milestones extends WP_UnitTestCase {

	public function tear_down() {
		foreach ( CASCR_Store::option_names() as $option ) {
			delete_option( $option );
		}

		CASCR_Registry::reset();
		parent::tear_down();
	}

	/**
	 * Runs a full pass through the runner, so the milestone hook fires.
	 *
	 * @param array $overrides Results keyed by identifier.
	 */
	private function run_with( $overrides = array() ) {
		$results = array();

		foreach ( CASCR_Registry::ids() as $id ) {
			$results[ $id ] = isset( $overrides[ $id ] ) ? $overrides[ $id ] : CASCR_Result::pass( 'ok' );
		}

		CASCR_Runner::finish( $results );
	}

	public function test_grade_a_is_recorded_once_with_its_first_date() {
		$this->run_with();
		$first = CASCR_Milestones::get()['reached']['first_a'];

		$this->run_with();

		$this->assertSame( $first, CASCR_Milestones::get()['reached']['first_a'] );
	}

	public function test_only_a_real_fix_counts_as_resolved() {
		$muted            = CASCR_Result::fail( 'editor on', 8 );
		$muted['ignored'] = true;

		$this->run_with(
			array(
				'wp_debug'  => CASCR_Result::fail( 'debug is on', 9 ),
				'file_edit' => CASCR_Result::fail( 'editor on', 8 ),
				'xmlrpc'    => CASCR_Result::warn( 'open', 5 ),
			)
		);
		$this->run_with(
			array(
				'file_edit' => $muted,
				'xmlrpc'    => CASCR_Result::inconclusive( 'unreachable' ),
			)
		);

		$this->assertSame( 1, CASCR_Milestones::get()['resolved'] );
	}

	public function test_an_open_critical_finding_holds_back_the_milestone() {
		// An existing state, so this is not the run that takes over the history.
		update_option( CASCR_Milestones::OPTION, array() );
		$this->run_with( array( 'php2shell' => CASCR_Result::warn( 'unclear', 6 ) ) );

		$this->assertArrayNotHasKey( 'no_critical', CASCR_Milestones::get()['reached'] );
		$this->assertContains( 'no_failed', CASCR_Milestones::new_in( CASCR_Store::last_run() ) );
	}

	public function test_the_streak_runs_across_the_turn_of_the_year() {
		$this->assertSame( 3, CASCR_Milestones::streak( array( '2025-11', '2025-12', '2026-01' ), '2026-01' ) );
	}

	public function test_the_current_month_may_still_be_open() {
		$this->assertSame( 2, CASCR_Milestones::streak( array( '2025-11', '2025-12' ), '2026-01' ) );
	}

	public function test_a_missed_month_ends_the_streak() {
		$this->assertSame( 1, CASCR_Milestones::streak( array( '2025-10', '2025-12' ), '2025-12' ) );
		$this->assertSame( 0, CASCR_Milestones::streak( array( '2025-10' ), '2026-01' ) );
	}

	public function test_muting_earns_no_milestone() {
		$muted            = CASCR_Result::fail( 'unpatched', 9 );
		$muted['ignored'] = true;

		$this->run_with( array( 'php2shell' => $muted ) );

		$reached = CASCR_Milestones::get()['reached'];
		$this->assertArrayNotHasKey( 'no_failed', $reached );
		$this->assertArrayNotHasKey( 'no_critical', $reached );
	}

	/**
	 * A site that was checked for months before milestones existed starts
	 * with what its history already shows, dated when it happened.
	 */
	public function test_an_existing_history_is_taken_over() {
		$ids    = CASCR_Registry::ids();
		$before = array_fill_keys( $ids, CASCR_History::MARK_PASS );
		$early  = strtotime( '2026-01-15 12:00:00' );
		$later  = strtotime( '2026-02-15 12:00:00' );

		$before['wp_debug'] = CASCR_History::MARK_FAIL;
		update_option(
			CASCR_History::OPTION,
			array(
				array(
					't'     => $early,
					'g'     => 'B',
					'r'     => 12.0,
					'tests' => $before,
				),
				array(
					't'     => $later,
					'g'     => 'A',
					'r'     => 0.0,
					'tests' => array_fill_keys( $ids, CASCR_History::MARK_PASS ),
				),
			)
		);

		$run = array(
			'generated' => time(),
			'grade'     => 'A',
			'tests'     => array(),
		);
		CASCR_Milestones::record( $run );
		$state = CASCR_Milestones::get();

		$this->assertSame( array(), CASCR_Milestones::new_in( $run ) );

		$this->assertSame( $later, $state['reached']['first_a'] );
		$this->assertSame( $later, $state['reached']['no_failed'] );
		$this->assertSame( $early, $state['reached']['no_critical'] );
		$this->assertSame( 1, $state['resolved'] );
		$this->assertContains( '2026-01', $state['months'] );
	}
}
