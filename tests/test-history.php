<?php
/**
 * The long term record of completed runs.
 *
 * @package CmsAdmins\SecurityCheck
 */

class Test_CASCR_History extends WP_UnitTestCase {

	public function tear_down() {
		foreach ( CASCR_Store::option_names() as $option ) {
			delete_option( $option );
		}

		parent::tear_down();
	}

	/**
	 * A run in the shape CASCR_Store stores it, reduced to what the history reads.
	 *
	 * @param array  $statuses Status keyed by test identifier.
	 * @param int    $time     Time of the run.
	 * @param string $grade    Letter grade.
	 * @param float  $risk     Risk percentage.
	 * @return array
	 */
	private function make_run( $statuses, $time, $grade = 'B', $risk = 20.0 ) {
		$run = array(
			'generated' => $time,
			'grade'     => $grade,
			'risk'      => $risk,
			'tests'     => array(),
		);

		foreach ( $statuses as $id => $status ) {
			$run['tests'][ $id ] = array(
				'status'  => $status,
				'ignored' => false,
			);
		}

		return $run;
	}

	public function test_a_point_carries_time_grade_and_every_status() {
		CASCR_History::append(
			$this->make_run(
				array(
					'wp_debug'        => CASCR_Result::STATUS_FAIL,
					'db_prefix'       => CASCR_Result::STATUS_WARN,
					'core_version'    => CASCR_Result::STATUS_PASS,
					'directory_index' => CASCR_Result::STATUS_INCONCLUSIVE,
				),
				1758700000,
				'C',
				38.5
			)
		);

		$point = CASCR_History::latest();

		$this->assertSame( 1758700000, $point['t'] );
		$this->assertSame( 'C', $point['g'] );
		$this->assertSame( 38.5, $point['r'] );
		$this->assertSame(
			array(
				'wp_debug'        => 'f',
				'db_prefix'       => 'w',
				'core_version'    => 'p',
				'directory_index' => 'u',
			),
			$point['tests']
		);
	}

	/**
	 * The starting point is what the head line refers to. It stays, the second
	 * oldest goes instead, otherwise "started on" quietly starts lying after
	 * two dozen runs.
	 */
	public function test_the_second_oldest_point_falls_off_and_the_start_stays() {
		for ( $i = 1; $i <= CASCR_History::LIMIT + 1; $i++ ) {
			CASCR_History::append( $this->make_run( array( 'wp_debug' => CASCR_Result::STATUS_PASS ), 1000 + $i ) );
		}

		$history = CASCR_History::all();

		$this->assertCount( CASCR_History::LIMIT, $history );
		$this->assertSame( 1001, CASCR_History::first()['t'] );
		$this->assertSame( 1003, $history[1]['t'] );
		$this->assertSame( 1000 + CASCR_History::LIMIT + 1, CASCR_History::latest()['t'] );
	}

	/**
	 * A check that broke again in between is one fix, dated at the most recent
	 * move to pass, not two.
	 */
	public function test_a_check_fixed_twice_is_counted_once() {
		CASCR_History::append( $this->make_run( array( 'wp_debug' => CASCR_Result::STATUS_FAIL ), 1000 ) );
		CASCR_History::append( $this->make_run( array( 'wp_debug' => CASCR_Result::STATUS_PASS ), 2000 ) );
		CASCR_History::append( $this->make_run( array( 'wp_debug' => CASCR_Result::STATUS_FAIL ), 3000 ) );
		CASCR_History::append( $this->make_run( array( 'wp_debug' => CASCR_Result::STATUS_PASS ), 4000 ) );

		$resolved = CASCR_History::resolved();

		$this->assertSame( array( 'wp_debug' => 4000 ), $resolved );
	}

	public function test_a_check_that_broke_again_is_not_counted_as_resolved() {
		CASCR_History::append( $this->make_run( array( 'wp_debug' => CASCR_Result::STATUS_FAIL ), 1000 ) );
		CASCR_History::append( $this->make_run( array( 'wp_debug' => CASCR_Result::STATUS_PASS ), 2000 ) );
		CASCR_History::append( $this->make_run( array( 'wp_debug' => CASCR_Result::STATUS_FAIL ), 3000 ) );

		$this->assertSame( array(), CASCR_History::resolved() );
	}

	/**
	 * A site that cannot reach itself over HTTP leaves up to fifteen checks
	 * unreachable in any given run. A fix recorded earlier has to survive that,
	 * otherwise the archive empties and refills from one run to the next.
	 */
	public function test_a_fix_survives_an_unreachable_last_run() {
		CASCR_History::append( $this->make_run( array( 'wp_debug' => CASCR_Result::STATUS_FAIL ), 1000 ) );
		CASCR_History::append( $this->make_run( array( 'wp_debug' => CASCR_Result::STATUS_PASS ), 2000 ) );
		CASCR_History::append( $this->make_run( array( 'wp_debug' => CASCR_Result::STATUS_INCONCLUSIVE ), 3000 ) );

		$this->assertSame( array( 'wp_debug' => 2000 ), CASCR_History::resolved() );
	}

	/**
	 * Muting a check that was fixed is not taking the fix back either.
	 */
	public function test_a_fix_survives_a_muted_last_run() {
		CASCR_History::append( $this->make_run( array( 'wp_debug' => CASCR_Result::STATUS_FAIL ), 1000 ) );
		CASCR_History::append( $this->make_run( array( 'wp_debug' => CASCR_Result::STATUS_PASS ), 2000 ) );

		$muted = $this->make_run( array( 'wp_debug' => CASCR_Result::STATUS_PASS ), 3000 );
		$muted['tests']['wp_debug']['ignored'] = true;

		CASCR_History::append( $muted );

		$this->assertSame( 'i', CASCR_History::latest()['tests']['wp_debug'] );
		$this->assertSame( array( 'wp_debug' => 2000 ), CASCR_History::resolved() );
	}

	/**
	 * An unreachable endpoint is not a change of mind, so it must not create a
	 * fix once the check answers again.
	 */
	public function test_an_inconclusive_run_in_between_does_not_break_the_chain() {
		CASCR_History::append( $this->make_run( array( 'wp_debug' => CASCR_Result::STATUS_FAIL ), 1000 ) );
		CASCR_History::append( $this->make_run( array( 'wp_debug' => CASCR_Result::STATUS_INCONCLUSIVE ), 2000 ) );
		CASCR_History::append( $this->make_run( array( 'wp_debug' => CASCR_Result::STATUS_PASS ), 3000 ) );

		$this->assertSame( array( 'wp_debug' => 3000 ), CASCR_History::resolved() );
	}

	public function test_the_two_old_runs_become_the_first_two_points() {
		update_option( CASCR_Store::OPTION_PREVIOUS, $this->make_run( array( 'wp_debug' => CASCR_Result::STATUS_FAIL ), 1000, 'F', 70.0 ), false );
		update_option( CASCR_Store::OPTION_LAST, $this->make_run( array( 'wp_debug' => CASCR_Result::STATUS_PASS ), 2000, 'A', 4.0 ), false );

		$this->assertTrue( CASCR_History::migrate() );

		$history = CASCR_History::all();

		$this->assertCount( 2, $history );
		$this->assertSame( 1000, $history[0]['t'] );
		$this->assertSame( 'F', $history[0]['g'] );
		$this->assertSame( 2000, $history[1]['t'] );
	}

	public function test_the_migration_never_runs_twice() {
		update_option( CASCR_Store::OPTION_LAST, $this->make_run( array( 'wp_debug' => CASCR_Result::STATUS_PASS ), 2000 ), false );

		$this->assertTrue( CASCR_History::migrate() );
		$this->assertFalse( CASCR_History::migrate() );
		$this->assertCount( 1, CASCR_History::all() );
	}

	public function test_nothing_is_written_without_an_earlier_run() {
		$this->assertFalse( CASCR_History::migrate() );
		$this->assertSame( array(), CASCR_History::all() );
	}
}
