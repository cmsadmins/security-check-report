<?php
/**
 * Persistence, the run comparison and the mute mechanism.
 *
 * @package CmsAdmins\SecurityCheck
 */

class Test_CASCR_Store extends WP_UnitTestCase {

	public function tear_down() {
		foreach ( CASCR_Store::option_names() as $option ) {
			delete_option( $option );
		}

		CASCR_Registry::reset();
		parent::tear_down();
	}

	/**
	 * @param array $overrides Results keyed by identifier.
	 * @return array
	 */
	private function results( $overrides = array() ) {
		$results = array();

		foreach ( CASCR_Registry::ids() as $id ) {
			$results[ $id ] = isset( $overrides[ $id ] ) ? $overrides[ $id ] : CASCR_Result::pass( 'ok' );
		}

		return $results;
	}

	/**
	 * @param array $results Results keyed by identifier.
	 * @return array
	 */
	private function store( $results ) {
		return CASCR_Store::save_run( $results, CASCR_Scoring::summarize( $results ) );
	}

	public function test_a_run_is_stored_and_read_back() {
		$this->store( $this->results() );

		$run = CASCR_Store::last_run();

		$this->assertNotEmpty( $run );
		$this->assertSame( 'A', $run['grade'] );
		$this->assertCount( count( CASCR_Registry::ids() ), $run['tests'] );
	}

	public function test_the_previous_run_is_kept() {
		$this->store( $this->results() );
		$this->store( $this->results( array( 'wp_debug' => CASCR_Result::fail( 'debug is on', 8 ) ) ) );

		$this->assertSame( 'pass', CASCR_Store::previous_run()['tests']['wp_debug']['status'] );
		$this->assertSame( 'fail', CASCR_Store::last_run()['tests']['wp_debug']['status'] );
	}

	public function test_there_is_no_comparison_before_the_second_run() {
		$this->store( $this->results() );

		$this->assertNull( CASCR_Store::diff() );
	}

	public function test_diff_reports_new_failures_and_fixes() {
		$this->store(
			$this->results(
				array(
					'wp_debug'  => CASCR_Result::fail( 'debug is on', 8 ),
					'db_prefix' => CASCR_Result::pass( 'custom prefix' ),
				)
			)
		);

		$this->store(
			$this->results(
				array(
					'wp_debug'  => CASCR_Result::pass( 'debug is off' ),
					'db_prefix' => CASCR_Result::warn( 'default prefix', 4 ),
				)
			)
		);

		$diff = CASCR_Store::diff();

		$this->assertContains( 'db_prefix', $diff['broken'] );
		$this->assertContains( 'wp_debug', $diff['fixed'] );
		$this->assertNotContains( 'wp_debug', $diff['broken'] );
	}

	public function test_diff_reports_a_finding_whose_content_changed() {
		$this->store( $this->results( array( 'unallowed_files' => CASCR_Result::fail( 'one file', 9, array( 'a.php' ) ) ) ) );
		$this->store( $this->results( array( 'unallowed_files' => CASCR_Result::fail( 'two files', 9, array( 'a.php', 'b.php' ) ) ) ) );

		$diff = CASCR_Store::diff();

		$this->assertContains( 'unallowed_files', $diff['changed'] );
		$this->assertNotContains( 'unallowed_files', $diff['broken'] );
	}

	/**
	 * The summary is deliberately not part of the fingerprint, so a translation
	 * update does not look like a changed finding.
	 */
	public function test_the_fingerprint_ignores_the_wording() {
		$german  = CASCR_Result::fail( 'Zwei Dateien gefunden', 9, array( 'a.php', 'b.php' ) );
		$english = CASCR_Result::fail( 'Two files found', 9, array( 'b.php', 'a.php' ) );

		$this->assertSame( CASCR_Store::fingerprint( $german ), CASCR_Store::fingerprint( $english ) );
	}

	public function test_a_muted_finding_comes_back_once_it_changes() {
		$result = CASCR_Result::fail( 'one file', 9, array( 'a.php' ) );

		CASCR_Store::ignore( 'unallowed_files', $result, CASCR_Store::IGNORE_UNTIL_CHANGED );

		$this->assertTrue( CASCR_Store::is_ignored( 'unallowed_files', $result ) );

		$changed = CASCR_Result::fail( 'two files', 9, array( 'a.php', 'b.php' ) );

		$this->assertFalse(
			CASCR_Store::is_ignored( 'unallowed_files', $changed ),
			'A finding muted until it changes must reappear when it changes.'
		);
	}

	public function test_a_permanently_muted_finding_stays_quiet() {
		CASCR_Store::ignore( 'unallowed_files', CASCR_Result::fail( 'one file', 9, array( 'a.php' ) ), CASCR_Store::IGNORE_PERMANENT );

		$this->assertTrue(
			CASCR_Store::is_ignored( 'unallowed_files', CASCR_Result::fail( 'ten files', 10, array( 'x.php' ) ) )
		);
	}

	public function test_unmuting_works() {
		$result = CASCR_Result::fail( 'one file', 9, array( 'a.php' ) );

		CASCR_Store::ignore( 'unallowed_files', $result );
		CASCR_Store::unignore( 'unallowed_files' );

		$this->assertFalse( CASCR_Store::is_ignored( 'unallowed_files', $result ) );
	}

	public function test_unknown_checks_cannot_be_muted() {
		$this->assertFalse( CASCR_Store::ignore( 'not_a_real_check', CASCR_Result::pass( 'ok' ) ) );
	}

	/**
	 * Drift checks compare against the first observation. Overwriting it on
	 * every run would make the comparison meaningless.
	 */
	public function test_a_baseline_is_recorded_once_and_not_overwritten() {
		$this->assertTrue( CASCR_Store::remember( 'roles', array( 'a' ) ) );
		$this->assertFalse( CASCR_Store::remember( 'roles', array( 'b' ) ) );
		$this->assertSame( array( 'a' ), CASCR_Store::baseline( 'roles' ) );

		CASCR_Store::rebase( 'roles', array( 'b' ) );
		$this->assertSame( array( 'b' ), CASCR_Store::baseline( 'roles' ) );
	}

	public function test_baseline_returns_the_default_when_nothing_was_recorded() {
		$this->assertSame( 'fallback', CASCR_Store::baseline( 'never_set', 'fallback' ) );
	}
}
