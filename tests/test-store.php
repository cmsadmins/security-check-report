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

	/**
	 * A re-check touches exactly one entry. Everything else has to stay the way
	 * the last full pass found it.
	 */
	public function test_a_single_test_can_be_replaced_after_a_recheck() {
		$this->store( $this->results() );

		$run = CASCR_Store::patch_test( 'wp_debug', CASCR_Result::fail( 'debug is on', 9 ) );

		$this->assertSame( 'fail', $run['tests']['wp_debug']['status'] );
		$this->assertSame( 'pass', $run['tests']['db_prefix']['status'] );
		$this->assertCount( count( CASCR_Registry::ids() ), $run['tests'] );
		$this->assertSame( 1, $run['counts']['fail'] );
		$this->assertSame( $run, CASCR_Store::last_run() );
	}

	public function test_a_recheck_is_noted_as_partial_and_rescores_the_run() {
		$this->store( $this->results( array( 'wp_debug' => CASCR_Result::fail( 'debug is on', 9 ) ) ) );

		$before = CASCR_Store::last_run();
		$run    = CASCR_Store::patch_test( 'wp_debug', CASCR_Result::pass( 'debug is off' ) );

		$this->assertArrayHasKey( 'wp_debug', $run['partial'] );
		$this->assertSame( 0, $run['counts']['fail'] );
		$this->assertLessThan( $before['risk'], $run['risk'] );
	}

	/**
	 * A partial pass is not a run, so it must not become a point on the curve.
	 */
	public function test_a_recheck_does_not_extend_the_history() {
		$this->store( $this->results() );

		CASCR_Store::patch_test( 'wp_debug', CASCR_Result::fail( 'debug is on', 9 ) );

		$this->assertCount( 1, CASCR_History::all() );
	}

	public function test_nothing_is_patched_without_a_stored_run() {
		$this->assertFalse( CASCR_Store::patch_test( 'wp_debug', CASCR_Result::pass( 'ok' ) ) );
	}

	public function test_an_unknown_identifier_is_not_patched_in() {
		$this->store( $this->results() );

		$this->assertFalse( CASCR_Store::patch_test( 'not_a_real_check', CASCR_Result::pass( 'ok' ) ) );
	}

	/**
	 * Anyone with a stored run agreed back when the checkbox was still asked on
	 * every visit. Asking again after an update would be a step backwards.
	 */
	public function test_an_existing_run_counts_as_consent() {
		$this->assertFalse( CASCR_Store::consent() );

		$this->store( $this->results() );

		$this->assertTrue( CASCR_Store::consent() );
	}

	public function test_consent_can_be_given_before_the_first_run() {
		$this->assertGreaterThan( 0, CASCR_Store::set_consent() );
		$this->assertTrue( CASCR_Store::consent() );
	}

	/**
	 * The page is rendered from the stored run, so the findings have to survive
	 * the write. The history stays a single character per test.
	 */
	public function test_a_stored_run_keeps_the_findings() {
		$this->store( $this->results( array( 'unallowed_files' => CASCR_Result::fail( 'two files', 9, array( 'a.php', 'b.php' ) ) ) ) );

		$this->assertSame( array( 'a.php', 'b.php' ), CASCR_Store::last_run()['tests']['unallowed_files']['items'] );
		$this->assertSame( 'f', CASCR_History::latest()['tests']['unallowed_files'] );
	}

	/**
	 * A run in the shape 2.3.2 wrote it: status, score, summary, hash, ignored,
	 * and nothing else.
	 *
	 * @return array
	 */
	private function legacy_run() {
		$tests = array();

		foreach ( CASCR_Registry::ids() as $id ) {
			$tests[ $id ] = array(
				'status'  => CASCR_Result::STATUS_PASS,
				'score'   => 0,
				'summary' => 'ok',
				'hash'    => 'legacy',
				'ignored' => false,
			);
		}

		$tests['wp_debug']['status']  = CASCR_Result::STATUS_FAIL;
		$tests['wp_debug']['score']   = 9;
		$tests['wp_debug']['summary'] = 'debug is on';

		$tests['db_prefix']['status']  = CASCR_Result::STATUS_WARN;
		$tests['db_prefix']['score']   = 4;
		$tests['db_prefix']['summary'] = 'default prefix';

		return array(
			'generated' => time() - DAY_IN_SECONDS,
			'version'   => '2.3.2',
			'grade'     => 'C',
			'risk'      => 12.5,
			'counts'    => array(
				'pass'         => count( CASCR_Registry::ids() ) - 2,
				'warn'         => 1,
				'fail'         => 1,
				'inconclusive' => 0,
				'ignored'      => 0,
				'total'        => count( CASCR_Registry::ids() ),
			),
			'tests'     => $tests,
		);
	}

	/**
	 * Every installation updating from 2.3.2 reads such a run back on its first
	 * page view. Scoring wants the remediation step and the help link, the
	 * result list wants the findings, and none of them are in there.
	 */
	public function test_a_run_from_an_older_version_is_read_without_warnings() {
		update_option( CASCR_Store::OPTION_LAST, $this->legacy_run(), false );

		$noticed = array();

		set_error_handler(
			function ( $number, $message ) use ( &$noticed ) {
				$noticed[] = $message;

				return true;
			}
		);

		$tests      = CASCR_Store::last_run()['tests'];
		$priorities = CASCR_Scoring::priorities( $tests );
		$summary    = CASCR_Scoring::summarize( $tests );

		restore_error_handler();

		$this->assertSame( array(), $noticed, 'Reading a run from an older version must not raise a warning.' );

		$this->assertSame( array( 'wp_debug', 'db_prefix' ), wp_list_pluck( $priorities, 'id' ) );
		$this->assertSame( 'debug is on', $priorities[0]['summary'] );
		$this->assertSame( '', $priorities[0]['fix'] );
		$this->assertSame( array(), $priorities[0]['link'] );
		$this->assertSame( array(), $tests['wp_debug']['items'] );
		$this->assertNotEmpty( $summary['grade'] );
	}

	/**
	 * Filling in the missing keys must not rewrite a run this version wrote.
	 */
	public function test_a_current_run_is_read_back_unchanged() {
		$run = $this->store( $this->results() );

		$this->assertSame( $run, CASCR_Store::last_run() );
	}

	/**
	 * The bubble is drawn on every admin page, so its number lives apart from
	 * the run and has to follow both ways of writing one.
	 */
	public function test_the_menu_count_is_kept_apart_from_the_run() {
		$this->assertSame( 0, CASCR_Store::badge() );

		$this->store( $this->results( array( 'wp_debug' => CASCR_Result::fail( 'debug is on', 9 ) ) ) );

		$this->assertSame( 1, CASCR_Store::badge() );

		CASCR_Store::patch_test( 'wp_debug', CASCR_Result::pass( 'debug is off' ) );

		$this->assertSame( 0, CASCR_Store::badge() );
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

	/**
	 * Muting happens while reading a run, so the flag the run carries is out
	 * of date the moment it matters. Without re-reading it, a finding sent
	 * away stayed on the short list and the button looked broken.
	 */
	public function test_muting_after_a_run_takes_effect_without_a_new_run() {
		$finding = CASCR_Result::fail( 'one file', 9, array( 'a.php' ) );

		$this->store( $this->results( array( 'unallowed_files' => $finding ) ) );

		$before = CASCR_Store::last_run();
		$this->assertFalse( $before['tests']['unallowed_files']['ignored'] );

		CASCR_Store::ignore( 'unallowed_files', $finding, CASCR_Store::IGNORE_UNTIL_CHANGED );

		$after = CASCR_Store::last_run();

		$this->assertTrue(
			$after['tests']['unallowed_files']['ignored'],
			'A finding muted after the run must read as muted straight away.'
		);

		$ids = wp_list_pluck( CASCR_Scoring::priorities( $after['tests'] ), 'id' );

		$this->assertNotContains(
			'unallowed_files',
			$ids,
			'A muted finding must leave the short list.'
		);
	}

	public function test_unmuting_after_a_run_brings_the_finding_back() {
		$finding = CASCR_Result::fail( 'one file', 9, array( 'a.php' ) );

		$this->store( $this->results( array( 'unallowed_files' => $finding ) ) );

		CASCR_Store::ignore( 'unallowed_files', $finding );
		CASCR_Store::unignore( 'unallowed_files' );

		$run = CASCR_Store::last_run();

		$this->assertFalse( $run['tests']['unallowed_files']['ignored'] );
	}

	/**
	 * Muting writes no run, so nothing else recounts the bubble.
	 */
	public function test_muting_updates_the_menu_bubble() {
		$finding = CASCR_Result::fail( 'one file', 9, array( 'a.php' ) );

		$this->store( $this->results( array( 'unallowed_files' => $finding ) ) );

		$this->assertSame( 1, CASCR_Store::badge() );

		CASCR_Store::ignore( 'unallowed_files', $finding );

		$this->assertSame( 0, CASCR_Store::badge() );

		CASCR_Store::unignore( 'unallowed_files' );

		$this->assertSame( 1, CASCR_Store::badge() );
	}

	/**
	 * The comparison answers what changed between two measurements, so there
	 * the state at the time of measuring is the honest answer.
	 */
	public function test_the_previous_run_keeps_the_mute_state_it_was_stored_with() {
		$finding = CASCR_Result::fail( 'one file', 9, array( 'a.php' ) );

		$this->store( $this->results( array( 'unallowed_files' => $finding ) ) );
		$this->store( $this->results() );

		CASCR_Store::ignore( 'unallowed_files', $finding );

		$previous = CASCR_Store::previous_run();

		$this->assertFalse( $previous['tests']['unallowed_files']['ignored'] );
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
