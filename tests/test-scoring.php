<?php
/**
 * Grading used to live in the browser and could not be tested at all.
 *
 * @package CmsAdmins\SecurityCheck
 */

class Test_CASCR_Scoring extends WP_UnitTestCase {

	public function tear_down() {
		CASCR_Registry::reset();
		parent::tear_down();
	}

	/**
	 * Builds a result set covering every registered check.
	 *
	 * @param array $overrides Results keyed by identifier.
	 * @return array
	 */
	private function results( $overrides = array() ) {
		$results = array();

		foreach ( CASCR_Registry::all() as $id => $test ) {
			$results[ $id ] = isset( $overrides[ $id ] )
				? $overrides[ $id ]
				: CASCR_Result::pass( 'ok' );
		}

		return $results;
	}

	public function test_a_clean_site_gets_an_a() {
		$summary = CASCR_Scoring::summarize( $this->results() );

		$this->assertSame( 0.0, $summary['risk'] );
		$this->assertSame( 'A', $summary['grade'] );
		$this->assertSame( 0, $summary['counts']['fail'] );
	}

	public function test_grade_boundaries() {
		$this->assertSame( 'A', CASCR_Scoring::grade( 0 ) );
		$this->assertSame( 'A', CASCR_Scoring::grade( 10 ) );
		$this->assertSame( 'B', CASCR_Scoring::grade( 10.1 ) );
		$this->assertSame( 'B', CASCR_Scoring::grade( 25 ) );
		$this->assertSame( 'C', CASCR_Scoring::grade( 25.1 ) );
		$this->assertSame( 'D', CASCR_Scoring::grade( 60 ) );
		$this->assertSame( 'F', CASCR_Scoring::grade( 60.1 ) );
		$this->assertSame( 'F', CASCR_Scoring::grade( 100 ) );
	}

	/**
	 * An unreachable endpoint says nothing about the site. It must not count.
	 */
	public function test_inconclusive_results_do_not_move_the_grade() {
		$clean = CASCR_Scoring::summarize( $this->results() );

		$with_unknown = CASCR_Scoring::summarize(
			$this->results(
				array(
					'security_headers' => CASCR_Result::inconclusive( 'no answer' ),
					'ssl'              => CASCR_Result::inconclusive( 'no answer' ),
				)
			)
		);

		$this->assertSame( $clean['risk'], $with_unknown['risk'] );
		$this->assertSame( 2, $with_unknown['counts']['inconclusive'] );
	}

	public function test_ignored_results_are_counted_separately_and_excluded() {
		$summary = CASCR_Scoring::summarize(
			$this->results(
				array(
					'wp_debug' => array_merge(
						CASCR_Result::fail( 'bad', 9 ),
						array( 'ignored' => true )
					),
				)
			)
		);

		$this->assertSame( 1, $summary['counts']['ignored'] );
		$this->assertSame( 0, $summary['counts']['fail'] );
		$this->assertSame( 0.0, $summary['risk'] );
	}

	/**
	 * One failing critical check cannot leave the site sitting on an A.
	 */
	public function test_a_failing_critical_check_forces_the_floor() {
		$summary = CASCR_Scoring::summarize(
			$this->results(
				array(
					'weak_password_users' => CASCR_Result::fail( 'guessable', 9 ),
				)
			)
		);

		$this->assertTrue( $summary['critical_fail'] );
		$this->assertGreaterThanOrEqual( CASCR_Scoring::CRITICAL_FLOOR, $summary['risk'] );
		$this->assertSame( 'D', $summary['grade'] );
	}

	public function test_a_low_severity_failure_weighs_less_than_a_critical_one() {
		$low = CASCR_Scoring::summarize(
			$this->results( array( 'db_prefix' => CASCR_Result::warn( 'default prefix', 6 ) ) )
		);

		$high = CASCR_Scoring::summarize(
			$this->results( array( 'database_user_privileges' => CASCR_Result::warn( 'too many rights', 6 ) ) )
		);

		$this->assertLessThan( $high['risk'], $low['risk'] );
	}

	public function test_informational_checks_never_move_the_grade() {
		$clean = CASCR_Scoring::summarize( $this->results() );

		$noisy = CASCR_Scoring::summarize(
			$this->results( array( 'security_plugins' => CASCR_Result::fail( 'nothing installed', 10 ) ) )
		);

		$this->assertSame( $clean['risk'], $noisy['risk'] );
	}

	public function test_priorities_are_capped_and_ordered_by_urgency() {
		$results = $this->results(
			array(
				'db_prefix'                => CASCR_Result::warn( 'low', 5 ),
				'wp_debug'                 => CASCR_Result::warn( 'medium', 5 ),
				'file_edit'                => CASCR_Result::fail( 'high', 8 ),
				'weak_password_users'      => CASCR_Result::fail( 'critical', 9 ),
				'database_user_privileges' => CASCR_Result::fail( 'critical', 9 ),
				'unallowed_files'          => CASCR_Result::fail( 'critical', 9 ),
				'php_execution'            => CASCR_Result::fail( 'critical', 9 ),
			)
		);

		$priorities = CASCR_Scoring::priorities( $results );

		$this->assertCount( CASCR_Scoring::PRIORITY_LIMIT, $priorities );
		$this->assertSame( 'fail', $priorities[0]['status'] );
		$this->assertSame( CASCR_Registry::SEVERITY_CRITICAL, $priorities[0]['severity'] );

		// Severity never rises down the list, and within one severity no
		// warning comes before a failure.
		for ( $i = 1; $i < count( $priorities ); $i++ ) {
			$prev = CASCR_Registry::severity_rank( $priorities[ $i - 1 ]['severity'] );
			$curr = CASCR_Registry::severity_rank( $priorities[ $i ]['severity'] );

			$this->assertGreaterThanOrEqual( $curr, $prev, 'A more severe finding was listed further down.' );

			if ( $prev === $curr ) {
				$this->assertFalse(
					'warn' === $priorities[ $i - 1 ]['status'] && 'fail' === $priorities[ $i ]['status'],
					'A failure was listed after a warning of the same severity.'
				);
			}
		}
	}

	/**
	 * Seen on a live site: PHP2Shell (critical, warning) sat behind missing
	 * security headers (medium, failure).
	 */
	public function test_a_critical_warning_outranks_a_medium_failure() {
		$priorities = CASCR_Scoring::priorities(
			$this->results(
				array(
					'security_headers' => CASCR_Result::fail( 'missing', 6 ),
					'php2shell'        => CASCR_Result::warn( 'unpatched', 6 ),
				)
			)
		);

		$this->assertSame( array( 'php2shell', 'security_headers' ), wp_list_pluck( $priorities, 'id' ) );
	}

	public function test_muted_checks_still_count_towards_their_category() {
		$summary = CASCR_Scoring::summarize(
			$this->results(
				array(
					'wp_debug' => array_merge( CASCR_Result::fail( 'bad', 9 ), array( 'ignored' => true ) ),
				)
			)
		);

		$category = CASCR_Registry::get( 'wp_debug' )['category'];
		$expected = count( wp_list_filter( CASCR_Registry::all(), array( 'category' => $category ) ) );

		$this->assertSame( $expected, array_sum( $summary['categories'][ $category ] ) );
		$this->assertSame( 1, $summary['categories'][ $category ]['ignored'] );
	}

	public function test_priorities_are_stable_across_runs() {
		$results = $this->results(
			array(
				'file_edit'  => CASCR_Result::fail( 'a', 8 ),
				'ssl'        => CASCR_Result::fail( 'b', 8 ),
				'brute_force' => CASCR_Result::fail( 'c', 8 ),
			)
		);

		$first  = wp_list_pluck( CASCR_Scoring::priorities( $results ), 'id' );
		$second = wp_list_pluck( CASCR_Scoring::priorities( array_reverse( $results, true ) ), 'id' );

		$this->assertSame( $first, $second, 'Equally ranked findings must not swap places between runs.' );
	}

	public function test_passing_checks_never_reach_the_priority_list() {
		$priorities = CASCR_Scoring::priorities( $this->results() );

		$this->assertSame( array(), $priorities );
	}

	/**
	 * The grade says where you stand, the verdict says what to do with it.
	 * Built in PHP so the plural forms are correct in every language.
	 */
	public function test_the_verdict_reads_as_a_sentence() {
		$clean = CASCR_Scoring::summarize( $this->results() );
		$this->assertSame( 'Nothing needs your attention right now.', $clean['verdict'] );

		$one = CASCR_Scoring::summarize(
			$this->results( array( 'wp_debug' => CASCR_Result::fail( 'bad', 9 ) ) )
		);
		$this->assertStringContainsString( '1 finding needs', $one['verdict'] );

		$mixed = CASCR_Scoring::summarize(
			$this->results(
				array(
					'wp_debug'  => CASCR_Result::fail( 'bad', 9 ),
					'file_edit' => CASCR_Result::fail( 'bad', 9 ),
					'db_prefix' => CASCR_Result::warn( 'meh', 5 ),
				)
			)
		);
		$this->assertStringContainsString( '2 findings need', $mixed['verdict'] );
		$this->assertStringContainsString( '1 more is worth', $mixed['verdict'] );
	}

	public function test_the_verdict_mentions_checks_that_could_not_run() {
		$summary = CASCR_Scoring::summarize(
			$this->results( array( 'ssl' => CASCR_Result::inconclusive( 'no answer' ) ) )
		);

		$this->assertStringContainsString( 'could not be completed', $summary['verdict'] );
	}

	/**
	 * The to-do list is the part people read, so a helper link on a finding has
	 * to survive into it.
	 */
	public function test_priorities_carry_the_link_of_a_finding() {
		$results = $this->results(
			array(
				'two_factor_coverage' => CASCR_Result::fail(
					'no second factor',
					9,
					array(),
					'install one',
					array(
						'url'   => 'https://example.com/2fa',
						'label' => 'A second factor',
					)
				),
			)
		);

		$priorities = CASCR_Scoring::priorities( $results );

		$this->assertSame( 'two_factor_coverage', $priorities[0]['id'] );
		$this->assertSame( 'https://example.com/2fa', $priorities[0]['link']['url'] );
	}

	public function test_grade_labels_exist_for_every_grade() {
		foreach ( array( 'A', 'B', 'C', 'D', 'F' ) as $grade ) {
			$this->assertNotEmpty( CASCR_Scoring::grade_label( $grade ) );
		}
	}
}
