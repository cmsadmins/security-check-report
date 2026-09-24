<?php
/**
 * What the dashboard makes of a run that has been re-checked since.
 *
 * @package CmsAdmins\SecurityCheck
 */

class Test_CASCR_Admin_Dashboard extends WP_UnitTestCase {

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
	private function store( $overrides = array() ) {
		$results = array();

		foreach ( CASCR_Registry::ids() as $id ) {
			$results[ $id ] = isset( $overrides[ $id ] ) ? $overrides[ $id ] : CASCR_Result::pass( 'ok' );
		}

		return CASCR_Store::save_run( $results, CASCR_Scoring::summarize( $results ) );
	}

	/**
	 * @return string
	 */
	private function render() {
		ob_start();
		CASCR_Admin_Dashboard::render( CASCR_Store::last_run() );

		return ob_get_clean();
	}

	/**
	 * @param string $id Test identifier.
	 * @return string
	 */
	private function label( $id ) {
		$test = CASCR_Registry::get( $id );

		return $test['label'];
	}

	/**
	 * Before this the answer went to wp.a11y.speak() and nowhere else, so
	 * anyone who could see the page learned nothing at all from a re-check that
	 * came back still failing.
	 */
	public function test_a_failed_recheck_is_written_on_the_page() {
		$this->store( array( 'wp_debug' => CASCR_Result::fail( 'debug is on', 9 ) ) );

		CASCR_Store::patch_test( 'wp_debug', CASCR_Result::fail( 'debug is still on', 9 ) );

		$markup = $this->render();

		$this->assertStringContainsString( 'debug is still on', $markup );
		$this->assertStringContainsString(
			sprintf( '%s is still open after the re-check.', $this->label( 'wp_debug' ) ),
			$markup
		);
	}

	/**
	 * And the other way round the success has to survive the reload that
	 * follows it, which the browser side confirmation never did.
	 */
	public function test_a_passed_recheck_is_written_on_the_page() {
		$this->store( array( 'wp_debug' => CASCR_Result::fail( 'debug is on', 9 ) ) );

		CASCR_Store::patch_test( 'wp_debug', CASCR_Result::pass( 'debug is off' ) );

		$markup = $this->render();

		$this->assertStringContainsString(
			sprintf( '%s passed the re-check.', $this->label( 'wp_debug' ) ),
			$markup
		);
		$this->assertStringContainsString( 'debug is off', $markup );
	}

	/**
	 * A partial pass writes no point on the curve, so the archive would never
	 * hear about it. It reads the run as well, and says which of the two a
	 * given entry came from.
	 */
	public function test_the_archive_lists_a_task_solved_by_a_recheck() {
		$this->store( array( 'wp_debug' => CASCR_Result::fail( 'debug is on', 9 ) ) );

		$this->assertStringNotContainsString( 'cascr-archive', $this->render() );

		CASCR_Store::patch_test( 'wp_debug', CASCR_Result::pass( 'debug is off' ) );

		$markup = $this->render();

		$this->assertStringContainsString( 'Resolved (1)', $markup );
		$this->assertStringContainsString( 'after a re-check', $markup );
		$this->assertCount( 1, CASCR_History::all(), 'A re-check is not a run and must not become a point.' );
	}

	/**
	 * The archive must not keep claiming a pass the last re-check contradicts.
	 */
	public function test_a_recheck_that_fails_again_leaves_the_archive() {
		$this->store( array( 'wp_debug' => CASCR_Result::fail( 'debug is on', 9 ) ) );
		$this->store( array( 'wp_debug' => CASCR_Result::pass( 'debug is off' ) ) );

		$this->assertStringContainsString( 'Resolved (1)', $this->render() );

		CASCR_Store::patch_test( 'wp_debug', CASCR_Result::fail( 'debug is on again', 9 ) );

		$this->assertStringNotContainsString( 'Resolved (', $this->render() );
	}

	/**
	 * The note about the grade no longer coming from one pass stays.
	 */
	public function test_the_partial_note_is_still_shown() {
		$this->store( array( 'wp_debug' => CASCR_Result::fail( 'debug is on', 9 ) ) );

		$this->assertStringNotContainsString( 'cascr-dash__partial', $this->render() );

		CASCR_Store::patch_test( 'wp_debug', CASCR_Result::pass( 'debug is off' ) );

		$this->assertStringContainsString( 'cascr-dash__partial', $this->render() );
	}
}
