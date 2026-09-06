<?php
/**
 * The registry is the single source of truth. These tests are what keeps it
 * from drifting apart again.
 *
 * @package CmsAdmins\SecurityCheck
 */

class Test_CASCR_Registry extends WP_UnitTestCase {

	public function tear_down() {
		CASCR_Registry::reset();
		parent::tear_down();
	}

	public function test_every_entry_is_complete() {
		foreach ( CASCR_Registry::all() as $id => $test ) {
			$this->assertMatchesRegularExpression( '/^[a-z0-9_]+$/', $id, "Identifier '{$id}' is not URL safe." );
			$this->assertNotEmpty( $test['label'], "Test '{$id}' has no label." );
			$this->assertNotSame( $id, $test['label'], "Test '{$id}' falls back to its identifier as a label." );
			$this->assertArrayHasKey( $test['category'], CASCR_Registry::categories(), "Test '{$id}' uses an unknown category." );
			$this->assertContains(
				$test['severity'],
				array(
					CASCR_Registry::SEVERITY_CRITICAL,
					CASCR_Registry::SEVERITY_HIGH,
					CASCR_Registry::SEVERITY_MEDIUM,
					CASCR_Registry::SEVERITY_LOW,
				),
				"Test '{$id}' uses an unknown severity."
			);
			$this->assertIsFloat( $test['weight'], "Test '{$id}' has a non-numeric weight." );
			$this->assertTrue( is_callable( $test['callback'] ), "Test '{$id}' has an uncallable callback." );
		}
	}

	/**
	 * The previous version kept documentation in a separate file keyed by the
	 * translated title, and the only test compared the number of entries. Seven
	 * titles had already drifted apart without anything noticing.
	 */
	public function test_documentation_matches_the_registry_exactly() {
		$tests = array_keys( CASCR_Registry::all() );
		$docs  = array_keys( CASCR_Registry::docs() );

		sort( $tests );
		sort( $docs );

		$this->assertSame(
			$tests,
			$docs,
			'Documentation keys and registry identifiers must match one to one.'
		);
	}

	public function test_every_documentation_entry_has_content() {
		foreach ( CASCR_Registry::ids() as $id ) {
			$doc = CASCR_Registry::doc( $id );

			$this->assertNotEmpty( $doc, "Test '{$id}' has no documentation." );
			$this->assertGreaterThan( 200, strlen( wp_strip_all_tags( $doc ) ), "Documentation for '{$id}' is too thin to be useful." );
		}
	}

	public function test_client_payload_carries_no_callbacks() {
		foreach ( CASCR_Registry::for_client() as $id => $test ) {
			$this->assertArrayNotHasKey( 'callback', $test, "Test '{$id}' leaks its callback to the browser." );
			$this->assertArrayHasKey( 'label', $test );
			$this->assertArrayHasKey( 'severity', $test );
		}
	}

	public function test_registry_can_be_filtered() {
		add_filter(
			'cascr_registry',
			function ( $tests ) {
				unset( $tests['wp_debug'] );

				return $tests;
			}
		);

		CASCR_Registry::reset();

		$this->assertFalse( CASCR_Registry::exists( 'wp_debug' ) );
	}

	public function test_malformed_entries_are_dropped() {
		add_filter(
			'cascr_registry',
			function ( $tests ) {
				$tests['broken'] = array( 'label' => 'Broken' );

				return $tests;
			}
		);

		CASCR_Registry::reset();

		$this->assertFalse( CASCR_Registry::exists( 'broken' ) );
	}

	public function test_no_test_has_a_negative_weight() {
		foreach ( CASCR_Registry::all() as $id => $test ) {
			$this->assertGreaterThanOrEqual( 0, $test['weight'], "Test '{$id}' has a negative weight." );
		}
	}
}
