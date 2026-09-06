<?php
/**
 * Executes checks and assembles a complete run.
 *
 * @package CmsAdmins\SecurityCheck
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The one place a check callback is invoked.
 *
 * The browser calls this once per test so progress stays visible; WP-CLI calls
 * run_all() and gets the identical outcome.
 */
class CASCR_Runner {

	/**
	 * Runs a single check.
	 *
	 * @param string $id Test identifier.
	 * @return array|null Null when no such check exists.
	 */
	public static function run( $id ) {
		$test = CASCR_Registry::get( $id );

		if ( ! $test ) {
			return null;
		}

		try {
			$result = call_user_func( $test['callback'] );
		} catch ( Exception $e ) {
			$result = CASCR_Result::inconclusive(
				__( 'The check could not be completed on this server.', 'security-check-report' )
			);
		}

		$result = CASCR_Result::normalize( $result );

		/**
		 * Filters a single check result.
		 *
		 * @param array  $result Normalised result array.
		 * @param string $id     Test identifier.
		 * @param array  $test   Registry entry.
		 */
		$result = CASCR_Result::normalize( apply_filters( 'cascr_test_result', $result, $id, $test ) );

		$result['id']       = $id;
		$result['label']    = $test['label'];
		$result['category'] = $test['category'];
		$result['severity'] = $test['severity'];
		$result['ignored']  = CASCR_Store::is_ignored( $id, $result );

		return $result;
	}

	/**
	 * Runs every registered check in registry order.
	 *
	 * @return array Results keyed by test identifier.
	 */
	public static function run_all() {
		$results = array();

		foreach ( CASCR_Registry::ids() as $id ) {
			$result = self::run( $id );
			if ( null !== $result ) {
				$results[ $id ] = $result;
			}
		}

		return $results;
	}

	/**
	 * Scores a set of results and persists the run.
	 *
	 * @param array $results Results keyed by test identifier.
	 * @return array Summary plus diff against the previous run.
	 */
	public static function finish( $results ) {
		$summary = CASCR_Scoring::summarize( $results );
		$run     = CASCR_Store::save_run( $results, $summary );

		$summary['diff'] = CASCR_Store::diff( $run, CASCR_Store::previous_run() );

		return $summary;
	}

	/**
	 * Convenience wrapper: run everything and score it.
	 *
	 * @return array Keys: results, summary.
	 */
	public static function scan() {
		CASCR_Http::reset();

		$results = self::run_all();
		$summary = self::finish( $results );

		return array(
			'results' => $results,
			'summary' => $summary,
		);
	}
}
