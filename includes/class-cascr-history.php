<?php
/**
 * The long term record of completed runs.
 *
 * @package CmsAdmins\SecurityCheck
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Keeps one small point per completed run.
 *
 * Two stored runs are enough to say what changed since yesterday, but not
 * enough to show anyone how far they have come. A point is deliberately tiny:
 * time, grade, risk and a single character per test, which keeps two dozen of
 * them well under the size of one full run.
 */
class CASCR_History {

	const OPTION = 'cascr_history';

	/**
	 * How many points are kept. Older ones fall off the front.
	 */
	const LIMIT = 24;

	const MARK_PASS         = 'p';
	const MARK_WARN         = 'w';
	const MARK_FAIL         = 'f';
	const MARK_INCONCLUSIVE = 'u';
	const MARK_IGNORED      = 'i';

	/**
	 * Appends a completed run.
	 *
	 * Only a full run belongs here. A single re-check is not a run, so the
	 * curve never claims a grade that was measured in one pass when it was not.
	 *
	 * @param array $run A run in the shape CASCR_Store stores it.
	 * @return array The point that was appended.
	 */
	public static function append( $run ) {
		$point = self::point( $run );

		$history   = self::all();
		$history[] = $point;

		if ( count( $history ) > self::LIMIT ) {
			// The oldest point is what "started on" refers to, and a starting
			// point that moves is worse than none. The second oldest goes
			// instead, so the sentence stays true past the twenty-fourth run.
			$start   = array_shift( $history );
			$history = array_slice( $history, -( self::LIMIT - 1 ) );

			array_unshift( $history, $start );
		}

		update_option( self::OPTION, $history, false );

		return $point;
	}

	/**
	 * Every stored point, oldest first.
	 *
	 * @return array
	 */
	public static function all() {
		$history = get_option( self::OPTION, array() );

		return is_array( $history ) ? array_values( $history ) : array();
	}

	/**
	 * The oldest point still on record, or an empty array.
	 *
	 * @return array
	 */
	public static function first() {
		$history = self::all();

		return empty( $history ) ? array() : $history[0];
	}

	/**
	 * The most recent point, or an empty array.
	 *
	 * @return array
	 */
	public static function latest() {
		$history = self::all();

		return empty( $history ) ? array() : $history[ count( $history ) - 1 ];
	}

	/**
	 * Checks that were a finding once and are passing now.
	 *
	 * A test that broke again in between and has since been fixed appears once,
	 * dated at the most recent move to pass, because that is the date the site
	 * owner would recognise.
	 *
	 * @return array<string, int> Test identifier mapped to the time it turned.
	 */
	public static function resolved() {
		return self::turned(
			array( self::MARK_FAIL, self::MARK_WARN ),
			array( self::MARK_PASS )
		);
	}

	/**
	 * Seeds the history from the two runs older installations already have.
	 *
	 * Without this, everyone who has been using the plugin for months would
	 * start at zero and see no progress at all. Refuses to run a second time,
	 * because by then the history speaks for itself.
	 *
	 * @return bool True when something was written.
	 */
	public static function migrate() {
		if ( ! empty( self::all() ) ) {
			return false;
		}

		$seeded = false;

		foreach ( array( CASCR_Store::previous_run(), CASCR_Store::last_run() ) as $run ) {
			if ( empty( $run['tests'] ) ) {
				continue;
			}

			self::append( $run );
			$seeded = true;
		}

		return $seeded;
	}

	/**
	 * Identifiers that moved from one set of states into another and stayed there.
	 *
	 * Inconclusive and muted results never overwrite the remembered state. A
	 * check that could not be reached for one run has not changed its mind, and
	 * treating it as a change would invent both fixes and regressions.
	 *
	 * @param string[] $from States the test has to come from.
	 * @param string[] $to   States it has to arrive in and still be in.
	 * @return array<string, int>
	 */
	private static function turned( $from, $to ) {
		$history = self::all();

		if ( count( $history ) < 2 ) {
			return array();
		}

		$decisive = array( self::MARK_PASS, self::MARK_WARN, self::MARK_FAIL );
		$previous = array();
		$when     = array();

		foreach ( $history as $point ) {
			if ( empty( $point['tests'] ) || ! is_array( $point['tests'] ) ) {
				continue;
			}

			foreach ( $point['tests'] as $id => $mark ) {
				if ( isset( $previous[ $id ] )
					&& in_array( $previous[ $id ], $from, true )
					&& in_array( $mark, $to, true ) ) {
					$when[ $id ] = isset( $point['t'] ) ? (int) $point['t'] : 0;
				}

				if ( in_array( $mark, $decisive, true ) ) {
					$previous[ $id ] = $mark;
				}
			}
		}

		$turned = array();

		foreach ( $when as $id => $time ) {
			// The last decisive state, not the raw mark of the last run. A
			// check that could not be reached or was muted in the final run
			// has not taken its fix back, and reading the raw mark here would
			// drop it from the archive until it answers again.
			if ( isset( $previous[ $id ] ) && in_array( $previous[ $id ], $to, true ) ) {
				$turned[ $id ] = $time;
			}
		}

		return $turned;
	}

	/**
	 * Reduces a full run to the handful of values worth keeping forever.
	 *
	 * @param array $run A run in the shape CASCR_Store stores it.
	 * @return array
	 */
	private static function point( $run ) {
		$tests = array();

		if ( ! empty( $run['tests'] ) && is_array( $run['tests'] ) ) {
			foreach ( $run['tests'] as $id => $test ) {
				$tests[ $id ] = self::mark( $test );
			}
		}

		return array(
			't'     => isset( $run['generated'] ) ? (int) $run['generated'] : time(),
			'g'     => isset( $run['grade'] ) ? (string) $run['grade'] : '',
			'r'     => isset( $run['risk'] ) ? (float) $run['risk'] : 0.0,
			'tests' => $tests,
		);
	}

	/**
	 * The single character a stored test is remembered by.
	 *
	 * @param array $test One entry of a stored run.
	 * @return string
	 */
	private static function mark( $test ) {
		if ( ! empty( $test['ignored'] ) ) {
			return self::MARK_IGNORED;
		}

		$marks = array(
			CASCR_Result::STATUS_PASS         => self::MARK_PASS,
			CASCR_Result::STATUS_WARN         => self::MARK_WARN,
			CASCR_Result::STATUS_FAIL         => self::MARK_FAIL,
			CASCR_Result::STATUS_INCONCLUSIVE => self::MARK_INCONCLUSIVE,
		);

		$status = isset( $test['status'] ) ? $test['status'] : '';

		return isset( $marks[ $status ] ) ? $marks[ $status ] : self::MARK_INCONCLUSIVE;
	}
}
