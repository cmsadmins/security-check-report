<?php
/**
 * Milestones and the monthly streak.
 *
 * @package CmsAdmins\SecurityCheck
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Remembers what a site has achieved, once and with a date.
 *
 * The history keeps two dozen points and drops the middle ones, which is too
 * short to count findings resolved over a year or months checked in a row.
 * This option keeps just that: the date each milestone was first reached, a
 * running count of resolved findings and the months that saw a full run.
 *
 * Muting never counts. A muted finding keeps its status, so it never shows up
 * as resolved, and a check that becomes inconclusive is not a fix either.
 */
class CASCR_Milestones {

	const OPTION = 'cascr_milestones';

	/**
	 * How many months are kept. Three years is more than any streak needs.
	 */
	const MONTH_LIMIT = 36;

	/**
	 * Hangs the recorder on the end of every full run.
	 */
	public static function register() {
		add_action( 'cascr_run_completed', array( __CLASS__, 'record' ), 10, 2 );
	}

	/**
	 * Every milestone in display order, with its label.
	 *
	 * @return array<string, string>
	 */
	public static function labels() {
		return array(
			'no_critical' => __( 'No open critical finding', 'security-check-report' ),
			'no_failed'   => __( 'No failed check', 'security-check-report' ),
			'first_a'     => __( 'Grade A for the first time', 'security-check-report' ),
			'resolved_10' => __( '10 findings resolved', 'security-check-report' ),
			'resolved_25' => __( '25 findings resolved', 'security-check-report' ),
			'resolved_50' => __( '50 findings resolved', 'security-check-report' ),
			'streak_3'    => __( 'Checked every month for 3 months', 'security-check-report' ),
			'streak_6'    => __( 'Checked every month for 6 months', 'security-check-report' ),
			'streak_12'   => __( 'Checked every month for 12 months', 'security-check-report' ),
		);
	}

	/**
	 * The stored state, always in full shape.
	 *
	 * @return array Keys reached, resolved, months.
	 */
	public static function get() {
		$state = get_option( self::OPTION, array() );
		$state = is_array( $state ) ? $state : array();

		return array(
			'reached'  => isset( $state['reached'] ) && is_array( $state['reached'] ) ? $state['reached'] : array(),
			'resolved' => isset( $state['resolved'] ) ? (int) $state['resolved'] : 0,
			'months'   => isset( $state['months'] ) && is_array( $state['months'] ) ? $state['months'] : array(),
			'seeded'   => isset( $state['seeded'] ) ? (int) $state['seeded'] : 0,
		);
	}

	/**
	 * Updates counters and milestones after a full run.
	 *
	 * @param array $run     The stored run.
	 * @param array $summary The summary, including the diff against the run before.
	 */
	public static function record( $run, $summary = array() ) {
		$seeded = false === get_option( self::OPTION );
		$state  = $seeded ? self::seed() : self::get();
		$time   = isset( $run['generated'] ) ? (int) $run['generated'] : time();
		$tests  = isset( $run['tests'] ) && is_array( $run['tests'] ) ? $run['tests'] : array();

		if ( $seeded ) {
			$state['seeded'] = $time;
		}

		// The seed already counts this run, the history holds it by now.
		if ( ! $seeded && ! empty( $summary['diff']['fixed'] ) ) {
			foreach ( $summary['diff']['fixed'] as $id ) {
				if ( isset( $tests[ $id ]['status'] ) && CASCR_Result::STATUS_PASS === $tests[ $id ]['status'] ) {
					++$state['resolved'];
				}
			}
		}

		$month = wp_date( 'Y-m', $time );
		if ( ! in_array( $month, $state['months'], true ) ) {
			$state['months'][] = $month;
			sort( $state['months'] );
			$state['months'] = array_slice( $state['months'], -self::MONTH_LIMIT );
		}

		$streak = self::streak( $state['months'], $month );
		$met    = array(
			'no_critical' => ! empty( $tests ) && null === CASCR_Scoring::open_critical( $tests, true ),
			'no_failed'   => ! empty( $tests ) && ! in_array( CASCR_Result::STATUS_FAIL, wp_list_pluck( $tests, 'status' ), true ),
			'first_a'     => isset( $run['grade'] ) && 'A' === $run['grade'],
			'resolved_10' => $state['resolved'] >= 10,
			'resolved_25' => $state['resolved'] >= 25,
			'resolved_50' => $state['resolved'] >= 50,
			'streak_3'    => $streak >= 3,
			'streak_6'    => $streak >= 6,
			'streak_12'   => $streak >= 12,
		);

		foreach ( $met as $key => $reached ) {
			if ( $reached && ! isset( $state['reached'][ $key ] ) ) {
				$state['reached'][ $key ] = $time;
			}
		}

		update_option( self::OPTION, $state, false );
	}

	/**
	 * The starting state for a site that was checked before milestones existed.
	 *
	 * Starting everyone at zero would tell a site with a year of work behind
	 * it that it has achieved nothing. The history knows the dates of the
	 * first grade A and of the first run without a failure, the months that
	 * saw a run, and which findings have been resolved. A muted check is
	 * stored as muted without its status, so it counts as still open here.
	 *
	 * @return array Same shape as get().
	 */
	private static function seed() {
		$state = array(
			'reached'  => array(),
			'resolved' => count( CASCR_History::resolved() ),
			'months'   => array(),
			'seeded'   => 0,
		);

		$open = array( CASCR_History::MARK_FAIL, CASCR_History::MARK_WARN, CASCR_History::MARK_IGNORED );

		foreach ( CASCR_History::all() as $point ) {
			$time  = (int) $point['t'];
			$marks = isset( $point['tests'] ) && is_array( $point['tests'] ) ? $point['tests'] : array();

			$state['months'][] = wp_date( 'Y-m', $time );

			$critical_open = false;
			foreach ( $marks as $id => $mark ) {
				$meta = CASCR_Registry::get( $id );
				if ( $meta && CASCR_Registry::SEVERITY_CRITICAL === $meta['severity'] && in_array( $mark, $open, true ) ) {
					$critical_open = true;
					break;
				}
			}

			$met = array(
				'first_a'     => 'A' === $point['g'],
				'no_failed'   => ! empty( $marks ) && ! array_intersect( array( CASCR_History::MARK_FAIL, CASCR_History::MARK_IGNORED ), $marks ),
				'no_critical' => ! empty( $marks ) && ! $critical_open,
			);

			foreach ( $met as $key => $reached ) {
				if ( $reached && ! isset( $state['reached'][ $key ] ) ) {
					$state['reached'][ $key ] = $time;
				}
			}
		}

		$state['months'] = array_slice( array_values( array_unique( $state['months'] ) ), -self::MONTH_LIMIT );
		sort( $state['months'] );

		return $state;
	}

	/**
	 * Months in a row with at least one full run, counted back from now.
	 *
	 * The current month may still be open: a streak that ended last month is
	 * not broken until this one is over, otherwise it would read zero on the
	 * first of every month.
	 *
	 * @param string[]|null $months Months as Y-m, the stored ones when omitted.
	 * @param string|null   $now    Current month as Y-m, today when omitted.
	 * @return int
	 */
	public static function streak( $months = null, $now = null ) {
		$months = null === $months ? self::get()['months'] : $months;
		$now    = null === $now ? wp_date( 'Y-m' ) : $now;

		$cursor = new DateTimeImmutable( $now . '-01' );
		if ( ! in_array( $now, $months, true ) ) {
			$cursor = $cursor->modify( '-1 month' );
		}

		$count = 0;
		while ( in_array( $cursor->format( 'Y-m' ), $months, true ) ) {
			++$count;
			$cursor = $cursor->modify( '-1 month' );
		}

		return $count;
	}

	/**
	 * Milestones first reached by the given run.
	 *
	 * Empty for the run that took over an existing history: what it finds
	 * there was reached over months, not by this one run.
	 *
	 * @param array $run The stored run.
	 * @return string[] Milestone keys.
	 */
	public static function new_in( $run ) {
		$state = self::get();

		if ( empty( $run['generated'] ) || (int) $run['generated'] === $state['seeded'] ) {
			return array();
		}

		return array_keys( $state['reached'], (int) $run['generated'], true );
	}
}
