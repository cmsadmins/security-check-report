<?php
/**
 * Turns a set of check results into a grade and a to-do list.
 *
 * @package CmsAdmins\SecurityCheck
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Weighted scoring, letter grade and deterministic prioritisation.
 *
 * This used to live in the browser, which made the outcome impossible to test
 * and impossible to reach from WP-CLI or a scheduled run.
 */
class CASCR_Scoring {

	/**
	 * Upper bound of the risk percentage for each grade.
	 *
	 * @var array<string, int>
	 */
	private static $grades = array(
		'A' => 10,
		'B' => 25,
		'C' => 40,
		'D' => 60,
		'F' => 100,
	);

	/**
	 * A failing critical check cannot result in better than this percentage.
	 */
	const CRITICAL_FLOOR = 41;

	/**
	 * Score at or above which a critical check triggers the floor.
	 */
	const CRITICAL_TRIGGER = 8;

	/**
	 * Number of entries on the priority list.
	 */
	const PRIORITY_LIMIT = 5;

	/**
	 * Builds the full report from raw results.
	 *
	 * @param array $results Results keyed by test identifier.
	 * @return array
	 */
	public static function summarize( $results ) {
		$counts = array(
			'pass'         => 0,
			'warn'         => 0,
			'fail'         => 0,
			'inconclusive' => 0,
			'ignored'      => 0,
			'total'        => 0,
		);

		$weighted_score = 0.0;
		$total_weight   = 0.0;
		$critical_fail  = false;
		$by_category    = array();

		foreach ( $results as $id => $result ) {
			++$counts['total'];

			if ( ! empty( $result['ignored'] ) ) {
				++$counts['ignored'];
				continue;
			}

			$status = $result['status'];
			if ( isset( $counts[ $status ] ) ) {
				++$counts[ $status ];
			}

			$test     = CASCR_Registry::get( $id );
			$severity = $test ? $test['severity'] : CASCR_Registry::SEVERITY_MEDIUM;
			$weight   = $test ? $test['weight'] : 1.5;

			if ( ! isset( $by_category[ $test ? $test['category'] : 'other' ] ) ) {
				$by_category[ $test ? $test['category'] : 'other' ] = array(
					'pass'         => 0,
					'warn'         => 0,
					'fail'         => 0,
					'inconclusive' => 0,
				);
			}
			++$by_category[ $test ? $test['category'] : 'other' ][ $status ];

			// An unreachable endpoint is not a finding. It must not move the grade.
			if ( CASCR_Result::STATUS_INCONCLUSIVE === $status || $weight <= 0 ) {
				continue;
			}

			$weighted_score += $result['score'] * $weight;
			$total_weight   += 10 * $weight;

			if ( CASCR_Registry::SEVERITY_CRITICAL === $severity && $result['score'] >= self::CRITICAL_TRIGGER ) {
				$critical_fail = true;
			}
		}

		$percentage = $total_weight > 0 ? ( $weighted_score / $total_weight ) * 100 : 0.0;

		if ( $critical_fail && $percentage < self::CRITICAL_FLOOR ) {
			$percentage = (float) self::CRITICAL_FLOOR;
		}

		$percentage = round( $percentage, 1 );

		return array(
			'generated'     => time(),
			'risk'          => $percentage,
			'grade'         => self::grade( $percentage ),
			'verdict'       => self::verdict( $counts ),
			'critical_fail' => $critical_fail,
			'counts'        => $counts,
			'categories'    => $by_category,
			'priorities'    => self::priorities( $results ),
		);
	}

	/**
	 * The result in one plain sentence.
	 *
	 * A letter grade tells you where you stand but not what to do with it.
	 * Built here rather than in the browser so the wording carries proper plural
	 * forms and reads the same over WP-CLI.
	 *
	 * @param array $counts Status counts from summarize().
	 * @return string
	 */
	public static function verdict( $counts ) {
		$parts = array();

		if ( $counts['fail'] > 0 ) {
			$parts[] = sprintf(
				/* translators: %d: number of failed checks. */
				_n(
					'%d finding needs your attention now.',
					'%d findings need your attention now.',
					$counts['fail'],
					'security-check-report'
				),
				$counts['fail']
			);
		}

		if ( $counts['warn'] > 0 ) {
			$parts[] = sprintf(
				/* translators: %d: number of warnings. */
				_n(
					'%d more is worth improving.',
					'%d more are worth improving.',
					$counts['warn'],
					'security-check-report'
				),
				$counts['warn']
			);
		}

		if ( empty( $parts ) ) {
			$parts[] = __( 'Nothing needs your attention right now.', 'security-check-report' );
		}

		if ( $counts['inconclusive'] > 0 ) {
			$parts[] = sprintf(
				/* translators: %d: number of checks that could not be completed. */
				_n(
					'%d check could not be completed and is not counted.',
					'%d checks could not be completed and are not counted.',
					$counts['inconclusive'],
					'security-check-report'
				),
				$counts['inconclusive']
			);
		}

		return implode( ' ', $parts );
	}

	/**
	 * Letter grade for a risk percentage.
	 *
	 * @param float $percentage Risk percentage, 0 to 100.
	 * @return string
	 */
	public static function grade( $percentage ) {
		foreach ( self::$grades as $letter => $max ) {
			if ( $percentage <= $max ) {
				return $letter;
			}
		}

		return 'F';
	}

	/**
	 * Translated label for a grade.
	 *
	 * @param string $grade Letter grade.
	 * @return string
	 */
	public static function grade_label( $grade ) {
		$labels = array(
			'A' => __( 'Excellent', 'security-check-report' ),
			'B' => __( 'Good', 'security-check-report' ),
			'C' => __( 'Moderate', 'security-check-report' ),
			'D' => __( 'Poor', 'security-check-report' ),
			'F' => __( 'Critical', 'security-check-report' ),
		);

		return isset( $labels[ $grade ] ) ? $labels[ $grade ] : $labels['F'];
	}

	/**
	 * The handful of things worth doing first.
	 *
	 * Ordering is fully deterministic: failures before warnings, then by
	 * urgency, then by score, then by identifier so equal entries never swap
	 * places between two runs of the same site.
	 *
	 * @param array $results Results keyed by test identifier.
	 * @return array
	 */
	public static function priorities( $results ) {
		$candidates = array();

		foreach ( $results as $id => $result ) {
			if ( ! empty( $result['ignored'] ) ) {
				continue;
			}

			if ( ! in_array( $result['status'], array( CASCR_Result::STATUS_FAIL, CASCR_Result::STATUS_WARN ), true ) ) {
				continue;
			}

			$test = CASCR_Registry::get( $id );
			if ( ! $test || $test['weight'] <= 0 ) {
				continue;
			}

			$candidates[] = array(
				'id'       => $id,
				'label'    => $test['label'],
				'severity' => $test['severity'],
				'status'   => $result['status'],
				'score'    => $result['score'],
				'summary'  => $result['summary'],
				'fix'      => $result['fix'],
				'link'     => isset( $result['link'] ) ? $result['link'] : array(),
				'rank'     => array(
					CASCR_Result::STATUS_FAIL === $result['status'] ? 1 : 0,
					CASCR_Registry::severity_rank( $test['severity'] ),
					$result['score'],
				),
			);
		}

		usort(
			$candidates,
			function ( $a, $b ) {
				for ( $i = 0; $i < 3; $i++ ) {
					if ( $a['rank'][ $i ] !== $b['rank'][ $i ] ) {
						return $b['rank'][ $i ] - $a['rank'][ $i ];
					}
				}

				return strcmp( $a['id'], $b['id'] );
			}
		);

		$candidates = array_slice( $candidates, 0, self::PRIORITY_LIMIT );

		foreach ( $candidates as &$candidate ) {
			unset( $candidate['rank'] );
		}
		unset( $candidate );

		return $candidates;
	}
}
