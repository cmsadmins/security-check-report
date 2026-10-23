<?php
/**
 * WP-CLI command.
 *
 * @package CmsAdmins\SecurityCheck
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Runs the security check from the command line.
 *
 * Only possible because the scoring lives in PHP. The numbers here are the same
 * ones the admin screen shows.
 */
class CASCR_CLI {

	/**
	 * Runs every security check and prints the result.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Output format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - summary
	 * ---
	 *
	 * [--failed-only]
	 * : Only list checks that failed or warned.
	 *
	 * [--fail-below=<grade>]
	 * : Exit with status 1 when the grade is worse than this one. For CI and
	 * monitoring.
	 * ---
	 * options:
	 *   - A
	 *   - B
	 *   - C
	 *   - D
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp security-check run
	 *     wp security-check run --format=json
	 *     wp security-check run --failed-only
	 *     wp security-check run --format=summary --fail-below=B
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Named arguments.
	 */
	public function run( $args, $assoc_args ) {
		$format      = isset( $assoc_args['format'] ) ? $assoc_args['format'] : 'table';
		$failed_only = isset( $assoc_args['failed-only'] );

		$scan = CASCR_Runner::scan();

		$this->report( $scan['results'], $scan['summary'], $format, $failed_only );

		if ( isset( $assoc_args['fail-below'] ) && self::is_worse( $scan['summary']['grade'], $assoc_args['fail-below'] ) ) {
			WP_CLI::halt( 1 );
		}
	}

	/**
	 * Is the grade worse than the threshold? A is best, F is worst.
	 *
	 * @param string $grade     Grade of the run.
	 * @param string $threshold Lowest acceptable grade.
	 * @return bool
	 */
	public static function is_worse( $grade, $threshold ) {
		return strpos( 'ABCDF', strtoupper( $grade ) ) > strpos( 'ABCDF', strtoupper( $threshold ) );
	}

	/**
	 * Prints a finished run.
	 *
	 * @param array  $results     Results keyed by identifier.
	 * @param array  $summary     Summary of the run.
	 * @param string $format      table, json or summary.
	 * @param bool   $failed_only Only list findings.
	 */
	private function report( $results, $summary, $format, $failed_only ) {

		if ( 'json' === $format ) {
			WP_CLI::line(
				wp_json_encode(
					array(
						'summary' => $summary,
						'results' => $results,
					)
				)
			);

			return;
		}

		WP_CLI::line(
			sprintf(
				'%s: %s (%s), %s %s%%',
				__( 'Grade', 'security-check-report' ),
				$summary['grade'],
				CASCR_Scoring::grade_label( $summary['grade'] ),
				__( 'risk score', 'security-check-report' ),
				$summary['risk']
			)
		);

		WP_CLI::line(
			sprintf(
				/* translators: 1: passed, 2: warnings, 3: failed, 4: not determined, 5: muted (all counts). */
				__( '%1$d passed, %2$d warnings, %3$d failed, %4$d not determined, %5$d muted', 'security-check-report' ),
				$summary['counts']['pass'],
				$summary['counts']['warn'],
				$summary['counts']['fail'],
				$summary['counts']['inconclusive'],
				$summary['counts']['ignored']
			)
		);

		if ( 'summary' === $format ) {
			return;
		}

		$rows = array();

		foreach ( $results as $id => $result ) {
			if ( $failed_only && ! in_array( $result['status'], array( 'fail', 'warn' ), true ) ) {
				continue;
			}

			$rows[] = array(
				'check'    => $id,
				'status'   => $result['status'],
				'score'    => $result['score'],
				'severity' => $result['severity'],
				'result'   => CASCR_Result::to_line( $result, 3 ),
			);
		}

		if ( empty( $rows ) ) {
			WP_CLI::success( __( 'Nothing needs your attention.', 'security-check-report' ) );

			return;
		}

		WP_CLI\Utils\format_items( 'table', $rows, array( 'check', 'status', 'score', 'severity', 'result' ) );
	}
}
