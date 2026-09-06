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
	 * ## EXAMPLES
	 *
	 *     wp security-check run
	 *     wp security-check run --format=json
	 *     wp security-check run --failed-only
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Named arguments.
	 */
	public function run( $args, $assoc_args ) {
		$format      = isset( $assoc_args['format'] ) ? $assoc_args['format'] : 'table';
		$failed_only = isset( $assoc_args['failed-only'] );

		$scan    = CASCR_Runner::scan();
		$results = $scan['results'];
		$summary = $scan['summary'];

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
				'%d passed, %d warnings, %d failed, %d not determined, %d muted',
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
