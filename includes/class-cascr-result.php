<?php
/**
 * Result objects returned by every security check.
 *
 * @package CmsAdmins\SecurityCheck
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Builds the array shape that every check returns.
 *
 * A check never assembles the array by hand. That keeps the four possible
 * states consistent and makes the score/status invariant testable.
 */
class CASCR_Result {

	const STATUS_PASS         = 'pass';
	const STATUS_WARN         = 'warn';
	const STATUS_FAIL         = 'fail';
	const STATUS_INCONCLUSIVE = 'inconclusive';

	/**
	 * Lowest score that counts as a warning.
	 */
	const THRESHOLD_WARN = 4;

	/**
	 * Lowest score that counts as a failure.
	 */
	const THRESHOLD_FAIL = 7;

	/**
	 * The check found nothing to report.
	 *
	 * @param string   $summary One sentence, translated.
	 * @param string[] $items   Optional supporting detail, raw and unescaped.
	 * @return array
	 */
	public static function pass( $summary, $items = array() ) {
		return self::build( self::STATUS_PASS, $summary, 0, $items, '', array() );
	}

	/**
	 * The check found something worth improving.
	 *
	 * @param string   $summary One sentence, translated.
	 * @param int      $score   Risk contribution, 4 to 6.
	 * @param string[] $items   Affected objects, raw and unescaped.
	 * @param string   $fix     Optional concrete remediation step.
	 * @param array    $link    Optional {url, label} pointing at further help.
	 * @return array
	 */
	public static function warn( $summary, $score, $items = array(), $fix = '', $link = array() ) {
		return self::build( self::STATUS_WARN, $summary, $score, $items, $fix, $link );
	}

	/**
	 * The check found a problem that needs attention.
	 *
	 * @param string   $summary One sentence, translated.
	 * @param int      $score   Risk contribution, 7 to 10.
	 * @param string[] $items   Affected objects, raw and unescaped.
	 * @param string   $fix     Optional concrete remediation step.
	 * @param array    $link    Optional {url, label} pointing at further help.
	 * @return array
	 */
	public static function fail( $summary, $score, $items = array(), $fix = '', $link = array() ) {
		return self::build( self::STATUS_FAIL, $summary, $score, $items, $fix, $link );
	}

	/**
	 * The check could not determine an answer.
	 *
	 * Used whenever an outbound request fails, a file cannot be read or an API
	 * returns nothing usable. Inconclusive results are reported separately and
	 * are excluded from the grade, so a flaky network never lowers the score.
	 *
	 * @param string $summary One sentence, translated.
	 * @param string $fix     Optional hint on how to make the check work.
	 * @return array
	 */
	public static function inconclusive( $summary, $fix = '' ) {
		return self::build( self::STATUS_INCONCLUSIVE, $summary, 0, array(), $fix, array() );
	}

	/**
	 * Informational result that never contributes to the grade.
	 *
	 * The registry gives these checks a weight of 0; the status is only there
	 * so the interface can render them in the neutral style.
	 *
	 * @param string   $summary One sentence, translated.
	 * @param string[] $items   Supporting detail, raw and unescaped.
	 * @return array
	 */
	public static function info( $summary, $items = array() ) {
		return self::build( self::STATUS_PASS, $summary, 0, $items, '', array() );
	}

	/**
	 * Normalises an arbitrary result array, so filtered results stay valid.
	 *
	 * @param mixed $result Result candidate.
	 * @return array
	 */
	public static function normalize( $result ) {
		if ( ! is_array( $result ) || ! isset( $result['status'], $result['summary'] ) ) {
			return self::inconclusive( __( 'The check returned an unexpected result.', 'security-check-report' ) );
		}

		return self::build(
			$result['status'],
			$result['summary'],
			isset( $result['score'] ) ? $result['score'] : 0,
			isset( $result['items'] ) ? $result['items'] : array(),
			isset( $result['fix'] ) ? $result['fix'] : '',
			isset( $result['link'] ) ? $result['link'] : array()
		);
	}

	/**
	 * @param string $status  One of the STATUS_* constants.
	 * @param string $summary One sentence, translated.
	 * @param int    $score   Risk contribution, 0 to 10.
	 * @param mixed  $items   Affected objects.
	 * @param string $fix     Remediation step.
	 * @param array  $link    Optional {url, label}.
	 * @return array
	 */
	private static function build( $status, $summary, $score, $items, $fix, $link = array() ) {
		$allowed = array( self::STATUS_PASS, self::STATUS_WARN, self::STATUS_FAIL, self::STATUS_INCONCLUSIVE );
		if ( ! in_array( $status, $allowed, true ) ) {
			$status = self::STATUS_INCONCLUSIVE;
		}

		$score = (int) $score;
		if ( $score < 0 ) {
			$score = 0;
		} elseif ( $score > 10 ) {
			$score = 10;
		}

		if ( self::STATUS_PASS === $status || self::STATUS_INCONCLUSIVE === $status ) {
			$score = 0;
		}

		$items = is_array( $items ) ? array_values( array_map( 'strval', $items ) ) : array();

		return array(
			'status'  => $status,
			'score'   => $score,
			'summary' => (string) $summary,
			'items'   => $items,
			'fix'     => (string) $fix,
			'link'    => self::sanitize_link( $link ),
		);
	}

	/**
	 * Keeps only a well formed http(s) link with a label.
	 *
	 * A check hands this to the interface, which turns it into an anchor, so an
	 * unvalidated value would end up in the document as a link target.
	 *
	 * @param mixed $link Link candidate.
	 * @return array Empty array when there is nothing usable.
	 */
	private static function sanitize_link( $link ) {
		if ( ! is_array( $link ) || empty( $link['url'] ) || empty( $link['label'] ) ) {
			return array();
		}

		$url = esc_url_raw( $link['url'], array( 'http', 'https' ) );

		if ( '' === $url ) {
			return array();
		}

		return array(
			'url'   => $url,
			'label' => (string) $link['label'],
		);
	}

	/**
	 * Flattens a result into the single sentence used by the text export.
	 *
	 * @param array $result Result array.
	 * @param int   $limit  Maximum number of items to append.
	 * @return string
	 */
	public static function to_line( $result, $limit = 5 ) {
		$line = $result['summary'];

		if ( empty( $result['items'] ) ) {
			return $line;
		}

		$shown = array_slice( $result['items'], 0, $limit );
		$rest  = count( $result['items'] ) - count( $shown );

		$line .= ' ' . implode( ', ', $shown );

		if ( $rest > 0 ) {
			$line .= ' ' . sprintf(
				/* translators: %d: number of additional items not listed. */
				_n( 'and %d more', 'and %d more', $rest, 'security-check-report' ),
				$rest
			);
		}

		return $line;
	}
}
