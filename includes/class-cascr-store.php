<?php
/**
 * Persistence for scan runs, muted findings and drift baselines.
 *
 * @package CmsAdmins\SecurityCheck
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Everything the plugin remembers between two page loads.
 *
 * Without this a report is read once and thrown away. With it the second run
 * can say what changed, and a finding the site owner has consciously accepted
 * stays quiet until its content actually differs.
 */
class CASCR_Store {

	const OPTION_LAST     = 'cascr_last_scan';
	const OPTION_PREVIOUS = 'cascr_previous_scan';
	const OPTION_IGNORED  = 'cascr_ignored';
	const OPTION_BASELINE = 'cascr_baseline';

	const IGNORE_PERMANENT     = 'permanent';
	const IGNORE_UNTIL_CHANGED = 'until_changed';

	/**
	 * Stores a completed run and rotates the previous one.
	 *
	 * @param array $results Results keyed by test identifier.
	 * @param array $summary Output of CASCR_Scoring::summarize().
	 * @return array The stored run.
	 */
	public static function save_run( $results, $summary ) {
		$current = get_option( self::OPTION_LAST, array() );
		if ( ! empty( $current ) ) {
			update_option( self::OPTION_PREVIOUS, $current, false );
		}

		$run = array(
			'generated' => time(),
			'version'   => CASCR_VERSION,
			'grade'     => $summary['grade'],
			'risk'      => $summary['risk'],
			'counts'    => $summary['counts'],
			'tests'     => array(),
		);

		foreach ( $results as $id => $result ) {
			$run['tests'][ $id ] = array(
				'status'  => $result['status'],
				'score'   => $result['score'],
				'summary' => $result['summary'],
				'hash'    => self::fingerprint( $result ),
				'ignored' => ! empty( $result['ignored'] ),
			);
		}

		update_option( self::OPTION_LAST, $run, false );

		return $run;
	}

	/**
	 * The most recent stored run, or an empty array.
	 *
	 * @return array
	 */
	public static function last_run() {
		$run = get_option( self::OPTION_LAST, array() );

		return is_array( $run ) ? $run : array();
	}

	/**
	 * The run before the most recent one, or an empty array.
	 *
	 * @return array
	 */
	public static function previous_run() {
		$run = get_option( self::OPTION_PREVIOUS, array() );

		return is_array( $run ) ? $run : array();
	}

	/**
	 * What changed between the two most recent runs.
	 *
	 * @param array $run      The newer run, defaults to the stored last run.
	 * @param array $previous The older run, defaults to the stored previous run.
	 * @return array|null Null when there is nothing to compare against.
	 */
	public static function diff( $run = null, $previous = null ) {
		$run      = null === $run ? self::last_run() : $run;
		$previous = null === $previous ? self::previous_run() : $previous;

		if ( empty( $run['tests'] ) || empty( $previous['tests'] ) ) {
			return null;
		}

		$broken   = array();
		$fixed    = array();
		$changed  = array();
		$is_issue = array( CASCR_Result::STATUS_FAIL, CASCR_Result::STATUS_WARN );

		foreach ( $run['tests'] as $id => $now ) {
			if ( ! isset( $previous['tests'][ $id ] ) ) {
				continue;
			}

			$before      = $previous['tests'][ $id ];
			$was_issue   = in_array( $before['status'], $is_issue, true );
			$is_issue_no = in_array( $now['status'], $is_issue, true );

			if ( $is_issue_no && ! $was_issue ) {
				$broken[] = $id;
			} elseif ( ! $is_issue_no && $was_issue ) {
				$fixed[] = $id;
			} elseif ( $is_issue_no && $was_issue && $before['hash'] !== $now['hash'] ) {
				$changed[] = $id;
			}
		}

		return array(
			'since'   => isset( $previous['generated'] ) ? (int) $previous['generated'] : 0,
			'broken'  => $broken,
			'fixed'   => $fixed,
			'changed' => $changed,
			'grade'   => array(
				'before' => isset( $previous['grade'] ) ? $previous['grade'] : '',
				'after'  => isset( $run['grade'] ) ? $run['grade'] : '',
			),
		);
	}

	/**
	 * Muted findings, keyed by test identifier.
	 *
	 * @return array
	 */
	public static function ignored() {
		$ignored = get_option( self::OPTION_IGNORED, array() );

		return is_array( $ignored ) ? $ignored : array();
	}

	/**
	 * Mutes a finding.
	 *
	 * In until_changed mode the fingerprint of the result is stored alongside
	 * it. As soon as the finding says something different, it comes back. This
	 * is the difference between accepting a known state and going blind.
	 *
	 * @param string $id     Test identifier.
	 * @param array  $result The result being muted.
	 * @param string $mode   IGNORE_PERMANENT or IGNORE_UNTIL_CHANGED.
	 * @return bool
	 */
	public static function ignore( $id, $result, $mode = self::IGNORE_UNTIL_CHANGED ) {
		if ( ! CASCR_Registry::exists( $id ) ) {
			return false;
		}

		if ( ! in_array( $mode, array( self::IGNORE_PERMANENT, self::IGNORE_UNTIL_CHANGED ), true ) ) {
			$mode = self::IGNORE_UNTIL_CHANGED;
		}

		$ignored        = self::ignored();
		$ignored[ $id ] = array(
			'mode'       => $mode,
			'hash'       => self::fingerprint( $result ),
			'ignored_at' => time(),
		);

		return update_option( self::OPTION_IGNORED, $ignored, false );
	}

	/**
	 * Unmutes a finding.
	 *
	 * @param string $id Test identifier.
	 * @return bool
	 */
	public static function unignore( $id ) {
		$ignored = self::ignored();

		if ( ! isset( $ignored[ $id ] ) ) {
			return false;
		}

		unset( $ignored[ $id ] );

		return update_option( self::OPTION_IGNORED, $ignored, false );
	}

	/**
	 * Whether a result should currently be hidden.
	 *
	 * @param string $id     Test identifier.
	 * @param array  $result The fresh result.
	 * @return bool
	 */
	public static function is_ignored( $id, $result ) {
		$ignored = self::ignored();

		if ( ! isset( $ignored[ $id ] ) ) {
			return false;
		}

		if ( self::IGNORE_PERMANENT === $ignored[ $id ]['mode'] ) {
			return true;
		}

		return $ignored[ $id ]['hash'] === self::fingerprint( $result );
	}

	/**
	 * A stable fingerprint of what a result is actually reporting.
	 *
	 * The summary is left out on purpose: it can change with a translation
	 * update without the underlying finding changing at all.
	 *
	 * @param array $result Result array.
	 * @return string
	 */
	public static function fingerprint( $result ) {
		$items = isset( $result['items'] ) ? $result['items'] : array();
		sort( $items );

		return md5(
			$result['status'] . '|' . $result['score'] . '|' . implode( "\n", $items )
		);
	}

	/**
	 * Reads a value from the drift baseline.
	 *
	 * @param string $key      Baseline key.
	 * @param mixed  $fallback Returned when the key was never recorded.
	 * @return mixed
	 */
	public static function baseline( $key, $fallback = null ) {
		$baseline = get_option( self::OPTION_BASELINE, array() );

		if ( ! is_array( $baseline ) || ! array_key_exists( $key, $baseline ) ) {
			return $fallback;
		}

		return $baseline[ $key ];
	}

	/**
	 * Records a baseline value, but never overwrites an existing one.
	 *
	 * Drift checks compare against the first observation. Overwriting it on
	 * every run would make the comparison meaningless.
	 *
	 * @param string $key   Baseline key.
	 * @param mixed  $value Value to record.
	 * @return bool True when a new value was written.
	 */
	public static function remember( $key, $value ) {
		$baseline = get_option( self::OPTION_BASELINE, array() );
		if ( ! is_array( $baseline ) ) {
			$baseline = array();
		}

		if ( array_key_exists( $key, $baseline ) ) {
			return false;
		}

		$baseline[ $key ] = $value;
		update_option( self::OPTION_BASELINE, $baseline, false );

		return true;
	}

	/**
	 * Replaces a baseline value after the user has accepted the change.
	 *
	 * @param string $key   Baseline key.
	 * @param mixed  $value Value to record.
	 */
	public static function rebase( $key, $value ) {
		$baseline = get_option( self::OPTION_BASELINE, array() );
		if ( ! is_array( $baseline ) ) {
			$baseline = array();
		}

		$baseline[ $key ] = $value;
		update_option( self::OPTION_BASELINE, $baseline, false );
	}

	/**
	 * Every option name the plugin creates. Used by the uninstall handler.
	 *
	 * @return string[]
	 */
	public static function option_names() {
		return array(
			self::OPTION_LAST,
			self::OPTION_PREVIOUS,
			self::OPTION_IGNORED,
			self::OPTION_BASELINE,
		);
	}
}
