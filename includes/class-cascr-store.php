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
	const OPTION_CONSENT  = 'cascr_consent';
	const OPTION_BADGE    = 'cascr_badge';

	/**
	 * First version whose stored run carries the findings of each test.
	 */
	const SHAPE_ITEMS = '2.4.0';

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
		// Old installations have two runs and no history. Seeding before the
		// rotation is the last moment at which both of them still exist.
		CASCR_History::migrate();

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
			$run['tests'][ $id ] = self::stored_test( $result );
		}

		update_option( self::OPTION_LAST, $run, false );

		self::remember_badge( $summary['counts'] );

		CASCR_History::append( $run );

		return $run;
	}

	/**
	 * Replaces one test inside the stored run after a re-check.
	 *
	 * Everything else in the run is left exactly as the last full pass found
	 * it. The outcome is noted under 'partial' so the interface can say that the
	 * grade no longer comes from a single pass and can show what the re-check
	 * actually found, and the history stays untouched: a re-check is not a run.
	 *
	 * The option is read here rather than by the caller because the check itself
	 * takes seconds to run. Two re-checks started in that window would both write
	 * back the copy they read before it, and whichever finished first would be
	 * gone without a word.
	 *
	 * @param string $id     Test identifier.
	 * @param array  $result The fresh result.
	 * @return array|false The updated run, or false when there is nothing to patch.
	 */
	public static function patch_test( $id, $result ) {
		$run = self::last_run();

		if ( empty( $run['tests'] ) || ! isset( $run['tests'][ $id ] ) ) {
			return false;
		}

		$run['tests'][ $id ] = self::stored_test( $result );

		$partial = isset( $run['partial'] ) && is_array( $run['partial'] ) ? $run['partial'] : array();

		// Re-inserted rather than overwritten in place, so the most recent
		// re-check is the last entry and the page can report on it without
		// carrying a second field for the same thing.
		unset( $partial[ $id ] );

		$partial[ $id ] = array(
			't'       => time(),
			'status'  => $result['status'],
			'summary' => $result['summary'],
		);

		$run['partial'] = $partial;

		$summary = CASCR_Scoring::summarize( $run['tests'] );

		$run['grade']  = $summary['grade'];
		$run['risk']   = $summary['risk'];
		$run['counts'] = $summary['counts'];

		update_option( self::OPTION_LAST, $run, false );

		self::remember_badge( $summary['counts'] );

		return $run;
	}

	/**
	 * The one number the menu bubble needs, kept apart from the run.
	 *
	 * The bubble is drawn on every single admin page. Reading the full run for
	 * it would unserialise the findings of sixty checks each time, so the count
	 * gets an option of its own. It is an integer, so this is the one value
	 * here that is worth autoloading.
	 *
	 * @param array $counts Status counts from CASCR_Scoring::summarize().
	 */
	private static function remember_badge( $counts ) {
		update_option( self::OPTION_BADGE, isset( $counts['fail'] ) ? (int) $counts['fail'] : 0 );
	}

	/**
	 * Open failures as of the last write, or zero when nothing is known.
	 *
	 * @return int
	 */
	public static function badge() {
		return (int) get_option( self::OPTION_BADGE, 0 );
	}

	/**
	 * Whether the site owner has agreed to the checks being run.
	 *
	 * Anyone with a stored run has agreed at least once, back when the checkbox
	 * was still asked on every visit. Asking them again after an update would
	 * be a step backwards.
	 *
	 * @return bool
	 */
	public static function consent() {
		if ( (int) get_option( self::OPTION_CONSENT, 0 ) > 0 ) {
			return true;
		}

		return ! empty( self::last_run() );
	}

	/**
	 * Records the one time agreement.
	 *
	 * @return int The recorded timestamp.
	 */
	public static function set_consent() {
		$now = time();

		update_option( self::OPTION_CONSENT, $now, false );

		return $now;
	}

	/**
	 * The shape a result is remembered in.
	 *
	 * One place for it, because a run written by the full pass and a run
	 * patched by a re-check have to be indistinguishable afterwards. The items
	 * come along because the page is rendered from the stored run alone: without
	 * them nobody could see what a finding actually named. Their length is
	 * already bounded by CASCR_Checks_Base::cap().
	 *
	 * @param array $result Result array.
	 * @return array
	 */
	private static function stored_test( $result ) {
		return array(
			'status'  => $result['status'],
			'score'   => $result['score'],
			'summary' => $result['summary'],
			'items'   => isset( $result['items'] ) && is_array( $result['items'] ) ? array_values( $result['items'] ) : array(),
			'fix'     => isset( $result['fix'] ) ? $result['fix'] : '',
			'link'    => isset( $result['link'] ) ? $result['link'] : array(),
			'hash'    => self::fingerprint( $result ),
			'ignored' => ! empty( $result['ignored'] ),
		);
	}

	/**
	 * The most recent stored run, or an empty array.
	 *
	 * @return array
	 */
	public static function last_run() {
		$run = self::normalize( get_option( self::OPTION_LAST, array() ) );

		// A run written before this shape existed carries mute flags that were
		// right when it was measured and a fingerprint that cannot be matched
		// any more. Deciding again on such a run would silently drop every
		// existing mute until the next full pass.
		if ( self::predates_items( $run ) ) {
			return $run;
		}

		return self::apply_mutes( $run );
	}

	/**
	 * Whether a run was written before a stored test carried its findings.
	 *
	 * The mute fingerprint is taken over the items, so a run without them can
	 * never produce the hash a live result produced. Runs of this shape carry
	 * their version, so this settles itself the moment a full pass is done.
	 *
	 * @param array $run A run that has been through normalize().
	 * @return bool
	 */
	private static function predates_items( $run ) {
		if ( empty( $run['tests'] ) ) {
			return false;
		}

		return empty( $run['version'] ) || version_compare( (string) $run['version'], self::SHAPE_ITEMS, '<' );
	}

	/**
	 * The run before the most recent one, or an empty array.
	 *
	 * @return array
	 */
	public static function previous_run() {
		return self::normalize( get_option( self::OPTION_PREVIOUS, array() ) );
	}

	/**
	 * Re-reads the mute state of every test in a run.
	 *
	 * A run records what was muted at the moment it was measured. Muting is a
	 * decision taken afterwards, usually while reading that very run, so the
	 * recorded flag is out of date the moment it matters. Handing it back
	 * verbatim left a finding that had just been sent away sitting on the list
	 * until the next full pass, which read as the button doing nothing.
	 *
	 * The previous run is deliberately left alone. It is only ever used to say
	 * what changed, and there the state at the time of measuring is the honest
	 * answer.
	 *
	 * @param array $run A run that has been through normalize().
	 * @return array
	 */
	private static function apply_mutes( $run ) {
		if ( empty( $run['tests'] ) || ! is_array( $run['tests'] ) ) {
			return $run;
		}

		foreach ( $run['tests'] as $id => $test ) {
			$run['tests'][ $id ]['ignored'] = self::is_ignored( $id, $test );
		}

		return $run;
	}

	/**
	 * Fills in what a run written by an older version does not carry.
	 *
	 * Up to 2.3.2 a stored test held status, score, summary, hash and ignored
	 * and nothing else. Scoring reads the remediation step and the help link,
	 * the rendered result list reads the findings, and the first page view
	 * after an update would otherwise run into whichever of them it touches
	 * first. Doing it on the way out of the option means no caller has to know
	 * which version wrote the run.
	 *
	 * The union keeps the keys a current run already has, in their order, so a
	 * run written by this version passes through unchanged.
	 *
	 * @param mixed $run Whatever the option holds.
	 * @return array
	 */
	private static function normalize( $run ) {
		if ( ! is_array( $run ) ) {
			return array();
		}

		if ( empty( $run['tests'] ) || ! is_array( $run['tests'] ) ) {
			return $run;
		}

		$defaults = array(
			'status'  => CASCR_Result::STATUS_INCONCLUSIVE,
			'score'   => 0,
			'summary' => '',
			'items'   => array(),
			'fix'     => '',
			'link'    => array(),
			'hash'    => '',
			'ignored' => false,
		);

		foreach ( $run['tests'] as $id => $test ) {
			$run['tests'][ $id ] = (array) $test + $defaults;
		}

		return $run;
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

		$saved = update_option( self::OPTION_IGNORED, $ignored, false );
		self::recount_run();

		return $saved;
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

		$saved = update_option( self::OPTION_IGNORED, $ignored, false );
		self::recount_run();

		return $saved;
	}

	/**
	 * Rescores the stored run after muting changed what counts as a failure.
	 *
	 * Muting does not write a run, and the grade, the counts and the risk in
	 * the stored run are not derived on the way out: the export route hands
	 * them straight to the browser and the dashboard widget reads them as they
	 * are. Left alone they kept describing a finding the site owner had just
	 * sent away, so a downloaded report contradicted its own result list and
	 * the widget claimed open tasks the report page no longer had. Reading the
	 * full run here is fine, this happens once per click rather than on every
	 * page.
	 */
	private static function recount_run() {
		$run = self::last_run();

		if ( empty( $run['tests'] ) ) {
			return;
		}

		$summary = CASCR_Scoring::summarize( $run['tests'] );

		$run['grade']  = $summary['grade'];
		$run['risk']   = $summary['risk'];
		$run['counts'] = $summary['counts'];

		update_option( self::OPTION_LAST, $run, false );

		self::remember_badge( $summary['counts'] );
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
			self::OPTION_CONSENT,
			self::OPTION_BADGE,
			CASCR_History::OPTION,
		);
	}
}
