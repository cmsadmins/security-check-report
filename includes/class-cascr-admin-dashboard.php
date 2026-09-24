<?php
/**
 * The view returning visitors see.
 *
 * @package CmsAdmins\SecurityCheck
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Markup for the checklist, the progress curve and the archive.
 *
 * Rendered in PHP rather than in the browser so the page stands on the stored
 * run alone, without a fresh pass.
 */
class CASCR_Admin_Dashboard {

	/**
	 * Height of the curve in user units, and the full scale with it.
	 *
	 * A bar stands for how well a run came out, not for how risky it was. Drawn
	 * the other way round the section called "Your progress" shows almost
	 * nothing once a site is in good shape, which is exactly when it has the
	 * most to show. Bars that grow as the site improves say the same thing and
	 * say it the way round people read it.
	 */
	const CURVE_HEIGHT = 100;

	/**
	 * Width of one bar and the gap that follows it, in user units.
	 *
	 * The drawing carries its own width, so ten runs fill the card the way a
	 * chart should and two runs stay a pair of bars rather than two slabs. Past
	 * roughly a dozen runs the page is narrower than the drawing and the
	 * stylesheet scales the whole row down, gaps included.
	 */
	const CURVE_BAR = 88;
	const CURVE_GAP = 20;

	/**
	 * Prints the dashboard view.
	 *
	 * @param array|null $run The stored run, read from the store when omitted.
	 */
	public static function render( $run = null ) {
		$run = null === $run ? CASCR_Store::last_run() : $run;

		if ( empty( $run['tests'] ) ) {
			return;
		}

		// Installations that were updated rather than newly installed arrive
		// here with two runs and no curve at all.
		CASCR_History::migrate();

		$summary = CASCR_Scoring::summarize( $run['tests'] );

		self::render_head( $run, $summary );
		self::render_curve();
		self::render_recheck( $run );
		self::render_tasks( $summary['priorities'] );
		self::render_open( $run, $summary['priorities'] );
		self::render_archive( $run );
		self::render_categories( $summary['categories'] );

		CASCR_Admin::render_results( $run );
		CASCR_Admin::render_export();
	}

	/**
	 * Grade, the line from the first run to today, and the way to start again.
	 *
	 * @param array $run     The stored run.
	 * @param array $summary Output of CASCR_Scoring::summarize().
	 */
	private static function render_head( $run, $summary ) {
		$grade = $summary['grade'];
		?>
		<section class="cascr-dash__head">
			<div class="cascr-score__card cascr-score__card--<?php echo esc_attr( strtolower( $grade ) ); ?>">
				<div class="cascr-score__grade">
					<span class="cascr-score__letter"><?php echo esc_html( $grade ); ?></span>
					<span class="cascr-score__label"><?php echo esc_html( CASCR_Scoring::grade_label( $grade ) ); ?></span>
				</div>

				<div class="cascr-score__meta">
					<div class="cascr-score__risk">
						<span class="cascr-score__risk-value"><?php echo esc_html( sprintf( '%s%%', $summary['risk'] ) ); ?></span>
						<span class="cascr-score__risk-label"><?php esc_html_e( 'Risk score', 'security-check-report' ); ?></span>
					</div>
					<p class="cascr-dash__journey"><?php echo wp_kses_post( self::journey( $grade, $summary['counts'] ) ); ?></p>
					<?php self::render_partial_note( $run ); ?>
				</div>

				<div class="cascr-dash__actions">
					<?php
					CASCR_Admin::render_consent();
					CASCR_Admin::render_launch( __( 'Re-check everything', 'security-check-report' ) );
					?>
				</div>
			</div>

			<?php CASCR_Admin::render_progress(); ?>

			<p class="cascr-score__verdict"><?php echo esc_html( $summary['verdict'] ); ?></p>
		</section>
		<?php
	}

	/**
	 * Where this site started and where it stands today.
	 *
	 * Both halves are finished sentences rather than numbers dropped into a
	 * template, because their plural form belongs to the number in them.
	 *
	 * @param string $grade  Current grade.
	 * @param array  $counts Status counts from summarize().
	 * @return string HTML, safe for wp_kses_post.
	 */
	private static function journey( $grade, $counts ) {
		$today = esc_html( CASCR_Scoring::today( $grade, $counts ) );

		$first = CASCR_History::first();

		if ( empty( $first['tests'] ) || count( CASCR_History::all() ) < 2 ) {
			return $today;
		}

		$start = sprintf(
			/* translators: 1: date of the first recorded run, 2: grade letter, 3: number of findings. */
			_n(
				'Started on %1$s: grade %2$s with %3$d finding.',
				'Started on %1$s: grade %2$s with %3$d findings.',
				self::findings( $first ),
				'security-check-report'
			),
			esc_html( wp_date( get_option( 'date_format' ), (int) $first['t'] ) ),
			esc_html( $first['g'] ),
			self::findings( $first )
		);

		return $start . ' ' . $today;
	}

	/**
	 * How many checks a recorded point counted as a finding.
	 *
	 * @param array $point One entry of the history.
	 * @return int
	 */
	private static function findings( $point ) {
		$marks = array( CASCR_History::MARK_FAIL, CASCR_History::MARK_WARN );
		$found = 0;

		foreach ( $point['tests'] as $mark ) {
			if ( in_array( $mark, $marks, true ) ) {
				++$found;
			}
		}

		return $found;
	}

	/**
	 * Says so when the grade no longer comes from a single pass.
	 *
	 * @param array $run The stored run.
	 */
	private static function render_partial_note( $run ) {
		$note = self::partial_line( $run );

		if ( '' === $note ) {
			return;
		}
		?>
		<p class="cascr-dash__partial"><?php echo esc_html( $note ); ?></p>
		<?php
	}

	/**
	 * How many checks were re-checked on their own since the last full pass.
	 *
	 * Built as a finished sentence for the same reason as the verdict: the
	 * count changes with every re-check and its plural form belongs to it.
	 *
	 * @param array $run The stored run.
	 * @return string Empty when the grade still comes from a single pass.
	 */
	private static function partial_line( $run ) {
		if ( empty( $run['partial'] ) || ! is_array( $run['partial'] ) ) {
			return '';
		}

		$count = count( $run['partial'] );

		return sprintf(
			/* translators: 1: number of checks re-checked on their own, 2: date of the last full pass. */
			_n(
				'%1$d check has been re-checked on its own since the full pass on %2$s.',
				'%1$d checks have been re-checked on their own since the full pass on %2$s.',
				$count,
				'security-check-report'
			),
			$count,
			wp_date( get_option( 'date_format' ), isset( $run['generated'] ) ? (int) $run['generated'] : time() )
		);
	}

	/**
	 * Every re-check the stored run has a recorded outcome for.
	 *
	 * The run carries one entry per identifier under 'partial', newest last.
	 * That single field is what the note about the partial grade counts, what
	 * the message below the curve reports and what the archive reads, so there
	 * is nothing to keep in step.
	 *
	 * @param array $run The stored run.
	 * @return array List of entries with id, time, status and summary.
	 */
	private static function rechecks( $run ) {
		if ( empty( $run['partial'] ) || ! is_array( $run['partial'] ) ) {
			return array();
		}

		$entries = array();

		foreach ( $run['partial'] as $id => $entry ) {
			// Before the outcome was kept, the field held nothing but the
			// time of the re-check. Those entries still count towards the
			// partial note, but there is no result to report for them.
			if ( ! is_array( $entry ) || ! isset( $entry['status'] ) ) {
				continue;
			}

			$entries[] = array(
				'id'      => $id,
				't'       => isset( $entry['t'] ) ? (int) $entry['t'] : 0,
				'status'  => $entry['status'],
				'summary' => isset( $entry['summary'] ) ? $entry['summary'] : '',
			);
		}

		return $entries;
	}

	/**
	 * What the last re-check found, in the place the page shows hints.
	 *
	 * Without this the answer lived in the browser alone: sighted users saw
	 * nothing at all when a check came back still failing, and anyone who
	 * reloaded lost the confirmation that it had passed. The history stays out
	 * of it, a partial pass is not a run.
	 *
	 * @param array $run The stored run.
	 */
	private static function render_recheck( $run ) {
		$entries = self::rechecks( $run );

		if ( empty( $entries ) ) {
			return;
		}

		$last   = end( $entries );
		$passed = CASCR_Result::STATUS_PASS === $last['status'];
		$test   = CASCR_Registry::get( $last['id'] );
		$label  = $test ? $test['label'] : $last['id'];

		if ( $passed ) {
			/* translators: %s: name of the check. */
			$headline = sprintf( __( '%s passed the re-check.', 'security-check-report' ), $label );
		} else {
			/* translators: %s: name of the check. */
			$headline = sprintf( __( '%s is still open after the re-check.', 'security-check-report' ), $label );
		}
		?>
		<div class="notice notice-<?php echo $passed ? 'success' : 'warning'; ?> cascr-notice" id="cascr-recheck">
			<p>
				<strong><?php echo esc_html( $headline ); ?></strong>
				<?php echo esc_html( $last['summary'] ); ?>
			</p>
		</div>
		<?php
	}

	/**
	 * One bar per recorded run, drawn by hand.
	 *
	 * A single point is not a development, so the curve stays away until there
	 * is something to compare.
	 */
	private static function render_curve() {
		$points = CASCR_History::all();
		$total  = count( $points );

		if ( $total < 2 ) {
			return;
		}

		$width = $total * ( self::CURVE_BAR + self::CURVE_GAP ) - self::CURVE_GAP;
		?>
		<section class="cascr-curve">
			<h2 class="cascr-section__title"><?php esc_html_e( 'Your progress', 'security-check-report' ); ?></h2>

			<svg
				class="cascr-curve__svg"
				width="<?php echo esc_attr( (string) $width ); ?>"
				height="<?php echo esc_attr( (string) self::CURVE_HEIGHT ); ?>"
				viewBox="<?php echo esc_attr( sprintf( '0 0 %1$d %2$d', $width, self::CURVE_HEIGHT ) ); ?>"
				preserveAspectRatio="none"
				role="img"
				aria-label="<?php echo esc_attr( __( 'How the site scored across the recorded runs, oldest on the left. A taller bar is a better run.', 'security-check-report' ) ); ?>"
			>
				<?php
				$index = 0;

				foreach ( $points as $point ) {
					$risk = isset( $point['r'] ) ? (float) $point['r'] : 0.0;

					// A run with everything wrong still gets a stub, so the
					// worst point on the chart is a bar and not a gap.
					$height = (int) max( 3, round( ( 100 - $risk ) / 100 * self::CURVE_HEIGHT ) );
					$grade  = isset( $point['g'] ) && '' !== $point['g'] ? $point['g'] : 'F';
					?>
					<rect
						class="cascr-curve__bar cascr-curve__bar--<?php echo esc_attr( strtolower( $grade ) ); ?>"
						x="<?php echo esc_attr( (string) ( $index * ( self::CURVE_BAR + self::CURVE_GAP ) ) ); ?>"
						y="<?php echo esc_attr( (string) ( self::CURVE_HEIGHT - $height ) ); ?>"
						width="<?php echo esc_attr( (string) self::CURVE_BAR ); ?>"
						height="<?php echo esc_attr( (string) $height ); ?>"
					>
						<title>
							<?php
							printf(
								/* translators: 1: date of the run, 2: grade letter. */
								esc_html__( '%1$s: grade %2$s', 'security-check-report' ),
								esc_html( wp_date( get_option( 'date_format' ), (int) $point['t'] ) ),
								esc_html( $grade )
							);
							?>
						</title>
					</rect>
					<?php
					++$index;
				}
				?>
			</svg>

			<p class="cascr-curve__legend">
				<?php
				printf(
					/* translators: %d: number of recorded runs. */
					esc_html( _n( '%d recorded run. A taller bar is a better run.', '%d recorded runs, the oldest on the left. A taller bar is a better run.', $total, 'security-check-report' ) ),
					(int) $total
				);
				?>
			</p>
		</section>
		<?php
	}

	/**
	 * The short list, as tasks rather than as a report.
	 *
	 * @param array $priorities Output of CASCR_Scoring::priorities().
	 */
	private static function render_tasks( $priorities ) {
		?>
		<section class="cascr-tasks" id="cascr-tasks">
			<h2 class="cascr-section__title"><?php esc_html_e( 'Your next five', 'security-check-report' ); ?></h2>
			<p class="cascr-section__lead"><?php esc_html_e( 'Work through these in order. Everything else can wait.', 'security-check-report' ); ?></p>

			<ol class="cascr-tasks__list">
				<?php
				foreach ( $priorities as $task ) {
					self::render_task( $task );
				}
				?>
			</ol>

			<?php if ( empty( $priorities ) ) : ?>
				<p class="cascr-empty"><?php esc_html_e( 'Nothing needs your attention right now.', 'security-check-report' ); ?></p>
			<?php endif; ?>
		</section>
		<?php
	}

	/**
	 * One task card.
	 *
	 * @param array $task One entry of the priority list.
	 */
	private static function render_task( $task ) {
		?>
		<li class="cascr-task cascr-task--<?php echo esc_attr( $task['severity'] ); ?>" data-cascr-task="<?php echo esc_attr( $task['id'] ); ?>">
			<div class="cascr-task__head">
				<span class="cascr-task__label"><?php echo esc_html( $task['label'] ); ?></span>
				<span class="cascr-badge cascr-badge--<?php echo esc_attr( $task['severity'] ); ?>">
					<?php echo esc_html( CASCR_Admin::severity_label( $task['severity'] ) ); ?>
				</span>
			</div>

			<p class="cascr-task__summary"><?php echo esc_html( $task['summary'] ); ?></p>

			<?php if ( ! empty( $task['fix'] ) ) : ?>
				<p class="cascr-task__fix"><?php echo esc_html( $task['fix'] ); ?></p>
			<?php endif; ?>

			<?php if ( ! empty( $task['link']['url'] ) ) : ?>
				<a class="cascr-result__helper" href="<?php echo esc_url( $task['link']['url'] ); ?>" target="_blank" rel="noopener noreferrer">
					<?php echo esc_html( $task['link']['label'] ); ?>
				</a>
			<?php endif; ?>

			<div class="cascr-task__actions">
				<button type="button" class="button button-primary" data-cascr-recheck="<?php echo esc_attr( $task['id'] ); ?>">
					<?php esc_html_e( 'Done, check it now', 'security-check-report' ); ?>
				</button>
				<button type="button" class="button button-link cascr-task__later" data-cascr-later="<?php echo esc_attr( $task['id'] ); ?>">
					<?php esc_html_e( 'later', 'security-check-report' ); ?>
				</button>
				<a class="cascr-result__link" href="#cascr-doc-<?php echo esc_attr( $task['id'] ); ?>" data-cascr-doc="<?php echo esc_attr( $task['id'] ); ?>">
					<?php esc_html_e( 'Read more about this check', 'security-check-report' ); ?>
				</a>
			</div>
		</li>
		<?php
	}

	/**
	 * Everything else that is still a finding, without the buttons.
	 *
	 * Folded away and stripped of actions on purpose: if everything is a task,
	 * the five above stop meaning anything.
	 *
	 * @param array $run        The stored run.
	 * @param array $priorities The entries already shown as tasks.
	 */
	private static function render_open( $run, $priorities ) {
		$tasked = wp_list_pluck( $priorities, 'id' );
		$open   = array();
		$issues = array( CASCR_Result::STATUS_FAIL, CASCR_Result::STATUS_WARN );

		foreach ( $run['tests'] as $id => $test ) {
			if ( ! empty( $test['ignored'] ) || in_array( $id, $tasked, true ) ) {
				continue;
			}

			if ( in_array( $test['status'], $issues, true ) && CASCR_Registry::exists( $id ) ) {
				$open[ $id ] = $test;
			}
		}

		if ( empty( $open ) ) {
			return;
		}
		?>
		<details class="cascr-openlist" id="cascr-open">
			<summary class="cascr-openlist__summary">
				<?php
				printf(
					/* translators: %d: number of findings that are not on the short list. */
					esc_html__( 'Still open (%d)', 'security-check-report' ),
					count( $open )
				);
				?>
			</summary>

			<ul class="cascr-openlist__list">
				<?php foreach ( $open as $id => $test ) : ?>
					<?php $definition = CASCR_Registry::get( $id ); ?>
					<li class="cascr-openlist__item">
						<span class="cascr-status cascr-status--<?php echo esc_attr( $test['status'] ); ?>">
							<?php echo esc_html( CASCR_Admin::status_label( $test['status'] ) ); ?>
						</span>
						<span class="cascr-openlist__label"><?php echo esc_html( $definition ? $definition['label'] : $id ); ?></span>
						<span class="cascr-openlist__text"><?php echo esc_html( $test['summary'] ); ?></span>
					</li>
				<?php endforeach; ?>
			</ul>
		</details>
		<?php
	}

	/**
	 * What this site has already put behind it.
	 *
	 * The history is the long record and a partial pass never writes to it, so
	 * a task solved by a single re-check would be invisible here until the next
	 * full run. Those entries are read from the run instead and are marked, so
	 * nobody mistakes them for a measured pass of the whole site.
	 *
	 * @param array $run The stored run.
	 */
	private static function render_archive( $run ) {
		$entries = array();

		foreach ( CASCR_History::resolved() as $id => $time ) {
			$entries[ $id ] = array(
				'time'    => (int) $time,
				'recheck' => false,
			);
		}

		foreach ( self::rechecks( $run ) as $entry ) {
			if ( CASCR_Result::STATUS_PASS !== $entry['status'] ) {
				// Measured as a finding again since the run the history
				// recorded. Claiming it as resolved would be a lie the page
				// contradicts three sections further up.
				unset( $entries[ $entry['id'] ] );
				continue;
			}

			$entries[ $entry['id'] ] = array(
				'time'    => $entry['t'],
				'recheck' => true,
			);
		}

		if ( empty( $entries ) ) {
			return;
		}

		uasort(
			$entries,
			function ( $a, $b ) {
				return $b['time'] - $a['time'];
			}
		);
		?>
		<details class="cascr-archive">
			<summary class="cascr-archive__summary">
				<?php
				printf(
					/* translators: %d: number of checks that were a finding once and pass now. */
					esc_html__( 'Resolved (%d)', 'security-check-report' ),
					count( $entries )
				);
				?>
			</summary>

			<ul class="cascr-archive__list">
				<?php foreach ( $entries as $id => $entry ) : ?>
					<?php $test = CASCR_Registry::get( $id ); ?>
					<li class="cascr-archive__item">
						<span class="cascr-archive__label"><?php echo esc_html( $test ? $test['label'] : $id ); ?></span>
						<?php if ( $entry['recheck'] ) : ?>
							<span class="cascr-archive__mark"><?php esc_html_e( 'after a re-check', 'security-check-report' ); ?></span>
						<?php endif; ?>
						<span class="cascr-archive__date"><?php echo esc_html( wp_date( get_option( 'date_format' ), $entry['time'] ) ); ?></span>
					</li>
				<?php endforeach; ?>
			</ul>
		</details>
		<?php
	}

	/**
	 * Passed against total, per area of the site.
	 *
	 * @param array $categories The categories block of the summary.
	 */
	private static function render_categories( $categories ) {
		$labels = CASCR_Registry::categories();
		?>
		<section class="cascr-cats">
			<h2 class="cascr-section__title"><?php esc_html_e( 'By category', 'security-check-report' ); ?></h2>

			<ul class="cascr-cats__list">
				<?php
				foreach ( $labels as $category => $label ) {
					if ( empty( $categories[ $category ] ) ) {
						continue;
					}

					$counts = $categories[ $category ];
					$total  = array_sum( $counts );
					$passed = (int) $counts['pass'];
					$share  = $total > 0 ? round( $passed / $total * 100 ) : 0;
					?>
					<li class="cascr-cat">
						<span class="cascr-cat__label"><?php echo esc_html( $label ); ?></span>
						<span class="cascr-cat__track">
							<span class="cascr-cat__fill" style="width:<?php echo esc_attr( (string) $share ); ?>%"></span>
						</span>
						<span class="cascr-cat__count">
							<?php
							printf(
								/* translators: 1: number of passed checks, 2: number of checks in the category. */
								esc_html__( '%1$d of %2$d passed', 'security-check-report' ),
								(int) $passed,
								(int) $total
							);
							?>
						</span>
					</li>
					<?php
				}
				?>
			</ul>
		</section>
		<?php
	}
}
