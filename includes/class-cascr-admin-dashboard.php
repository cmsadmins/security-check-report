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
	 * Height of the curve in user units. Also the full risk scale, so a bar is
	 * as many units tall as the run was risky.
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
		self::render_tasks( $summary['priorities'] );
		self::render_open( $run, $summary['priorities'] );
		self::render_archive();
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
			<div class="cascr-score__card cascr-score__card--<?php echo esc_attr( strtolower( $grade ) ); ?>" data-cascr-card>
				<div class="cascr-score__grade">
					<span class="cascr-score__letter" data-cascr-letter><?php echo esc_html( $grade ); ?></span>
					<span class="cascr-score__label" data-cascr-grade-label><?php echo esc_html( CASCR_Scoring::grade_label( $grade ) ); ?></span>
				</div>

				<div class="cascr-score__meta">
					<div class="cascr-score__risk">
						<span class="cascr-score__risk-value" data-cascr-risk><?php echo esc_html( sprintf( '%s%%', $summary['risk'] ) ); ?></span>
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

			<p class="cascr-score__verdict" data-cascr-verdict><?php echo esc_html( $summary['verdict'] ); ?></p>
		</section>
		<?php
	}

	/**
	 * Where this site started and where it stands today.
	 *
	 * The second half carries a hook of its own: a re-check moves it, and a
	 * head that shows one grade while the sentence below it claims another is
	 * worse than no sentence at all. The whole sentence is swapped rather than
	 * the numbers inside it, because its plural form belongs to the number.
	 *
	 * @param string $grade  Current grade.
	 * @param array  $counts Status counts from summarize().
	 * @return string HTML, safe for wp_kses_post.
	 */
	private static function journey( $grade, $counts ) {
		$today = '<span data-cascr-today>' . esc_html( CASCR_Scoring::today( $grade, $counts ) ) . '</span>';

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
	 * The paragraph is always in the markup, empty and hidden while the grade
	 * still comes from one pass: the first re-check has to be able to put the
	 * sentence there without a reload, and a claim like this one appearing a
	 * page load too late is the same as it missing.
	 *
	 * @param array $run The stored run.
	 */
	private static function render_partial_note( $run ) {
		$note = self::partial_line( $run );
		?>
		<p class="cascr-dash__partial" data-cascr-partial <?php echo '' === $note ? 'hidden' : ''; ?>><?php echo esc_html( $note ); ?></p>
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
	public static function partial_line( $run ) {
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
				aria-label="<?php echo esc_attr( __( 'Risk over the recorded runs, oldest on the left.', 'security-check-report' ) ); ?>"
			>
				<?php
				$index = 0;

				foreach ( $points as $point ) {
					$risk   = isset( $point['r'] ) ? (float) $point['r'] : 0.0;
					$height = (int) max( 2, round( $risk / 100 * self::CURVE_HEIGHT ) );
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
					esc_html( _n( '%d recorded run, the oldest on the left.', '%d recorded runs, the oldest on the left.', $total, 'security-check-report' ) ),
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

			<ul class="cascr-tasks__done" id="cascr-tasks-done"></ul>

			<ol class="cascr-tasks__list" id="cascr-tasks-list">
				<?php
				foreach ( $priorities as $task ) {
					self::render_task( $task );
				}
				?>
			</ol>

			<p class="cascr-empty" id="cascr-tasks-empty" <?php echo empty( $priorities ) ? '' : 'hidden'; ?>>
				<?php esc_html_e( 'Nothing needs your attention right now.', 'security-check-report' ); ?>
			</p>
		</section>
		<?php
	}

	/**
	 * One task card.
	 *
	 * The browser rebuilds this shape after a re-check, so the class names here
	 * and the ones in admin.js have to stay in step.
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

			<p class="cascr-task__summary" data-cascr-task-summary><?php echo esc_html( $task['summary'] ); ?></p>

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
				<span data-cascr-open-count>
					<?php
					printf(
						/* translators: %d: number of findings that are not on the short list. */
						esc_html__( 'Still open (%d)', 'security-check-report' ),
						count( $open )
					);
					?>
				</span>
			</summary>

			<ul class="cascr-openlist__list">
				<?php foreach ( $open as $id => $test ) : ?>
					<?php $definition = CASCR_Registry::get( $id ); ?>
					<li class="cascr-openlist__item" data-cascr-open="<?php echo esc_attr( $id ); ?>">
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
	 */
	private static function render_archive() {
		$resolved = CASCR_History::resolved();

		if ( empty( $resolved ) ) {
			return;
		}

		arsort( $resolved );
		?>
		<details class="cascr-archive">
			<summary class="cascr-archive__summary">
				<?php
				printf(
					/* translators: %d: number of checks that were a finding once and pass now. */
					esc_html__( 'Resolved (%d)', 'security-check-report' ),
					count( $resolved )
				);
				?>
			</summary>

			<ul class="cascr-archive__list">
				<?php foreach ( $resolved as $id => $time ) : ?>
					<?php $test = CASCR_Registry::get( $id ); ?>
					<li class="cascr-archive__item">
						<span class="cascr-archive__label"><?php echo esc_html( $test ? $test['label'] : $id ); ?></span>
						<span class="cascr-archive__date"><?php echo esc_html( wp_date( get_option( 'date_format' ), (int) $time ) ); ?></span>
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
