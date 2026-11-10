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
		$next    = CASCR_Scoring::next_grade( $run['tests'] );

		self::render_head( $run, $summary, $next );
		self::render_curve();
		self::render_recheck( $run );
		self::render_tasks( $summary['priorities'], $next );
		self::render_open( $run, $summary['priorities'] );
		self::render_archive( $run );
		self::render_milestones();
		self::render_categories( $summary['categories'] );

		CASCR_Admin::render_results( $run );
		CASCR_Admin::render_export();
	}

	/**
	 * Grade, the line from the first run to today, and the way to start again.
	 *
	 * @param array      $run     The stored run.
	 * @param array      $summary Output of CASCR_Scoring::summarize().
	 * @param array|null $next    Output of CASCR_Scoring::next_grade().
	 */
	private static function render_head( $run, $summary, $next ) {
		$grade = $summary['grade'];
		?>
		<section class="cascr-dash__head" id="cascr-summary" tabindex="-1" aria-label="<?php esc_attr_e( 'Result of the latest run', 'security-check-report' ); ?>">
			<div class="cascr-score__card cascr-score__card--dash cascr-score__card--<?php echo esc_attr( strtolower( $grade ) ); ?>">
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
					<?php self::render_since_last(); ?>
					<?php self::render_partial_note( $run ); ?>
				</div>

				<div class="cascr-dash__actions">
					<?php
					// The button belongs at the top of its column. The consent
					// checkbox has to come first while it is still unticked,
					// because the hint under the button points up at it.
					if ( CASCR_Store::consent() ) {
						CASCR_Admin::render_launch( __( 'Re-check everything', 'security-check-report' ) );
						CASCR_Admin::render_consent();
					} else {
						CASCR_Admin::render_consent();
						CASCR_Admin::render_launch( __( 'Re-check everything', 'security-check-report' ) );
					}
					?>
				</div>

				<?php self::render_goals( $run, $next ); ?>
			</div>

			<?php CASCR_Admin::render_progress(); ?>

			<p class="cascr-score__verdict"><?php echo esc_html( $summary['verdict'] ); ?></p>
		</section>
		<?php
	}

	/**
	 * What the latest run changed against the one before it. Silent when
	 * nothing changed or there is no earlier run.
	 */
	private static function render_since_last() {
		$diff = CASCR_Store::diff();

		if ( null === $diff ) {
			return;
		}

		// A grade can move without any check changing sides, when a score
		// inside a finding grows or shrinks. That alone is worth the line.
		$moved = self::grade_move( $diff['grade']['before'], $diff['grade']['after'] );

		if ( '' === $moved && empty( $diff['broken'] ) && empty( $diff['fixed'] ) ) {
			return;
		}

		$parts = array();

		if ( ! empty( $diff['broken'] ) ) {
			$parts[] = sprintf(
				/* translators: %d: number of checks that turned into a finding. */
				_n( '%d new finding', '%d new findings', count( $diff['broken'] ), 'security-check-report' ),
				count( $diff['broken'] )
			);
		}

		if ( ! empty( $diff['fixed'] ) ) {
			$parts[] = sprintf(
				/* translators: %d: number of findings that are gone. */
				_n( '%d resolved', '%d resolved', count( $diff['fixed'] ), 'security-check-report' ),
				count( $diff['fixed'] )
			);
		}
		?>
		<p class="cascr-dash__journey cascr-dash__since">
			<?php
			echo esc_html(
				trim(
					$moved . ' ' . ( empty( $parts ) ? '' : sprintf(
						/* translators: %s: list such as "2 new findings, 3 resolved". */
						__( 'Since the run before: %s.', 'security-check-report' ),
						implode( ', ', $parts )
					) )
				)
			);
			?>
		</p>
		<?php
	}

	/**
	 * One sentence when the grade moved between two runs, empty otherwise.
	 *
	 * @param string $before Grade of the run before.
	 * @param string $after  Grade of the latest run.
	 * @return string
	 */
	private static function grade_move( $before, $after ) {
		$order = 'ABCDF';

		if ( '' === $before || '' === $after || $before === $after
			|| false === strpos( $order, $before ) || false === strpos( $order, $after ) ) {
			return '';
		}

		if ( strpos( $order, $after ) < strpos( $order, $before ) ) {
			/* translators: 1: grade before, 2: grade now. */
			return sprintf( __( 'Grade up from %1$s to %2$s.', 'security-check-report' ), $before, $after );
		}

		/* translators: 1: grade before, 2: grade now. */
		return sprintf( __( 'Grade down from %1$s to %2$s.', 'security-check-report' ), $before, $after );
	}

	/**
	 * The distance to the next grade, the monthly streak and what this run
	 * reached for the first time, as a row of its own under the grade. Each
	 * entry only when it has something to say, the row only when one does.
	 *
	 * @param array      $run  The stored run.
	 * @param array|null $next Output of CASCR_Scoring::next_grade().
	 */
	private static function render_goals( $run, $next ) {
		$goals = array();

		if ( null !== $next ) {
			$count = count( $next['ids'] );
			$line  = sprintf(
				/* translators: 1: number of tasks, 2: grade letter. */
				_n( '%1$d task away from grade %2$s.', '%1$d tasks away from grade %2$s.', $count, 'security-check-report' ),
				$count,
				$next['grade']
			);

			if ( $count <= 3 ) {
				$names = array();
				foreach ( $next['ids'] as $id ) {
					$test    = CASCR_Registry::get( $id );
					$names[] = $test ? $test['label'] : $id;
				}
				/* translators: %s: comma separated names of checks. */
				$line .= ' ' . sprintf( __( 'Fix: %s.', 'security-check-report' ), implode( ', ', $names ) );
			}

			$goals[] = array( __( 'Next grade', 'security-check-report' ), $line );
		}

		$streak = CASCR_Milestones::streak();
		if ( $streak >= 2 ) {
			$goals[] = array(
				__( 'Streak', 'security-check-report' ),
				/* translators: %d: number of months in a row with a full run. */
				sprintf( _n( 'Checked every month for %d month.', 'Checked every month for %d months.', $streak, 'security-check-report' ), $streak ),
			);
		}

		$labels = CASCR_Milestones::labels();
		foreach ( CASCR_Milestones::new_in( $run ) as $key ) {
			if ( isset( $labels[ $key ] ) ) {
				$goals[] = array(
					__( 'Milestone', 'security-check-report' ),
					/* translators: %s: name of a milestone. */
					sprintf( __( 'Reached with this run: %s.', 'security-check-report' ), $labels[ $key ] ),
				);
			}
		}

		if ( empty( $goals ) ) {
			return;
		}
		?>
		<ul class="cascr-goals">
			<?php foreach ( $goals as $goal ) : ?>
				<li class="cascr-goal">
					<span class="cascr-goal__label"><?php echo esc_html( $goal[0] ); ?></span>
					<span class="cascr-goal__text"><?php echo esc_html( $goal[1] ); ?></span>
				</li>
			<?php endforeach; ?>
		</ul>
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
	 * One bar per recorded run, with its grade above and its date below.
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

		?>
		<section class="cascr-curve">
			<h2 class="cascr-section__title"><?php esc_html_e( 'Your progress', 'security-check-report' ); ?></h2>
			<p class="cascr-section__lead"><?php esc_html_e( 'One bar per full run, the latest on the left. The taller the bar, the lower the risk.', 'security-check-report' ); ?></p>

			<ol class="cascr-curve__list">
				<?php
				foreach ( array_reverse( $points ) as $point ) {
					$risk  = isset( $point['r'] ) ? (float) $point['r'] : 0.0;
					$grade = isset( $point['g'] ) && '' !== $point['g'] ? $point['g'] : 'F';
					$time  = (int) $point['t'];

					// A run with everything wrong still gets a stub, so the
					// worst point on the chart is a bar and not a gap.
					$height = max( 4, (int) round( 100 - $risk ) );
					$full   = sprintf(
						/* translators: 1: date of the run, 2: grade letter. */
						__( '%1$s: grade %2$s', 'security-check-report' ),
						wp_date( get_option( 'date_format' ), $time ),
						$grade
					);
					?>
					<li class="cascr-curve__run" title="<?php echo esc_attr( $full ); ?>">
						<span class="screen-reader-text"><?php echo esc_html( $full ); ?></span>
						<span class="cascr-curve__plot" aria-hidden="true">
							<span class="cascr-curve__bar cascr-curve__bar--<?php echo esc_attr( strtolower( $grade ) ); ?>" style="height:<?php echo esc_attr( (string) $height ); ?>%">
								<span class="cascr-curve__grade"><?php echo esc_html( $grade ); ?></span>
							</span>
						</span>
						<span class="cascr-curve__date" aria-hidden="true">
							<?php
							/* translators: short date under each bar of the progress chart, PHP date() format. */
							echo esc_html( wp_date( __( 'M j', 'security-check-report' ), $time ) );
							?>
						</span>
					</li>
					<?php
				}
				?>
			</ol>
		</section>
		<?php
	}

	/**
	 * The short list, as tasks rather than as a report.
	 *
	 * @param array      $priorities Output of CASCR_Scoring::priorities().
	 * @param array|null $next       Output of CASCR_Scoring::next_grade().
	 */
	private static function render_tasks( $priorities, $next = null ) {
		$lifts = null === $next ? array() : $next['ids'];
		?>
		<section class="cascr-tasks" id="cascr-tasks">
			<h2 class="cascr-section__title"><?php esc_html_e( 'Your next five', 'security-check-report' ); ?></h2>
			<p class="cascr-section__lead"><?php esc_html_e( 'Work through these in order. Everything else can wait.', 'security-check-report' ); ?></p>

			<ol class="cascr-tasks__list">
				<?php
				foreach ( $priorities as $task ) {
					self::render_task( $task, in_array( $task['id'], $lifts, true ) );
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
	 * @param array $task  One entry of the priority list.
	 * @param bool  $lifts Whether fixing it is part of the way to the next grade.
	 */
	private static function render_task( $task, $lifts = false ) {
		?>
		<li class="cascr-task cascr-task--<?php echo esc_attr( $task['severity'] ); ?>" data-cascr-task="<?php echo esc_attr( $task['id'] ); ?>">
			<div class="cascr-task__head">
				<span class="cascr-task__label" id="cascr-task-label-<?php echo esc_attr( $task['id'] ); ?>"><?php echo esc_html( $task['label'] ); ?></span>
				<?php // Status next to severity: a critical check can be an open question, not a proven failure. ?>
				<span class="cascr-status cascr-status--<?php echo esc_attr( $task['status'] ); ?>">
					<?php echo esc_html( CASCR_Admin::status_label( $task['status'] ) ); ?>
				</span>
				<span class="cascr-badge cascr-badge--<?php echo esc_attr( $task['severity'] ); ?>">
					<?php echo esc_html( CASCR_Admin::severity_label( $task['severity'] ) ); ?>
				</span>
				<?php if ( $lifts ) : ?>
					<span class="cascr-badge cascr-badge--goal"><?php esc_html_e( 'Raises the grade', 'security-check-report' ); ?></span>
				<?php endif; ?>
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
				<button type="button" class="button button-primary" data-cascr-recheck="<?php echo esc_attr( $task['id'] ); ?>" aria-describedby="cascr-task-label-<?php echo esc_attr( $task['id'] ); ?>">
					<?php esc_html_e( 'Done, check it now', 'security-check-report' ); ?>
				</button>
				<button type="button" class="button button-link cascr-task__later" data-cascr-later="<?php echo esc_attr( $task['id'] ); ?>" aria-describedby="cascr-task-label-<?php echo esc_attr( $task['id'] ); ?>">
					<?php esc_html_e( 'later', 'security-check-report' ); ?>
				</button>
				<a class="cascr-result__link" href="#cascr-doc-<?php echo esc_attr( $task['id'] ); ?>" data-cascr-doc="<?php echo esc_attr( $task['id'] ); ?>" aria-describedby="cascr-task-label-<?php echo esc_attr( $task['id'] ); ?>">
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
	 * Milestones reached, with their date, and the ones still ahead.
	 *
	 * The open ones carry how far along the site is, so they read as a goal
	 * rather than as something missing.
	 */
	private static function render_milestones() {
		$state   = CASCR_Milestones::get();
		$labels  = CASCR_Milestones::labels();
		$streak  = CASCR_Milestones::streak();
		$reached = array_intersect_key( $state['reached'], $labels );

		if ( empty( $state['months'] ) ) {
			return;
		}

		arsort( $reached );
		?>
		<details class="cascr-archive cascr-milestones">
			<summary class="cascr-archive__summary">
				<?php
				printf(
					/* translators: 1: milestones reached, 2: milestones in total. */
					esc_html__( 'Milestones (%1$d of %2$d)', 'security-check-report' ),
					count( $reached ),
					count( $labels )
				);
				?>
			</summary>

			<ul class="cascr-archive__list">
				<?php foreach ( $reached as $key => $time ) : ?>
					<li class="cascr-archive__item">
						<span class="cascr-archive__label"><?php echo esc_html( $labels[ $key ] ); ?></span>
						<span class="cascr-archive__date"><?php echo esc_html( wp_date( get_option( 'date_format' ), (int) $time ) ); ?></span>
					</li>
				<?php endforeach; ?>

				<?php foreach ( array_diff_key( $labels, $reached ) as $key => $label ) : ?>
					<?php
					$goal = (int) substr( $key, strrpos( $key, '_' ) + 1 );
					$have = null;
					if ( 0 === strpos( $key, 'resolved_' ) ) {
						$have = $state['resolved'];
					} elseif ( 0 === strpos( $key, 'streak_' ) ) {
						$have = $streak;
					}
					?>
					<li class="cascr-archive__item cascr-milestones__open">
						<span class="cascr-archive__label"><?php echo esc_html( $label ); ?></span>
						<span class="cascr-archive__mark">
							<?php
							if ( null === $have ) {
								esc_html_e( 'not yet', 'security-check-report' );
							} else {
								/* translators: 1: progress so far, 2: goal. */
								echo esc_html( sprintf( __( '%1$d of %2$d', 'security-check-report' ), min( $have, $goal ), $goal ) );
							}
							?>
						</span>
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
