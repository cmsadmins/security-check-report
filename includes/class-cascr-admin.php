<?php
/**
 * The admin screen.
 *
 * @package CmsAdmins\SecurityCheck
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Menu entry, assets and markup for the report page.
 */
class CASCR_Admin {

	const SLUG      = 'security-check-report';
	const SCREEN_ID = 'toplevel_page_security-check-report';

	/**
	 * Registers the top level menu entry.
	 */
	public static function register_menu() {
		$title = CASCR_Nudges::menu_title( __( 'Security Check', 'security-check-report' ) );

		add_menu_page(
			__( 'Security Check Report', 'security-check-report' ),
			$title,
			'manage_options',
			self::SLUG,
			array( __CLASS__, 'render' ),
			'dashicons-shield',
			100
		);
	}

	/**
	 * Loads the stylesheet and the script on our screen only.
	 *
	 * @param string $hook Current admin page hook.
	 */
	public static function enqueue( $hook ) {
		if ( self::SCREEN_ID !== $hook ) {
			return;
		}

		wp_enqueue_script(
			'cascr-admin',
			CASCR_URL . 'assets/js/admin.js',
			array( 'wp-a11y' ),
			CASCR_VERSION,
			true
		);

		wp_enqueue_style(
			'cascr-admin',
			CASCR_URL . 'assets/css/admin.css',
			array(),
			CASCR_VERSION
		);

		wp_localize_script( 'cascr-admin', 'cascr', self::script_data() );
	}

	/**
	 * Everything the script needs, including every string it renders.
	 *
	 * The page itself is rendered in PHP. What is left here is what the browser
	 * builds on its own: the progress of a run, the card it swaps after a
	 * re-check and the three exports.
	 *
	 * @return array
	 */
	private static function script_data() {
		$run = CASCR_Store::last_run();

		return array(
			'root'        => esc_url_raw( rest_url( CASCR_REST::NAMESPACE_V1 ) ),
			'nonce'       => wp_create_nonce( 'wp_rest' ),
			'concurrency' => 3,
			'siteName'    => wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ),
			'siteUrl'     => home_url( '/' ),
			'tests'       => CASCR_Registry::for_client(),
			'categories'  => CASCR_Registry::categories(),
			// The exports read the run itself over the REST route, but the
			// to-do list is scored in PHP, so it travels with the page and is
			// replaced by whatever a re-check answers.
			'priorities'  => empty( $run['tests'] ) ? array() : CASCR_Scoring::priorities( $run['tests'] ),
			'grades'      => array(
				'A' => CASCR_Scoring::grade_label( 'A' ),
				'B' => CASCR_Scoring::grade_label( 'B' ),
				'C' => CASCR_Scoring::grade_label( 'C' ),
				'D' => CASCR_Scoring::grade_label( 'D' ),
				'F' => CASCR_Scoring::grade_label( 'F' ),
			),
			'severities'  => array(
				CASCR_Registry::SEVERITY_CRITICAL => self::severity_label( CASCR_Registry::SEVERITY_CRITICAL ),
				CASCR_Registry::SEVERITY_HIGH     => self::severity_label( CASCR_Registry::SEVERITY_HIGH ),
				CASCR_Registry::SEVERITY_MEDIUM   => self::severity_label( CASCR_Registry::SEVERITY_MEDIUM ),
				CASCR_Registry::SEVERITY_LOW      => self::severity_label( CASCR_Registry::SEVERITY_LOW ),
			),
			'i18n'        => array(
				/* translators: 1: number of the check being run, 2: total number of checks. */
				'progress'       => __( 'Check %1$d of %2$d', 'security-check-report' ),
				'error'          => __( 'This check could not be completed.', 'security-check-report' ),
				'statusPass'     => __( 'Passed', 'security-check-report' ),
				'statusWarn'     => __( 'Warning', 'security-check-report' ),
				'statusFail'     => __( 'Failed', 'security-check-report' ),
				'statusUnknown'  => __( 'Not determined', 'security-check-report' ),
				'riskScore'      => __( 'Risk score', 'security-check-report' ),
				'nextActions'    => __( 'Your to-do list', 'security-check-report' ),
				'recommendation' => __( 'What to do', 'security-check-report' ),
				'documentation'  => __( 'Read more about this check', 'security-check-report' ),
				'mute'           => __( 'Mute this finding', 'security-check-report' ),
				'unmute'         => __( 'Unmute', 'security-check-report' ),
				'muted'          => __( 'Muted until the finding changes.', 'security-check-report' ),
				'unmuted'        => __( 'The finding is shown again.', 'security-check-report' ),
				'copied'         => __( 'The report was copied to the clipboard.', 'security-check-report' ),
				'copyFailed'     => __( 'The report could not be copied.', 'security-check-report' ),
				'reportTitle'    => __( 'Security Check Report', 'security-check-report' ),
				'generatedOn'    => __( 'Generated', 'security-check-report' ),
				'grade'          => __( 'Grade', 'security-check-report' ),
				'summary'        => __( 'Summary', 'security-check-report' ),
				'checks'         => __( 'Checks', 'security-check-report' ),
				// Kept as separate strings rather than one comma separated line,
				// so a comma in a translation cannot corrupt the CSV.
				'csvColumns'     => array(
					__( 'Check', 'security-check-report' ),
					__( 'Category', 'security-check-report' ),
					__( 'Severity', 'security-check-report' ),
					__( 'Status', 'security-check-report' ),
					__( 'Score', 'security-check-report' ),
					__( 'Result', 'security-check-report' ),
				),
				/* translators: %d: number of findings that are not on the short list. */
				'stillOpen'      => __( 'Still open (%d)', 'security-check-report' ),
				'taskDone'       => __( 'Done, check it now', 'security-check-report' ),
				'taskLater'      => __( 'later', 'security-check-report' ),
				'taskChecking'   => __( 'Checking again', 'security-check-report' ),
				'taskResolved'   => __( 'Resolved', 'security-check-report' ),
				'taskRemains'    => __( 'Still open after the re-check.', 'security-check-report' ),
				'nothingLeft'    => __( 'Nothing is left on the list. Run all checks again whenever you have changed something.', 'security-check-report' ),
				'scanFinished'   => __( 'The security check finished.', 'security-check-report' ),
			),
		);
	}

	/**
	 * Renders the page.
	 *
	 * One screen, two views. Without a stored run there is nothing to show but
	 * the way in; with one the checklist takes over.
	 */
	public static function render() {
		$run = CASCR_Store::last_run();
		?>
		<div class="wrap cascr" id="cascr-app">

			<header class="cascr-header">
				<h1><?php esc_html_e( 'Security Check Report', 'security-check-report' ); ?></h1>
				<p class="cascr-header__subtitle">
					<?php
					printf(
						/* translators: %d: number of checks the plugin runs. */
						esc_html( _n( '%d check across your WordPress installation.', '%d checks across your WordPress installation.', count( CASCR_Registry::ids() ), 'security-check-report' ) ),
						count( CASCR_Registry::ids() )
					);
					?>
				</p>
			</header>

			<?php
			if ( empty( $run['tests'] ) ) {
				self::render_onboarding();
			} else {
				CASCR_Admin_Dashboard::render( $run );
			}
			?>

			<section class="cascr-docs">
				<div class="cascr-docs__header">
					<h2><?php esc_html_e( 'What each check looks at', 'security-check-report' ); ?></h2>
				</div>

				<div class="cascr-search">
					<label class="screen-reader-text" for="cascr-doc-search"><?php esc_html_e( 'Search the checks', 'security-check-report' ); ?></label>
					<input
						type="search"
						id="cascr-doc-search"
						class="cascr-search__input"
						placeholder="<?php esc_attr_e( 'Search the checks', 'security-check-report' ); ?>"
						autocomplete="off"
					/>
					<span class="cascr-search__count" id="cascr-doc-count"><?php echo esc_html( (string) count( CASCR_Registry::ids() ) ); ?></span>
				</div>

				<p class="cascr-docs__empty" id="cascr-doc-empty" hidden><?php esc_html_e( 'No check matches that search.', 'security-check-report' ); ?></p>

				<?php self::render_documentation(); ?>
			</section>

			<footer class="cascr-footer">
				<a class="cascr-footer__brand" href="https://www.cms-admins.de/" target="_blank" rel="noopener noreferrer">CMS ADMINS</a>
				<span class="cascr-footer__sep">&middot;</span>
				<a href="https://www.cms-admins.de/wordpress-sicherheit/" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'WordPress security', 'security-check-report' ); ?></a>
				<span class="cascr-footer__sep">&middot;</span>
				<a href="https://www.cms-admins.de/docs/" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Documentation', 'security-check-report' ); ?></a>
				<span class="cascr-footer__sep">&middot;</span>
				<a href="https://github.com/cmsadmins/security-check-report/issues" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Report a false positive', 'security-check-report' ); ?></a>
				<span class="cascr-footer__sep">&middot;</span>
				<a href="https://wordpress.org/support/plugin/security-check-report/" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Support', 'security-check-report' ); ?></a>
			</footer>
		</div>
		<?php
	}

	/**
	 * The three steps somebody sees before their first run.
	 */
	private static function render_onboarding() {
		?>
		<ol class="cascr-steps">

			<li class="cascr-step is-current" id="cascr-step-1">
				<div class="cascr-step__head">
					<span class="cascr-step__num" aria-hidden="true">1</span>
					<div>
						<h2 class="cascr-step__title">
							<span class="screen-reader-text"><?php esc_html_e( 'Step 1:', 'security-check-report' ); ?></span>
							<?php esc_html_e( 'Start the check', 'security-check-report' ); ?>
						</h2>
						<p class="cascr-step__lead">
							<?php
							printf(
								/* translators: %d: number of checks the plugin runs. */
								esc_html__( '%d checks, about a minute. Nothing on your site is changed.', 'security-check-report' ),
								count( CASCR_Registry::ids() )
							);
							?>
						</p>
					</div>
				</div>

				<div class="cascr-step__body">
					<?php
					self::render_consent();
					self::render_launch( __( 'Start the security check', 'security-check-report' ) );
					self::render_progress();
					?>
				</div>
			</li>

			<li class="cascr-step is-upcoming" id="cascr-step-2">
				<div class="cascr-step__head">
					<span class="cascr-step__num" aria-hidden="true">2</span>
					<div>
						<h2 class="cascr-step__title">
							<span class="screen-reader-text"><?php esc_html_e( 'Step 2:', 'security-check-report' ); ?></span>
							<?php esc_html_e( 'Your result', 'security-check-report' ); ?>
						</h2>
						<p class="cascr-step__lead"><?php esc_html_e( 'A grade, what it means, and the short list to work through.', 'security-check-report' ); ?></p>
					</div>
				</div>

				<div class="cascr-step__body">
					<p class="cascr-waiting"><?php esc_html_e( 'Appears once the check has run.', 'security-check-report' ); ?></p>
				</div>
			</li>

			<li class="cascr-step is-upcoming" id="cascr-step-3">
				<div class="cascr-step__head">
					<span class="cascr-step__num" aria-hidden="true">3</span>
					<div>
						<h2 class="cascr-step__title">
							<span class="screen-reader-text"><?php esc_html_e( 'Step 3:', 'security-check-report' ); ?></span>
							<?php esc_html_e( 'Go through everything else', 'security-check-report' ); ?>
						</h2>
						<p class="cascr-step__lead"><?php esc_html_e( 'Every check with its detail, filterable, and the report to take away.', 'security-check-report' ); ?></p>
					</div>
				</div>

				<div class="cascr-step__body">
					<p class="cascr-waiting"><?php esc_html_e( 'Appears once the check has run.', 'security-check-report' ); ?></p>
				</div>
			</li>

		</ol>
		<?php
	}

	/**
	 * What the checks do to the site, asked once and said every time.
	 *
	 * The sentence stays on the page after the agreement has been given. Only
	 * the checkbox goes away, because asking the same question on every visit
	 * is not consent, it is a toll gate.
	 */
	public static function render_consent() {
		$text = __( 'These checks read the site, write one temporary file to the uploads folder and delete it again. The result is an assessment rather than a guarantee.', 'security-check-report' );

		if ( CASCR_Store::consent() ) {
			?>
			<p class="cascr-consent-note"><?php echo esc_html( $text ); ?></p>
			<?php
			return;
		}
		?>
		<label class="cascr-consent" for="cascr-consent">
			<input type="checkbox" id="cascr-consent" />
			<span><?php echo esc_html( $text ); ?> <?php esc_html_e( 'I understand.', 'security-check-report' ); ?></span>
		</label>
		<?php
	}

	/**
	 * The button that starts a full pass.
	 *
	 * @param string $label Button caption.
	 */
	public static function render_launch( $label ) {
		$ready = CASCR_Store::consent();
		?>
		<div class="cascr-launch">
			<button type="button" id="cascr-run" class="button button-primary button-hero cascr-launch__button" <?php disabled( ! $ready ); ?>>
				<?php echo esc_html( $label ); ?>
			</button>
			<p class="cascr-launch__hint" id="cascr-launch-hint" <?php echo $ready ? 'hidden' : ''; ?>>
				<?php esc_html_e( 'Tick the box above to start.', 'security-check-report' ); ?>
			</p>
		</div>
		<?php
	}

	/**
	 * The bar the run fills while it works.
	 */
	public static function render_progress() {
		?>
		<div class="cascr-progress" id="cascr-progress" hidden>
			<div class="cascr-progress__row">
				<span class="cascr-progress__spinner" aria-hidden="true"></span>
				<span class="cascr-progress__label" id="cascr-progress-label"></span>
			</div>
			<div class="cascr-progress__track">
				<div class="cascr-progress__bar" id="cascr-progress-bar"></div>
			</div>
		</div>
		<?php
	}

	/**
	 * Every check of the stored run, grouped and filterable.
	 *
	 * @param array $run The stored run.
	 */
	public static function render_results( $run ) {
		$tests      = CASCR_Registry::all();
		$categories = CASCR_Registry::categories();
		$counts     = array(
			'all'          => 0,
			'fail'         => 0,
			'warn'         => 0,
			'pass'         => 0,
			'inconclusive' => 0,
			'ignored'      => 0,
		);

		foreach ( $run['tests'] as $id => $test ) {
			if ( ! isset( $tests[ $id ] ) ) {
				continue;
			}

			++$counts['all'];

			$key = empty( $test['ignored'] ) ? $test['status'] : 'ignored';

			if ( isset( $counts[ $key ] ) ) {
				++$counts[ $key ];
			}
		}

		$filters = array(
			'all'          => __( 'All', 'security-check-report' ),
			'fail'         => __( 'Failed', 'security-check-report' ),
			'warn'         => __( 'Warning', 'security-check-report' ),
			'pass'         => __( 'Passed', 'security-check-report' ),
			'inconclusive' => __( 'Not determined', 'security-check-report' ),
			'ignored'      => __( 'Muted', 'security-check-report' ),
		);
		?>
		<section class="cascr-results" id="cascr-results">
			<h2 class="cascr-section__title"><?php esc_html_e( 'All checks', 'security-check-report' ); ?></h2>

			<div class="cascr-filters" id="cascr-filters">
				<?php
				// Empty chips stay in the document rather than being left out:
				// muting a finding has to be able to reveal one without the
				// browser rebuilding the bar.
				foreach ( $filters as $value => $label ) {
					?>
					<button
						type="button"
						class="cascr-filter<?php echo 'all' === $value ? ' is-active' : ''; ?>"
						data-cascr-filter="<?php echo esc_attr( $value ); ?>"
						data-cascr-label="<?php echo esc_attr( $label ); ?>"
						aria-pressed="<?php echo 'all' === $value ? 'true' : 'false'; ?>"
						<?php echo 'all' !== $value && 0 === $counts[ $value ] ? 'hidden' : ''; ?>
					><?php echo esc_html( sprintf( '%1$s (%2$d)', $label, $counts[ $value ] ) ); ?></button>
					<?php
				}
				?>
			</div>

			<div class="cascr-results__list">
				<?php
				foreach ( $categories as $category => $title ) {
					$ids = array();

					foreach ( $run['tests'] as $id => $test ) {
						if ( isset( $tests[ $id ] ) && $tests[ $id ]['category'] === $category ) {
							$ids[] = $id;
						}
					}

					if ( empty( $ids ) ) {
						continue;
					}
					?>
					<div class="cascr-results__group" data-cascr-group="<?php echo esc_attr( $category ); ?>">
						<h3 class="cascr-results__group-title"><?php echo esc_html( $title ); ?></h3>
						<?php
						foreach ( $ids as $id ) {
							self::render_result_row( $id, $tests[ $id ], $run['tests'][ $id ] );
						}
						?>
					</div>
					<?php
				}
				?>
			</div>

			<p class="cascr-empty" id="cascr-results-empty" hidden><?php esc_html_e( 'No check matches that filter.', 'security-check-report' ); ?></p>
		</section>
		<?php
	}

	/**
	 * One row of the full list.
	 *
	 * The detail containers are printed even when they are empty, so a re-check
	 * can fill them without the browser having to know the markup.
	 *
	 * @param string $id   Test identifier.
	 * @param array  $test Registry entry.
	 * @param array  $data Stored result.
	 */
	private static function render_result_row( $id, $test, $data ) {
		$muted  = ! empty( $data['ignored'] );
		$status = $muted ? 'ignored' : $data['status'];
		$items  = isset( $data['items'] ) && is_array( $data['items'] ) ? $data['items'] : array();
		$fix    = isset( $data['fix'] ) ? $data['fix'] : '';
		$link   = isset( $data['link'] ) && ! empty( $data['link']['url'] ) ? $data['link'] : array();
		?>
		<details
			class="cascr-result cascr-result--<?php echo esc_attr( $status ); ?>"
			id="cascr-result-<?php echo esc_attr( $id ); ?>"
			data-cascr-row="<?php echo esc_attr( $id ); ?>"
			data-cascr-status="<?php echo esc_attr( $status ); ?>"
			data-cascr-real="<?php echo esc_attr( $data['status'] ); ?>"
		>
			<summary class="cascr-result__summary">
				<span class="cascr-status cascr-status--<?php echo esc_attr( $status ); ?>" data-cascr-status-label>
					<?php echo esc_html( self::status_label( $data['status'] ) ); ?>
				</span>
				<span class="cascr-result__label"><?php echo esc_html( $test['label'] ); ?></span>
				<span class="cascr-result__text" data-cascr-summary><?php echo esc_html( $data['summary'] ); ?></span>
			</summary>

			<div class="cascr-result__body">
				<h4 class="cascr-result__heading" data-cascr-items-heading <?php echo empty( $items ) ? 'hidden' : ''; ?>>
					<?php esc_html_e( 'Details', 'security-check-report' ); ?>
				</h4>
				<ul class="cascr-result__items" data-cascr-items <?php echo empty( $items ) ? 'hidden' : ''; ?>>
					<?php foreach ( $items as $item ) : ?>
						<li><?php echo esc_html( $item ); ?></li>
					<?php endforeach; ?>
				</ul>

				<h4 class="cascr-result__heading" data-cascr-fix-heading <?php echo '' === $fix ? 'hidden' : ''; ?>>
					<?php esc_html_e( 'What to do', 'security-check-report' ); ?>
				</h4>
				<p class="cascr-result__fix" data-cascr-fix <?php echo '' === $fix ? 'hidden' : ''; ?>><?php echo esc_html( $fix ); ?></p>

				<?php if ( ! empty( $link ) ) : ?>
					<a class="cascr-result__helper" href="<?php echo esc_url( $link['url'] ); ?>" target="_blank" rel="noopener noreferrer">
						<?php echo esc_html( $link['label'] ); ?>
					</a>
				<?php endif; ?>

				<div class="cascr-result__actions">
					<a class="cascr-result__link" href="#cascr-doc-<?php echo esc_attr( $id ); ?>" data-cascr-doc="<?php echo esc_attr( $id ); ?>">
						<?php esc_html_e( 'Read more about this check', 'security-check-report' ); ?>
					</a>
					<button type="button" class="button button-link cascr-result__mute" data-cascr-mute="<?php echo esc_attr( $id ); ?>">
						<?php echo $muted ? esc_html__( 'Unmute', 'security-check-report' ) : esc_html__( 'Mute this finding', 'security-check-report' ); ?>
					</button>
					<span class="cascr-result__muted-note" data-cascr-muted-note <?php echo $muted ? '' : 'hidden'; ?>>
						<?php esc_html_e( 'Muted until the finding changes.', 'security-check-report' ); ?>
					</span>
				</div>
			</div>
		</details>
		<?php
	}

	/**
	 * The buttons that take the report off the screen.
	 */
	public static function render_export() {
		$buttons = array(
			'text' => __( 'Download as text', 'security-check-report' ),
			'json' => __( 'Download as JSON', 'security-check-report' ),
			'csv'  => __( 'Download as CSV', 'security-check-report' ),
			'copy' => __( 'Copy report', 'security-check-report' ),
		);
		?>
		<section class="cascr-export-section" id="cascr-export">
			<h2 class="cascr-section__title"><?php esc_html_e( 'Take the report with you', 'security-check-report' ); ?></h2>
			<div class="cascr-export__row">
				<?php foreach ( $buttons as $format => $label ) : ?>
					<button type="button" class="button" data-cascr-export="<?php echo esc_attr( $format ); ?>">
						<?php echo esc_html( $label ); ?>
					</button>
				<?php endforeach; ?>
			</div>
		</section>
		<?php
	}

	/**
	 * Renders the documentation, grouped the same way the results are.
	 */
	private static function render_documentation() {
		$tests      = CASCR_Registry::all();
		$categories = CASCR_Registry::categories();

		foreach ( $categories as $category => $title ) {
			$in_category = array_filter(
				$tests,
				function ( $test ) use ( $category ) {
					return $test['category'] === $category;
				}
			);

			if ( empty( $in_category ) ) {
				continue;
			}
			?>
			<div class="cascr-docs__group" data-category="<?php echo esc_attr( $category ); ?>">
				<h3 class="cascr-docs__group-title"><?php echo esc_html( $title ); ?></h3>
				<?php foreach ( $in_category as $id => $test ) : ?>
					<details class="cascr-doc" id="cascr-doc-<?php echo esc_attr( $id ); ?>"
						data-search="<?php echo esc_attr( strtolower( $test['label'] . ' ' . wp_strip_all_tags( CASCR_Registry::doc( $id ) ) ) ); ?>">
						<summary class="cascr-doc__summary">
							<span class="cascr-doc__title"><?php echo esc_html( $test['label'] ); ?></span>
							<span class="cascr-badge cascr-badge--<?php echo esc_attr( $test['severity'] ); ?>">
								<?php echo esc_html( self::severity_label( $test['severity'] ) ); ?>
							</span>
						</summary>
						<div class="cascr-doc__body"><?php echo wp_kses_post( CASCR_Registry::doc( $id ) ); ?></div>
					</details>
				<?php endforeach; ?>
			</div>
			<?php
		}
	}

	/**
	 * Translated label for a severity level.
	 *
	 * @param string $severity Severity slug.
	 * @return string
	 */
	public static function severity_label( $severity ) {
		$labels = array(
			CASCR_Registry::SEVERITY_CRITICAL => __( 'Critical', 'security-check-report' ),
			CASCR_Registry::SEVERITY_HIGH     => __( 'High', 'security-check-report' ),
			CASCR_Registry::SEVERITY_MEDIUM   => __( 'Medium', 'security-check-report' ),
			CASCR_Registry::SEVERITY_LOW      => __( 'Low', 'security-check-report' ),
		);

		return isset( $labels[ $severity ] ) ? $labels[ $severity ] : $severity;
	}

	/**
	 * Translated label for a result status.
	 *
	 * @param string $status One of the CASCR_Result STATUS_* values.
	 * @return string
	 */
	public static function status_label( $status ) {
		$labels = array(
			CASCR_Result::STATUS_PASS         => __( 'Passed', 'security-check-report' ),
			CASCR_Result::STATUS_WARN         => __( 'Warning', 'security-check-report' ),
			CASCR_Result::STATUS_FAIL         => __( 'Failed', 'security-check-report' ),
			CASCR_Result::STATUS_INCONCLUSIVE => __( 'Not determined', 'security-check-report' ),
		);

		return isset( $labels[ $status ] ) ? $labels[ $status ] : $status;
	}
}
