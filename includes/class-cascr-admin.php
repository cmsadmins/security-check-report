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
		add_menu_page(
			__( 'Security Check Report', 'security-check-report' ),
			__( 'Security Check', 'security-check-report' ),
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
	 * The previous version shipped four translatable strings and hardcoded the
	 * rest of the report in English, with a German date format thrown in.
	 *
	 * @return array
	 */
	private static function script_data() {
		return array(
			'root'        => esc_url_raw( rest_url( CASCR_REST::NAMESPACE_V1 ) ),
			'nonce'       => wp_create_nonce( 'wp_rest' ),
			'concurrency' => 3,
			'siteName'    => wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ),
			'siteUrl'     => home_url( '/' ),
			'tests'       => CASCR_Registry::for_client(),
			'categories'  => CASCR_Registry::categories(),
			'grades'      => array(
				'A' => CASCR_Scoring::grade_label( 'A' ),
				'B' => CASCR_Scoring::grade_label( 'B' ),
				'C' => CASCR_Scoring::grade_label( 'C' ),
				'D' => CASCR_Scoring::grade_label( 'D' ),
				'F' => CASCR_Scoring::grade_label( 'F' ),
			),
			'i18n'        => array(
				/* translators: 1: number of the check being run, 2: total number of checks. */
				'progress'       => __( 'Check %1$d of %2$d', 'security-check-report' ),
				'error'          => __( 'This check could not be completed.', 'security-check-report' ),
				'statusPass'     => __( 'Passed', 'security-check-report' ),
				'statusWarn'     => __( 'Warning', 'security-check-report' ),
				'statusFail'     => __( 'Failed', 'security-check-report' ),
				'statusUnknown'  => __( 'Not determined', 'security-check-report' ),
				'statusIgnored'  => __( 'Muted', 'security-check-report' ),
				'filterAll'      => __( 'All', 'security-check-report' ),
				'riskScore'      => __( 'Risk score', 'security-check-report' ),
				'nextActions'    => __( 'Do this first', 'security-check-report' ),
				'nothingToDo'    => __( 'Nothing needs your attention right now.', 'security-check-report' ),
				'sinceLastRun'   => __( 'Since the previous run', 'security-check-report' ),
				'newIssues'      => __( 'newly failing', 'security-check-report' ),
				'fixedIssues'    => __( 'resolved', 'security-check-report' ),
				'changedIssues'  => __( 'changed', 'security-check-report' ),
				'noChange'       => __( 'Nothing changed since the previous run.', 'security-check-report' ),
				'results'        => __( 'All checks', 'security-check-report' ),
				'details'        => __( 'Details', 'security-check-report' ),
				'recommendation' => __( 'What to do', 'security-check-report' ),
				'documentation'  => __( 'Read more about this check', 'security-check-report' ),
				'mute'           => __( 'Mute this finding', 'security-check-report' ),
				'unmute'         => __( 'Unmute', 'security-check-report' ),
				'muted'          => __( 'Muted until the finding changes.', 'security-check-report' ),
				'unmuted'        => __( 'The finding is shown again.', 'security-check-report' ),
				'exportText'     => __( 'Download as text', 'security-check-report' ),
				'exportJson'     => __( 'Download as JSON', 'security-check-report' ),
				'exportCsv'      => __( 'Download as CSV', 'security-check-report' ),
				'copyReport'     => __( 'Copy report', 'security-check-report' ),
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
				'runAgain'       => __( 'Run again', 'security-check-report' ),
				'scanFinished'   => __( 'The security check finished.', 'security-check-report' ),
			),
		);
	}

	/**
	 * Renders the page.
	 */
	public static function render() {
		$last = CASCR_Store::last_run();
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

			<div class="cascr-start" id="cascr-start">
				<label class="cascr-start__consent">
					<input type="checkbox" id="cascr-consent" />
					<span><?php esc_html_e( 'I understand that these checks read the site, write one temporary file to the uploads folder and delete it again, and that the result is an assessment rather than a guarantee.', 'security-check-report' ); ?></span>
				</label>
				<div class="cascr-start__actions">
					<button type="button" id="cascr-run" class="button button-primary button-hero" disabled>
						<?php esc_html_e( 'Run the security check', 'security-check-report' ); ?>
					</button>
					<?php if ( ! empty( $last['generated'] ) ) : ?>
						<p class="cascr-start__last">
							<?php
							printf(
								/* translators: 1: relative time since the last run, 2: grade letter, 3: grade label. */
								esc_html__( 'Last run %1$s ago: grade %2$s, %3$s.', 'security-check-report' ),
								esc_html( human_time_diff( (int) $last['generated'], time() ) ),
								esc_html( isset( $last['grade'] ) ? $last['grade'] : '?' ),
								esc_html( CASCR_Scoring::grade_label( isset( $last['grade'] ) ? $last['grade'] : 'F' ) )
							);

							if ( isset( $last['counts']['fail'], $last['counts']['warn'] ) ) {
								echo ' ';
								printf(
									/* translators: %d: number of failed checks. */
									esc_html( _n( '%d failed', '%d failed', (int) $last['counts']['fail'], 'security-check-report' ) ),
									(int) $last['counts']['fail']
								);
								echo ', ';
								printf(
									/* translators: %d: number of warnings. */
									esc_html( _n( '%d warning.', '%d warnings.', (int) $last['counts']['warn'], 'security-check-report' ) ),
									(int) $last['counts']['warn']
								);
							}
							?>
						</p>
					<?php endif; ?>
				</div>
			</div>

			<div class="cascr-progress" id="cascr-progress" hidden>
				<div class="cascr-progress__row">
					<span class="cascr-progress__spinner" aria-hidden="true"></span>
					<span class="cascr-progress__label" id="cascr-progress-label"></span>
				</div>
				<div class="cascr-progress__track">
					<div class="cascr-progress__bar" id="cascr-progress-bar"></div>
				</div>
			</div>

			<div class="cascr-report" id="cascr-report" hidden>
				<section class="cascr-score" id="cascr-score" aria-live="polite"></section>
				<section class="cascr-priorities" id="cascr-priorities"></section>
				<section class="cascr-diff" id="cascr-diff"></section>
				<section class="cascr-results" id="cascr-results"></section>
				<section class="cascr-export" id="cascr-export"></section>
			</div>

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
	private static function severity_label( $severity ) {
		$labels = array(
			CASCR_Registry::SEVERITY_CRITICAL => __( 'Critical', 'security-check-report' ),
			CASCR_Registry::SEVERITY_HIGH     => __( 'High', 'security-check-report' ),
			CASCR_Registry::SEVERITY_MEDIUM   => __( 'Medium', 'security-check-report' ),
			CASCR_Registry::SEVERITY_LOW      => __( 'Low', 'security-check-report' ),
		);

		return isset( $labels[ $severity ] ) ? $labels[ $severity ] : $severity;
	}
}
