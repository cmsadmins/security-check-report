<?php
/**
 * The reminders that bring somebody back to the report.
 *
 * @package CmsAdmins\SecurityCheck
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Menu bubble, dashboard widget and the notice after a month without a run.
 *
 * A report nobody returns to is worth nothing. These three reminders live
 * outside the plugin screen on purpose, because that is where the site owner
 * actually is. None of them shows up before the first run: a site that has
 * never been checked has nothing to be reminded of yet.
 */
class CASCR_Nudges {

	/**
	 * Where a single user records that they have seen enough of the notice.
	 */
	const META_DISMISSED = 'cascr_nudge';

	/**
	 * Action name shared by the dismiss link and its admin-post handler.
	 */
	const DISMISS_ACTION = 'cascr_dismiss_nudge';

	/**
	 * Identifier of the dashboard widget.
	 */
	const WIDGET_ID = 'cascr_dashboard_widget';

	/**
	 * After this long without a full run the report is treated as stale.
	 */
	const STALE_AFTER = 30 * DAY_IN_SECONDS;

	/**
	 * Hangs the reminders on their hooks.
	 */
	public static function register() {
		add_action( 'wp_dashboard_setup', array( __CLASS__, 'add_widget' ) );
		add_action( 'admin_notices', array( __CLASS__, 'stale_notice' ) );
		add_action( 'admin_post_' . self::DISMISS_ACTION, array( __CLASS__, 'dismiss' ) );
	}

	/**
	 * The menu title, with a count bubble while findings are open.
	 *
	 * Only failures are counted. Counting warnings as well would leave the
	 * bubble lit on nearly every site forever, and a badge that never goes out
	 * is one nobody reads.
	 *
	 * @param string $title Untouched menu title.
	 * @return string Title, followed by the bubble markup when there is something to report.
	 */
	public static function menu_title( $title ) {
		// Read from the small option rather than the stored run: this runs on
		// every admin page, and the run is tens of kilobytes. Before the first
		// write after an update the option is missing and the bubble stays off,
		// which is the right way to be wrong here.
		$count = CASCR_Store::badge();

		if ( $count < 1 ) {
			return $title;
		}

		$number = number_format_i18n( $count );

		$label = sprintf(
			/* translators: %s: number of failed checks. */
			_n( '%s failed check', '%s failed checks', $count, 'security-check-report' ),
			$number
		);

		return sprintf(
			'%1$s <span class="update-plugins count-%2$d"><span class="update-count" aria-hidden="true">%3$s</span><span class="screen-reader-text">%4$s</span></span>',
			$title,
			$count,
			esc_html( $number ),
			esc_html( $label )
		);
	}

	/**
	 * Registers the dashboard widget for everyone allowed to act on it.
	 */
	public static function add_widget() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		wp_add_dashboard_widget(
			self::WIDGET_ID,
			__( 'Security Check', 'security-check-report' ),
			array( __CLASS__, 'render_widget' )
		);
	}

	/**
	 * Grade, open tasks and the age of the last full run.
	 */
	public static function render_widget() {
		$run = CASCR_Store::last_run();

		if ( empty( $run['tests'] ) ) {
			printf(
				'<p>%s</p>',
				esc_html__( 'This site has not been checked yet.', 'security-check-report' )
			);
			printf(
				'<p><a class="button button-primary" href="%1$s">%2$s</a></p>',
				esc_url( self::page_url() ),
				esc_html__( 'Run the first check', 'security-check-report' )
			);

			return;
		}

		$grade = isset( $run['grade'] ) ? (string) $run['grade'] : '';
		$open  = self::open_tasks( $run );

		printf(
			'<p class="cascr-widget-grade"><strong>%1$s</strong> %2$s</p>',
			esc_html( $grade ),
			esc_html( CASCR_Scoring::grade_label( $grade ) )
		);

		printf(
			'<p>%s</p>',
			esc_html(
				sprintf(
					/* translators: %d: number of findings still open. */
					_n( '%d open task', '%d open tasks', $open, 'security-check-report' ),
					$open
				)
			)
		);

		$generated = isset( $run['generated'] ) ? (int) $run['generated'] : 0;

		if ( $generated > 0 ) {
			printf(
				'<p>%s</p>',
				esc_html(
					sprintf(
						/* translators: %s: length of time, for example "2 weeks". */
						__( 'Last full check %s ago.', 'security-check-report' ),
						human_time_diff( $generated, time() )
					)
				)
			);
		}

		printf(
			'<p><a href="%1$s">%2$s</a></p>',
			esc_url( self::page_url() ),
			esc_html__( 'Open the report', 'security-check-report' )
		);
	}

	/**
	 * The reminder after a month without a full run.
	 *
	 * Limited to the screens somebody passes through anyway. On the report page
	 * itself it would be pointless, and on every other screen it would be noise.
	 */
	public static function stale_notice() {
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;

		if ( ! $screen || ! in_array( $screen->id, array( 'dashboard', 'plugins', 'update-core' ), true ) ) {
			return;
		}

		if ( ! self::is_due() ) {
			return;
		}

		$run = CASCR_Store::last_run();

		printf(
			'<div class="notice notice-info is-dismissible"><p>%1$s</p><p><a href="%2$s">%3$s</a> <a href="%4$s">%5$s</a></p></div>',
			esc_html(
				sprintf(
					/* translators: %s: length of time, for example "2 months". */
					__( 'The last full security check on this site ran %s ago.', 'security-check-report' ),
					human_time_diff( (int) $run['generated'], time() )
				)
			),
			esc_url( self::page_url() ),
			esc_html__( 'Open the report', 'security-check-report' ),
			esc_url( self::dismiss_url() ),
			esc_html__( 'Stop reminding me', 'security-check-report' )
		);
	}

	/**
	 * Whether this user should see the stale notice at all.
	 *
	 * Kept apart from the screen check so the decision can be read without an
	 * admin screen in place.
	 *
	 * @return bool
	 */
	public static function is_due() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return false;
		}

		$run = CASCR_Store::last_run();

		if ( empty( $run['generated'] ) ) {
			return false;
		}

		if ( time() - (int) $run['generated'] < self::STALE_AFTER ) {
			return false;
		}

		return ! get_user_meta( get_current_user_id(), self::META_DISMISSED, true );
	}

	/**
	 * Records that this user wants the notice gone for good.
	 */
	public static function dismiss() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die(
				esc_html__( 'You are not allowed to do that.', 'security-check-report' ),
				'',
				array( 'response' => 403 )
			);
		}

		check_admin_referer( self::DISMISS_ACTION );

		update_user_meta( get_current_user_id(), self::META_DISMISSED, time() );

		$referer = wp_get_referer();

		wp_safe_redirect( $referer ? $referer : admin_url() );
		exit;
	}

	/**
	 * How many findings are waiting to be worked on.
	 *
	 * Warnings count here, unlike in the bubble: the checklist offers them as
	 * tasks, so the widget would contradict the page if it left them out.
	 *
	 * @param array $run A stored run.
	 * @return int
	 */
	private static function open_tasks( $run ) {
		$fail = isset( $run['counts']['fail'] ) ? (int) $run['counts']['fail'] : 0;
		$warn = isset( $run['counts']['warn'] ) ? (int) $run['counts']['warn'] : 0;

		return $fail + $warn;
	}

	/**
	 * Link to the report page.
	 *
	 * @return string
	 */
	private static function page_url() {
		return admin_url( 'admin.php?page=' . CASCR_Admin::SLUG );
	}

	/**
	 * Nonce protected link that switches the notice off for this user.
	 *
	 * @return string
	 */
	private static function dismiss_url() {
		return wp_nonce_url(
			admin_url( 'admin-post.php?action=' . self::DISMISS_ACTION ),
			self::DISMISS_ACTION
		);
	}
}
