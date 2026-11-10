<?php
/**
 * The stored report as a WordPress ability.
 *
 * @package CmsAdmins\SecurityCheck
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Makes the last run readable for AI clients and other tools through the
 * Abilities API that ships with WordPress 7.0.
 *
 * The ability only reads. It never starts a scan, the same rule Site Health
 * follows. It also leaves out the items of every finding: those are user
 * names, paths and plugin names, and a tool asking for the grade has no need
 * to see who the dormant administrators are.
 */
class CASCR_Abilities {

	/**
	 * Category slug, shared with the ability name.
	 */
	const CATEGORY = 'security-check-report';

	/**
	 * Full name of the reading ability.
	 */
	const GET_REPORT = 'security-check-report/get-report';

	/**
	 * Hangs the registration on the Abilities API hooks.
	 */
	public static function register() {
		add_action( 'wp_abilities_api_categories_init', array( __CLASS__, 'register_category' ) );
		add_action( 'wp_abilities_api_init', array( __CLASS__, 'register_abilities' ) );
	}

	/**
	 * Registers the category the ability belongs to.
	 */
	public static function register_category() {
		if ( ! function_exists( 'wp_register_ability_category' ) ) {
			return;
		}

		wp_register_ability_category(
			self::CATEGORY,
			array(
				'label'       => __( 'Security Check Report', 'security-check-report' ),
				'description' => __( 'Read the results of the security check.', 'security-check-report' ),
			)
		);
	}

	/**
	 * Registers the reading ability.
	 */
	public static function register_abilities() {
		if ( ! function_exists( 'wp_register_ability' ) ) {
			return;
		}

		$finding = array(
			'type'       => 'object',
			'properties' => array(
				'id'       => array( 'type' => 'string' ),
				'label'    => array( 'type' => 'string' ),
				'severity' => array( 'type' => 'string' ),
				'status'   => array( 'type' => 'string' ),
				'summary'  => array( 'type' => 'string' ),
				'fix'      => array( 'type' => 'string' ),
			),
		);

		wp_register_ability(
			self::GET_REPORT,
			array(
				'label'               => __( 'Get the security report', 'security-check-report' ),
				'description'         => __( 'Returns the grade of the last full security check, how many checks passed, warned or failed, the five tasks worth doing first and every open finding. Starts no scan and leaves out user names, paths and other raw findings.', 'security-check-report' ),
				'category'            => self::CATEGORY,
				'output_schema'       => array(
					'type'       => 'object',
					'properties' => array(
						'run' => array(
							'type'       => array( 'object', 'null' ),
							'properties' => array(
								'generated'   => array( 'type' => 'string' ),
								'version'     => array( 'type' => 'string' ),
								'grade'       => array( 'type' => 'string' ),
								'grade_label' => array( 'type' => 'string' ),
								'risk'        => array( 'type' => 'number' ),
								'counts'      => array( 'type' => 'object' ),
								'tasks'       => array(
									'type'  => 'array',
									'items' => $finding,
								),
								'open'        => array(
									'type'  => 'array',
									'items' => $finding,
								),
							),
						),
					),
				),
				'execute_callback'    => array( __CLASS__, 'get_report' ),
				'permission_callback' => array( __CLASS__, 'can_read' ),
				'meta'                => array(
					'annotations'  => array(
						'readonly'    => true,
						'destructive' => false,
						'idempotent'  => true,
					),
					'show_in_rest' => true,
				),
			)
		);
	}

	/**
	 * Same rule as the plugin screen and the REST routes.
	 *
	 * @return bool
	 */
	public static function can_read() {
		return current_user_can( 'manage_options' );
	}

	/**
	 * The last stored run without its raw findings.
	 *
	 * @return array Key 'run', null before the first full run.
	 */
	public static function get_report() {
		$run = CASCR_Store::last_run();

		if ( empty( $run ) ) {
			return array( 'run' => null );
		}

		$tasks = array();
		foreach ( CASCR_Scoring::priorities( $run['tests'] ) as $task ) {
			$tasks[] = self::finding( $task['id'], $task );
		}

		$open = array();
		foreach ( $run['tests'] as $id => $test ) {
			if ( empty( $test['ignored'] ) && in_array( $test['status'], array( CASCR_Result::STATUS_FAIL, CASCR_Result::STATUS_WARN ), true ) ) {
				$open[] = self::finding( $id, $test );
			}
		}

		return array(
			'run' => array(
				'generated'   => gmdate( 'c', (int) $run['generated'] ),
				'version'     => (string) $run['version'],
				'grade'       => (string) $run['grade'],
				'grade_label' => CASCR_Scoring::grade_label( $run['grade'] ),
				'risk'        => $run['risk'],
				'counts'      => $run['counts'],
				'tasks'       => $tasks,
				'open'        => $open,
			),
		);
	}

	/**
	 * One finding in the shape the schema promises, items deliberately absent.
	 *
	 * @param string $id     Test identifier.
	 * @param array  $result Stored test or priority entry.
	 * @return array
	 */
	private static function finding( $id, $result ) {
		$test = CASCR_Registry::get( $id );

		return array(
			'id'       => $id,
			'label'    => $test ? $test['label'] : $id,
			'severity' => $test ? $test['severity'] : '',
			'status'   => $result['status'],
			'summary'  => $result['summary'],
			'fix'      => isset( $result['fix'] ) ? (string) $result['fix'] : '',
		);
	}
}
