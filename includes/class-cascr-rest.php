<?php
/**
 * REST routes used by the admin interface.
 *
 * @package CmsAdmins\SecurityCheck
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The cascr/v1 namespace.
 *
 * Replaces the single admin-ajax action. One route per verb, a proper
 * permission callback on each and the nonce in the header rather than the body.
 */
class CASCR_REST {

	const NAMESPACE_V1 = 'cascr/v1';

	/**
	 * Registers every route.
	 */
	public static function register_routes() {
		register_rest_route(
			self::NAMESPACE_V1,
			'/tests',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( __CLASS__, 'get_tests' ),
				'permission_callback' => array( __CLASS__, 'can_manage' ),
			)
		);

		register_rest_route(
			self::NAMESPACE_V1,
			'/run/(?P<id>[a-z0-9_]+)',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( __CLASS__, 'run_test' ),
				'permission_callback' => array( __CLASS__, 'can_manage' ),
				'args'                => array(
					'id' => array(
						'required'          => true,
						'type'              => 'string',
						'validate_callback' => array( 'CASCR_Registry', 'exists' ),
					),
				),
			)
		);

		register_rest_route(
			self::NAMESPACE_V1,
			'/recheck/(?P<id>[a-z0-9_]+)',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( __CLASS__, 'recheck_test' ),
				'permission_callback' => array( __CLASS__, 'can_manage' ),
				'args'                => array(
					'id' => array(
						'required' => true,
						'type'     => 'string',
					),
				),
			)
		);

		register_rest_route(
			self::NAMESPACE_V1,
			'/consent',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( __CLASS__, 'set_consent' ),
				'permission_callback' => array( __CLASS__, 'can_manage' ),
			)
		);

		register_rest_route(
			self::NAMESPACE_V1,
			'/report',
			array(
				array(
					'methods'             => WP_REST_Server::READABLE,
					'callback'            => array( __CLASS__, 'get_report' ),
					'permission_callback' => array( __CLASS__, 'can_manage' ),
				),
				array(
					'methods'             => WP_REST_Server::CREATABLE,
					'callback'            => array( __CLASS__, 'save_report' ),
					'permission_callback' => array( __CLASS__, 'can_manage' ),
					'args'                => array(
						'results' => array(
							'required' => true,
							'type'     => 'object',
						),
					),
				),
			)
		);

		register_rest_route(
			self::NAMESPACE_V1,
			'/ignore',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( __CLASS__, 'set_ignore' ),
				'permission_callback' => array( __CLASS__, 'can_manage' ),
				'args'                => array(
					'id'     => array(
						'required'          => true,
						'type'              => 'string',
						'validate_callback' => array( 'CASCR_Registry', 'exists' ),
					),
					'ignore' => array(
						'type'    => 'boolean',
						'default' => true,
					),
					'mode'   => array(
						'type'    => 'string',
						'enum'    => array( CASCR_Store::IGNORE_UNTIL_CHANGED, CASCR_Store::IGNORE_PERMANENT ),
						'default' => CASCR_Store::IGNORE_UNTIL_CHANGED,
					),
				),
			)
		);
	}

	/**
	 * Only administrators may run or read a security report.
	 *
	 * @return bool|WP_Error
	 */
	public static function can_manage() {
		if ( current_user_can( 'manage_options' ) ) {
			return true;
		}

		return new WP_Error(
			'cascr_forbidden',
			__( 'You are not allowed to run security checks on this site.', 'security-check-report' ),
			array( 'status' => rest_authorization_required_code() )
		);
	}

	/**
	 * The registry, plus whatever the last run said.
	 *
	 * @return WP_REST_Response
	 */
	public static function get_tests() {
		return rest_ensure_response(
			array(
				'tests'      => CASCR_Registry::for_client(),
				'categories' => CASCR_Registry::categories(),
				'ignored'    => array_keys( CASCR_Store::ignored() ),
			)
		);
	}

	/**
	 * Runs one check.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public static function run_test( $request ) {
		$result = CASCR_Runner::run( $request['id'] );

		if ( null === $result ) {
			return new WP_Error(
				'cascr_unknown_test',
				__( 'There is no check with that identifier.', 'security-check-report' ),
				array( 'status' => 404 )
			);
		}

		return rest_ensure_response( $result );
	}

	/**
	 * Runs one check again and writes it into the stored run.
	 *
	 * This is what the "done, check it now" button behind a task calls. The
	 * answer carries the new grade and the new priority list, so the page can
	 * swap the affected card without reloading everything.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public static function recheck_test( $request ) {
		$id     = $request['id'];
		$result = CASCR_Runner::run( $id );

		if ( null === $result ) {
			return new WP_Error(
				'cascr_unknown_test',
				__( 'There is no check with that identifier.', 'security-check-report' ),
				array( 'status' => 404 )
			);
		}

		$run = CASCR_Store::patch_test( $id, $result );

		if ( false === $run ) {
			return new WP_Error(
				'cascr_no_run',
				__( 'There is no stored report to update. Run all checks once first.', 'security-check-report' ),
				array( 'status' => 409 )
			);
		}

		$summary = CASCR_Scoring::summarize( $run['tests'] );

		return rest_ensure_response(
			array(
				'id'         => $id,
				'result'     => $result,
				'partial'    => $run['partial'],
				'summary'    => array(
					'grade'   => $summary['grade'],
					'label'   => CASCR_Scoring::grade_label( $summary['grade'] ),
					'risk'    => $summary['risk'],
					'counts'  => $summary['counts'],
					'verdict' => $summary['verdict'],
					// Finished sentences, not numbers: their plural form is
					// decided here, where the catalogue is.
					'today'   => CASCR_Scoring::today( $summary['grade'], $summary['counts'] ),
					'note'    => CASCR_Admin_Dashboard::partial_line( $run ),
				),
				'priorities' => $summary['priorities'],
			)
		);
	}

	/**
	 * Records the one time agreement to run the checks.
	 *
	 * @return WP_REST_Response
	 */
	public static function set_consent() {
		return rest_ensure_response(
			array( 'consent' => CASCR_Store::set_consent() )
		);
	}

	/**
	 * The stored run, its summary and the comparison with the run before it.
	 *
	 * @return WP_REST_Response
	 */
	public static function get_report() {
		$run = CASCR_Store::last_run();

		if ( empty( $run ) ) {
			return rest_ensure_response( array( 'run' => null ) );
		}

		return rest_ensure_response(
			array(
				'run'  => $run,
				'diff' => CASCR_Store::diff(),
			)
		);
	}

	/**
	 * Scores and stores a run the browser has just finished.
	 *
	 * The scoring itself happens here, never in the browser, so the same
	 * numbers come out over WP-CLI.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public static function save_report( $request ) {
		$posted  = (array) $request['results'];
		$results = array();

		foreach ( CASCR_Registry::ids() as $id ) {
			if ( ! isset( $posted[ $id ] ) ) {
				continue;
			}

			$result            = CASCR_Result::normalize( (array) $posted[ $id ] );
			$result['id']      = $id;
			$result['ignored'] = ! empty( $posted[ $id ]['ignored'] );
			$results[ $id ]    = $result;
		}

		$summary = CASCR_Runner::finish( $results );

		return rest_ensure_response(
			array(
				'summary' => $summary,
				'grade'   => array(
					'letter' => $summary['grade'],
					'label'  => CASCR_Scoring::grade_label( $summary['grade'] ),
				),
			)
		);
	}

	/**
	 * Mutes or unmutes a finding.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public static function set_ignore( $request ) {
		$id = $request['id'];

		if ( ! $request['ignore'] ) {
			CASCR_Store::unignore( $id );

			return rest_ensure_response(
				array(
					'id'      => $id,
					'ignored' => false,
				)
			);
		}

		$result = CASCR_Runner::run( $id );

		if ( null === $result ) {
			return rest_ensure_response(
				array(
					'id'      => $id,
					'ignored' => false,
				)
			);
		}

		CASCR_Store::ignore( $id, $result, $request['mode'] );

		return rest_ensure_response(
			array(
				'id'      => $id,
				'ignored' => true,
				'mode'    => $request['mode'],
			)
		);
	}
}
