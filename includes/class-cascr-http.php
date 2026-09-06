<?php
/**
 * Cached outbound requests.
 *
 * @package CmsAdmins\SecurityCheck
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Wraps wp_remote_* so the same URL is only fetched once per scan.
 *
 * Several checks look at the very same response: the homepage is needed for the
 * security headers, the exposed PHP version, the legacy meta tags and the CORS
 * configuration. Without memoisation that is four identical round trips.
 */
class CASCR_Http {

	/**
	 * Responses keyed by method, URL and arguments.
	 *
	 * @var array
	 */
	private static $cache = array();

	/**
	 * Default timeout in seconds for every request the plugin makes.
	 */
	const TIMEOUT = 10;

	/**
	 * Performs a GET request, reusing an identical earlier one.
	 *
	 * @param string $url  Absolute URL.
	 * @param array  $args Optional wp_remote_get arguments.
	 * @return array|WP_Error
	 */
	public static function get( $url, $args = array() ) {
		return self::request( 'GET', $url, $args );
	}

	/**
	 * Performs a HEAD request, reusing an identical earlier one.
	 *
	 * @param string $url  Absolute URL.
	 * @param array  $args Optional wp_remote_head arguments.
	 * @return array|WP_Error
	 */
	public static function head( $url, $args = array() ) {
		return self::request( 'HEAD', $url, $args );
	}

	/**
	 * Performs a POST request. Not cached, since bodies differ by intent.
	 *
	 * @param string $url  Absolute URL.
	 * @param array  $args Optional wp_remote_post arguments.
	 * @return array|WP_Error
	 */
	public static function post( $url, $args = array() ) {
		return wp_remote_post( $url, self::defaults( $args ) );
	}

	/**
	 * The site homepage response, fetched at most once per request lifecycle.
	 *
	 * @return array|WP_Error
	 */
	public static function home() {
		return self::get( home_url( '/' ) );
	}

	/**
	 * Fetches a URL and reports whether it is publicly readable.
	 *
	 * A 200 with a non-empty body is the only thing that counts as exposed.
	 * Some hosts answer 200 with their own error page, so callers can pass a
	 * needle that must appear in the body.
	 *
	 * @param string $url    Absolute URL.
	 * @param string $needle Optional string that must appear in the body.
	 * @return bool|null True if reachable, false if not, null if undeterminable.
	 */
	public static function is_public( $url, $needle = '' ) {
		$response = self::get(
			$url,
			array(
				'redirection' => 0,
				'headers'     => array( 'Range' => 'bytes=0-2047' ),
			)
		);

		if ( is_wp_error( $response ) ) {
			return null;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code && 206 !== $code ) {
			return false;
		}

		$body = wp_remote_retrieve_body( $response );
		if ( '' === trim( $body ) ) {
			return false;
		}

		if ( '' !== $needle ) {
			return false !== strpos( $body, $needle );
		}

		return true;
	}

	/**
	 * Empties the in-memory cache. Used between test cases.
	 */
	public static function reset() {
		self::$cache = array();
	}

	/**
	 * @param string $method HTTP method.
	 * @param string $url    Absolute URL.
	 * @param array  $args   Request arguments.
	 * @return array|WP_Error
	 */
	private static function request( $method, $url, $args ) {
		$args = self::defaults( $args );
		$key  = md5( $method . '|' . $url . '|' . wp_json_encode( $args ) );

		if ( array_key_exists( $key, self::$cache ) ) {
			return self::$cache[ $key ];
		}

		if ( 'HEAD' === $method ) {
			$response = wp_remote_head( $url, $args );
		} else {
			$response = wp_remote_get( $url, $args );
		}

		self::$cache[ $key ] = $response;

		return $response;
	}

	/**
	 * @param array $args Caller supplied arguments.
	 * @return array
	 */
	private static function defaults( $args ) {
		return wp_parse_args(
			$args,
			array(
				'timeout'    => self::TIMEOUT,
				'user-agent' => 'CMS ADMINS Security Check Report/' . CASCR_VERSION . '; ' . home_url( '/' ),
			)
		);
	}
}
