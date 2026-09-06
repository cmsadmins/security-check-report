<?php
/**
 * Checks for transport security, response headers and public endpoints.
 *
 * @package CmsAdmins\SecurityCheck
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Network and transport checks.
 */
class CASCR_Checks_Network extends CASCR_Checks_Base {

	/**
	 * Recommended minimum for the HSTS max-age directive, in seconds.
	 */
	const HSTS_MIN_AGE = 15552000;

	/**
	 * Is the whole site served over HTTPS?
	 *
	 * The previous version called is_ssl(), which only says whether the
	 * administrator happened to open the dashboard over HTTPS.
	 *
	 * @return array
	 */
	public static function ssl() {
		$home    = home_url();
		$scheme  = wp_parse_url( $home, PHP_URL_SCHEME );
		$secure  = 'https' === $scheme;
		$details = array();

		if ( ! $secure ) {
			return CASCR_Result::fail(
				__( 'The site address still uses http, so every login and every form submission travels in the clear.', 'security-check-report' ),
				9,
				array( $home ),
				__( 'Get a certificate, switch the site and home addresses to https and redirect http to https.', 'security-check-report' )
			);
		}

		if ( ! defined( 'FORCE_SSL_ADMIN' ) || ! FORCE_SSL_ADMIN ) {
			$details[] = __( 'FORCE_SSL_ADMIN is not set', 'security-check-report' );
		}

		$plain    = set_url_scheme( $home, 'http' );
		$response = CASCR_Http::get( $plain, array( 'redirection' => 0 ) );

		if ( ! is_wp_error( $response ) ) {
			$code     = wp_remote_retrieve_response_code( $response );
			$location = self::header( $response, 'location' );

			if ( ! in_array( $code, array( 301, 308 ), true ) || 0 !== strpos( $location, 'https://' ) ) {
				$details[] = __( 'the http address does not redirect permanently to https', 'security-check-report' );
			}
		}

		if ( empty( $details ) ) {
			return CASCR_Result::pass( __( 'The site is served over HTTPS and http is redirected.', 'security-check-report' ) );
		}

		return CASCR_Result::warn(
			__( 'The site uses HTTPS, but the setup is not complete.', 'security-check-report' ),
			5,
			$details,
			__( "Add define( 'FORCE_SSL_ADMIN', true ); to wp-config.php and redirect http to https with a 301.", 'security-check-report' )
		);
	}

	/**
	 * How long is the certificate still valid, and over which protocol?
	 *
	 * @return array
	 */
	public static function tls_certificate() {
		$host = wp_parse_url( home_url(), PHP_URL_HOST );

		if ( 'https' !== wp_parse_url( home_url(), PHP_URL_SCHEME ) ) {
			return CASCR_Result::inconclusive( __( 'The site does not use HTTPS, so there is no certificate to inspect.', 'security-check-report' ) );
		}

		if ( ! function_exists( 'stream_socket_client' ) || ! extension_loaded( 'openssl' ) ) {
			return CASCR_Result::inconclusive( __( 'This server cannot inspect TLS certificates.', 'security-check-report' ) );
		}

		$port    = (int) wp_parse_url( home_url(), PHP_URL_PORT );
		$port    = $port > 0 ? $port : 443;
		$context = stream_context_create(
			array(
				'ssl' => array(
					'capture_peer_cert' => true,
					'verify_peer'       => false,
					'verify_peer_name'  => false,
					'SNI_enabled'       => true,
					'peer_name'         => $host,
				),
			)
		);

		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- A refused connection is reported as inconclusive below.
		$socket = @stream_socket_client(
			'ssl://' . $host . ':' . $port,
			$errno,
			$errstr,
			5,
			STREAM_CLIENT_CONNECT,
			$context
		);

		if ( ! $socket ) {
			return CASCR_Result::inconclusive( __( 'No TLS connection to the site could be opened from the server itself.', 'security-check-report' ) );
		}

		$params = stream_context_get_params( $socket );

		// The crypto key only exists on an encrypted stream, and the stub for
		// stream_get_meta_data does not describe it.
		$protocol = self::nested_string( stream_get_meta_data( $socket ), 'crypto', 'protocol' );

		fclose( $socket ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- This is a network socket, not a file.

		if ( empty( $params['options']['ssl']['peer_certificate'] ) ) {
			return CASCR_Result::inconclusive( __( 'The certificate could not be read.', 'security-check-report' ) );
		}

		$cert = openssl_x509_parse( $params['options']['ssl']['peer_certificate'] );

		if ( ! is_array( $cert ) || empty( $cert['validTo_time_t'] ) ) {
			return CASCR_Result::inconclusive( __( 'The certificate could not be parsed.', 'security-check-report' ) );
		}

		$expires   = (int) $cert['validTo_time_t'];
		$remaining = $expires - time();

		$items = array(
			sprintf(
				/* translators: %s: certificate expiry date. */
				__( 'valid until %s', 'security-check-report' ),
				date_i18n( get_option( 'date_format' ), $expires )
			),
		);

		if ( '' !== $protocol ) {
			$items[] = $protocol;
		}

		if ( $remaining <= 0 ) {
			return CASCR_Result::fail(
				__( 'The TLS certificate has expired. Visitors get a browser warning instead of the site.', 'security-check-report' ),
				10,
				$items,
				__( 'Renew the certificate now and check that automatic renewal actually runs.', 'security-check-report' )
			);
		}

		if ( $remaining < 14 * DAY_IN_SECONDS ) {
			return CASCR_Result::fail(
				sprintf(
					/* translators: %s: human readable time until expiry. */
					__( 'The TLS certificate expires in %s.', 'security-check-report' ),
					human_time_diff( time(), $expires )
				),
				7,
				$items,
				__( 'Renew it and check that automatic renewal runs.', 'security-check-report' )
			);
		}

		if ( '' !== $protocol && preg_match( '/TLSv1(\.[01])?$/', $protocol ) ) {
			return CASCR_Result::warn(
				sprintf(
					/* translators: %s: negotiated TLS protocol version. */
					__( 'The connection was negotiated over %s, which browsers have retired.', 'security-check-report' ),
					$protocol
				),
				5,
				$items,
				__( 'Ask the host to allow TLS 1.2 and 1.3 only.', 'security-check-report' )
			);
		}

		return CASCR_Result::pass( __( 'The TLS certificate is valid and not about to expire.', 'security-check-report' ), $items );
	}

	/**
	 * Which of the recommended response headers are missing?
	 *
	 * Scored per header instead of all or nothing, and the cross-origin
	 * isolation headers are treated as optional because setting them breaks
	 * embeds on most ordinary sites.
	 *
	 * @return array
	 */
	public static function security_headers() {
		$response = CASCR_Http::home();

		if ( is_wp_error( $response ) ) {
			return CASCR_Result::inconclusive( __( 'The response headers could not be retrieved.', 'security-check-report' ) );
		}

		$expected = array(
			'Strict-Transport-Security' => 3,
			'Content-Security-Policy'   => 3,
			'X-Content-Type-Options'    => 2,
			'X-Frame-Options'           => 2,
			'Referrer-Policy'           => 1,
			'Permissions-Policy'        => 1,
		);

		$optional = array( 'Cross-Origin-Opener-Policy', 'Cross-Origin-Embedder-Policy', 'Cross-Origin-Resource-Policy' );

		$missing = array();
		$score   = 0;

		foreach ( $expected as $header => $weight ) {
			if ( '' === self::header( $response, $header ) ) {
				$missing[] = $header;
				$score    += $weight;
			}
		}

		// X-Frame-Options is redundant once the policy sets frame-ancestors.
		$csp = self::header( $response, 'Content-Security-Policy' );
		if ( in_array( 'X-Frame-Options', $missing, true ) && false !== stripos( $csp, 'frame-ancestors' ) ) {
			$missing = array_values( array_diff( $missing, array( 'X-Frame-Options' ) ) );
			$score  -= 2;
		}

		$missing_optional = array();
		foreach ( $optional as $header ) {
			if ( '' === self::header( $response, $header ) ) {
				$missing_optional[] = $header;
			}
		}

		if ( empty( $missing ) ) {
			return CASCR_Result::pass(
				__( 'All recommended security headers are present.', 'security-check-report' ),
				empty( $missing_optional )
					? array()
					: array(
						sprintf(
							/* translators: %s: comma separated list of optional headers. */
							__( 'optional and not set: %s', 'security-check-report' ),
							implode( ', ', $missing_optional )
						),
					)
			);
		}

		$score = max( 4, min( 8, $score ) );

		$summary = sprintf(
			/* translators: %d: number of missing security headers. */
			_n(
				'%d recommended security header is missing.',
				'%d recommended security headers are missing.',
				count( $missing ),
				'security-check-report'
			),
			count( $missing )
		);

		return $score >= CASCR_Result::THRESHOLD_FAIL
			? CASCR_Result::fail( $summary, $score, $missing, self::header_fix() )
			: CASCR_Result::warn( $summary, $score, $missing, self::header_fix() );
	}

	/**
	 * Is the HSTS header long lived and does it cover subdomains?
	 *
	 * @return array
	 */
	public static function hsts_quality() {
		if ( 'https' !== wp_parse_url( home_url(), PHP_URL_SCHEME ) ) {
			return CASCR_Result::inconclusive( __( 'HSTS only applies to sites served over HTTPS.', 'security-check-report' ) );
		}

		$response = CASCR_Http::home();

		if ( is_wp_error( $response ) ) {
			return CASCR_Result::inconclusive( __( 'The response headers could not be retrieved.', 'security-check-report' ) );
		}

		$header = self::header( $response, 'Strict-Transport-Security' );

		if ( '' === $header ) {
			return CASCR_Result::warn(
				__( 'No HSTS header is sent, so the first request of a visit can still be downgraded to http.', 'security-check-report' ),
				5,
				array(),
				__( 'Send Strict-Transport-Security: max-age=31536000; includeSubDomains once the whole site is reliably on HTTPS.', 'security-check-report' )
			);
		}

		$issues  = array();
		$max_age = 0;

		if ( preg_match( '/max-age\s*=\s*(\d+)/i', $header, $matches ) ) {
			$max_age = (int) $matches[1];
		}

		if ( $max_age < self::HSTS_MIN_AGE ) {
			$issues[] = sprintf(
				/* translators: %d: max-age value in seconds. */
				_n( 'max-age is only %d second', 'max-age is only %d seconds', $max_age, 'security-check-report' ),
				$max_age
			);
		}

		if ( false === stripos( $header, 'includeSubDomains' ) ) {
			$issues[] = __( 'includeSubDomains is not set', 'security-check-report' );
		}

		if ( empty( $issues ) ) {
			return CASCR_Result::pass( __( 'The HSTS header is set up properly.', 'security-check-report' ), array( $header ) );
		}

		return CASCR_Result::warn(
			__( 'The HSTS header is present but weaker than it should be.', 'security-check-report' ),
			4,
			$issues,
			__( 'Use max-age=31536000; includeSubDomains. Add preload only when every subdomain is on HTTPS for good.', 'security-check-report' )
		);
	}

	/**
	 * Does the Content Security Policy actually restrict anything?
	 *
	 * @return array
	 */
	public static function csp_quality() {
		$response = CASCR_Http::home();

		if ( is_wp_error( $response ) ) {
			return CASCR_Result::inconclusive( __( 'The response headers could not be retrieved.', 'security-check-report' ) );
		}

		$policy = self::header( $response, 'Content-Security-Policy' );
		$report = self::header( $response, 'Content-Security-Policy-Report-Only' );

		if ( '' === $policy && '' === $report ) {
			return CASCR_Result::warn(
				__( 'No Content Security Policy is sent, so an injected script runs with no restriction.', 'security-check-report' ),
				5,
				array(),
				__( 'Start with Content-Security-Policy-Report-Only, watch the reports for a while, then switch it to the enforcing header.', 'security-check-report' )
			);
		}

		if ( '' === $policy ) {
			return CASCR_Result::warn(
				__( 'The Content Security Policy is only sent in report-only mode, so nothing is actually blocked.', 'security-check-report' ),
				4,
				array( $report ),
				__( 'Once the reports are quiet, send the same policy as Content-Security-Policy.', 'security-check-report' )
			);
		}

		$issues = array();

		if ( false !== stripos( $policy, "'unsafe-inline'" ) ) {
			$issues[] = __( "'unsafe-inline' allows injected inline scripts to run", 'security-check-report' );
		}

		if ( false !== stripos( $policy, "'unsafe-eval'" ) ) {
			$issues[] = __( "'unsafe-eval' allows strings to be executed as code", 'security-check-report' );
		}

		if ( preg_match( '/(default|script)-src[^;]*\s\*/i', $policy ) ) {
			$issues[] = __( 'a wildcard source allows scripts from anywhere', 'security-check-report' );
		}

		if ( false === stripos( $policy, 'object-src' ) && false === stripos( $policy, 'default-src' ) ) {
			$issues[] = __( 'neither default-src nor object-src is set', 'security-check-report' );
		}

		if ( empty( $issues ) ) {
			return CASCR_Result::pass( __( 'A Content Security Policy is enforced and contains no obvious escape hatch.', 'security-check-report' ) );
		}

		return CASCR_Result::warn(
			__( 'A Content Security Policy is enforced but leaves the main hole open.', 'security-check-report' ),
			5,
			$issues,
			__( 'Replace unsafe-inline with a nonce or a hash for the scripts the site really needs.', 'security-check-report' )
		);
	}

	/**
	 * Are the session cookies marked properly?
	 *
	 * @return array
	 */
	public static function cookie_flags() {
		$response = CASCR_Http::get( wp_login_url(), array( 'redirection' => 0 ) );

		if ( is_wp_error( $response ) ) {
			return CASCR_Result::inconclusive( __( 'The login page could not be requested.', 'security-check-report' ) );
		}

		$cookies = wp_remote_retrieve_header( $response, 'set-cookie' );
		$cookies = is_array( $cookies ) ? $cookies : array_filter( array( $cookies ) );

		if ( empty( $cookies ) ) {
			return CASCR_Result::inconclusive( __( 'The login page set no cookies that could be inspected.', 'security-check-report' ) );
		}

		$https  = 'https' === wp_parse_url( home_url(), PHP_URL_SCHEME );
		$issues = array();

		foreach ( $cookies as $cookie ) {
			$name = trim( strtok( $cookie, '=' ) );

			if ( $https && false === stripos( $cookie, 'secure' ) ) {
				$issues[] = sprintf(
					/* translators: %s: cookie name. */
					__( '%s is not marked Secure', 'security-check-report' ),
					$name
				);
			}

			if ( false === stripos( $cookie, 'samesite' ) ) {
				$issues[] = sprintf(
					/* translators: %s: cookie name. */
					__( '%s has no SameSite attribute', 'security-check-report' ),
					$name
				);
			}
		}

		if ( empty( $issues ) ) {
			return CASCR_Result::pass( __( 'The cookies set by the login page carry the right attributes.', 'security-check-report' ) );
		}

		return CASCR_Result::warn(
			__( 'Cookies are sent without the attributes that limit where a browser will send them back.', 'security-check-report' ),
			4,
			self::cap( array_unique( $issues ) ),
			__( 'Set SameSite=Lax on the session cookies at the server, and Secure on every cookie once the site is on HTTPS.', 'security-check-report' )
		);
	}

	/**
	 * Does the site hand its responses to any origin that asks?
	 *
	 * @return array
	 */
	public static function cors_configuration() {
		$response = CASCR_Http::home();

		if ( is_wp_error( $response ) ) {
			return CASCR_Result::inconclusive( __( 'The response headers could not be retrieved.', 'security-check-report' ) );
		}

		$origin      = self::header( $response, 'Access-Control-Allow-Origin' );
		$credentials = strtolower( self::header( $response, 'Access-Control-Allow-Credentials' ) );

		if ( '' === $origin ) {
			return CASCR_Result::pass( __( 'No cross-origin headers are sent, which is the right default.', 'security-check-report' ) );
		}

		if ( '*' === $origin && 'true' === $credentials ) {
			return CASCR_Result::fail(
				__( 'Every origin is allowed to read responses and to send credentials along.', 'security-check-report' ),
				9,
				array( 'Access-Control-Allow-Origin: *', 'Access-Control-Allow-Credentials: true' ),
				__( 'Never combine the two. Name the origins that are actually allowed.', 'security-check-report' )
			);
		}

		if ( '*' === $origin ) {
			return CASCR_Result::warn(
				__( 'Every origin is allowed to read responses from this site.', 'security-check-report' ),
				5,
				array( 'Access-Control-Allow-Origin: *' ),
				__( 'Name the origins that are actually allowed instead of using the wildcard.', 'security-check-report' )
			);
		}

		return CASCR_Result::pass(
			__( 'Cross-origin access is limited to a named origin.', 'security-check-report' ),
			array( 'Access-Control-Allow-Origin: ' . $origin )
		);
	}

	/**
	 * Do the response headers name the PHP version?
	 *
	 * @return array
	 */
	public static function php_version_in_headers() {
		$response = CASCR_Http::home();

		if ( is_wp_error( $response ) ) {
			return CASCR_Result::inconclusive( __( 'The response headers could not be retrieved.', 'security-check-report' ) );
		}

		$found = array();

		foreach ( array( 'X-Powered-By', 'Server' ) as $header ) {
			$value = self::header( $response, $header );

			if ( '' !== $value && preg_match( '/(php|apache|nginx)[\/ ]\d/i', $value ) ) {
				$found[] = $header . ': ' . $value;
			}
		}

		if ( empty( $found ) ) {
			return CASCR_Result::pass( __( 'The response headers do not name software versions.', 'security-check-report' ) );
		}

		return CASCR_Result::warn(
			__( 'The response headers name the exact software versions in use, which saves an attacker the work of finding out.', 'security-check-report' ),
			4,
			$found,
			__( 'Set expose_php to Off in php.ini and trim the server token in the web server configuration.', 'security-check-report' )
		);
	}

	/**
	 * Which discovery tags does the front page still emit?
	 *
	 * @return array
	 */
	public static function legacy_meta_exposure() {
		$response = CASCR_Http::home();

		if ( is_wp_error( $response ) ) {
			return CASCR_Result::inconclusive( __( 'The front page could not be retrieved.', 'security-check-report' ) );
		}

		$body    = wp_remote_retrieve_body( $response );
		$exposed = array();

		if ( preg_match( '/<meta[^>]+name=["\']generator["\'][^>]*WordPress\s*([0-9.]*)/i', $body, $matches ) ) {
			$exposed[] = '' !== trim( $matches[1] )
				? sprintf(
					/* translators: %s: WordPress version number. */
					__( 'generator tag naming WordPress %s', 'security-check-report' ),
					trim( $matches[1] )
				)
				: __( 'generator tag naming WordPress', 'security-check-report' );
		}

		if ( false !== strpos( $body, 'wlwmanifest' ) ) {
			$exposed[] = __( 'Windows Live Writer manifest link', 'security-check-report' );
		}

		if ( false !== strpos( $body, 'EditURI' ) || false !== strpos( $body, 'rsd+xml' ) ) {
			$exposed[] = __( 'Really Simple Discovery link', 'security-check-report' );
		}

		if ( empty( $exposed ) ) {
			return CASCR_Result::pass( __( 'The front page emits no legacy discovery tags.', 'security-check-report' ) );
		}

		return CASCR_Result::warn(
			__( 'The front page emits discovery tags that give away details about the installation.', 'security-check-report' ),
			min( 5, 2 + count( $exposed ) ),
			$exposed,
			__( 'Remove the generator, wlwmanifest and RSD hooks from wp_head. This is fingerprinting, not a hole in itself.', 'security-check-report' )
		);
	}

	/**
	 * Is the XML-RPC endpoint answering?
	 *
	 * @return array
	 */
	public static function xmlrpc() {
		$url = site_url( '/xmlrpc.php' );

		$response = CASCR_Http::post(
			$url,
			array(
				'body'    => '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>',
				'headers' => array( 'Content-Type' => 'text/xml' ),
			)
		);

		if ( is_wp_error( $response ) ) {
			return CASCR_Result::inconclusive( __( 'The XML-RPC endpoint could not be reached.', 'security-check-report' ) );
		}

		$code = wp_remote_retrieve_response_code( $response );
		$body = wp_remote_retrieve_body( $response );

		if ( in_array( $code, array( 401, 403, 404, 405 ), true ) ) {
			return CASCR_Result::pass( __( 'The XML-RPC endpoint is blocked.', 'security-check-report' ) );
		}

		if ( 200 !== $code || false === strpos( $body, 'methodResponse' ) ) {
			return CASCR_Result::pass( __( 'The XML-RPC endpoint does not answer method calls.', 'security-check-report' ) );
		}

		$items = array();

		if ( false !== strpos( $body, 'system.multicall' ) ) {
			$items[] = __( 'system.multicall is available, which lets one request try many passwords', 'security-check-report' );
		}

		if ( false !== strpos( $body, 'pingback.ping' ) ) {
			$items[] = __( 'pingback.ping is available, which lets the site be used to probe other hosts', 'security-check-report' );
		}

		return CASCR_Result::warn(
			__( 'The XML-RPC endpoint answers method calls.', 'security-check-report' ),
			empty( $items ) ? 4 : 6,
			$items,
			__( 'If nothing uses XML-RPC, block xmlrpc.php at the server. The Jetpack and app clients are the usual exceptions.', 'security-check-report' )
		);
	}

	/**
	 * Can the list of user names be read without logging in?
	 *
	 * @return array
	 */
	public static function user_enumeration() {
		$methods = array();
		$unknown = 0;

		$response = CASCR_Http::get( home_url( '/?author=1' ), array( 'redirection' => 0 ) );

		if ( is_wp_error( $response ) ) {
			++$unknown;
		} else {
			$code     = wp_remote_retrieve_response_code( $response );
			$location = self::header( $response, 'location' );

			if ( in_array( $code, array( 301, 302 ), true ) && false !== strpos( $location, '/author/' ) ) {
				$methods[] = __( 'the ?author=N parameter reveals the login name', 'security-check-report' );
			}
		}

		$response = CASCR_Http::get( rest_url( 'wp/v2/users' ), array( 'headers' => array( 'Accept' => 'application/json' ) ) );

		if ( is_wp_error( $response ) ) {
			++$unknown;
		} else {
			$users = json_decode( wp_remote_retrieve_body( $response ), true );

			if ( 200 === wp_remote_retrieve_response_code( $response ) && is_array( $users ) && ! empty( $users ) ) {
				$methods[] = sprintf(
					/* translators: %d: number of user records returned by the REST API. */
					_n(
						'the REST endpoint /wp/v2/users lists %d account',
						'the REST endpoint /wp/v2/users lists %d accounts',
						count( $users ),
						'security-check-report'
					),
					count( $users )
				);
			}
		}

		$response = CASCR_Http::get( home_url( '/?rest_route=/oembed/1.0/embed&url=' . rawurlencode( home_url() ) ) );

		if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
			$body = wp_remote_retrieve_body( $response );

			if ( false !== strpos( $body, 'author_url' ) || false !== strpos( $body, 'author_name' ) ) {
				$methods[] = __( 'the oEmbed endpoint reveals the author', 'security-check-report' );
			}
		}

		if ( empty( $methods ) ) {
			return $unknown > 1
				? CASCR_Result::inconclusive( __( 'User enumeration could not be checked.', 'security-check-report' ) )
				: CASCR_Result::pass( __( 'The usual ways of reading out user names are closed.', 'security-check-report' ) );
		}

		return CASCR_Result::warn(
			__( 'User names can be read without logging in, which turns password guessing from two unknowns into one.', 'security-check-report' ),
			min( 7, 4 + count( $methods ) ),
			$methods,
			__( 'Require authentication on the users endpoint and stop the ?author redirect. Display names that differ from login names help too.', 'security-check-report' )
		);
	}

	/**
	 * Which REST routes accept writes from anyone?
	 *
	 * @return array
	 */
	public static function rest_open_routes() {
		if ( ! function_exists( 'rest_get_server' ) ) {
			return CASCR_Result::inconclusive( __( 'The REST API is not available.', 'security-check-report' ) );
		}

		$routes = rest_get_server()->get_routes();
		$open   = array();

		// The batch endpoint deliberately has no callback of its own: it checks
		// permissions on each request it carries instead. Reporting it would be
		// a finding on stock WordPress and would teach people to ignore this
		// check.
		$expected = array( '/batch/v1' );

		foreach ( $routes as $route => $handlers ) {
			if ( in_array( $route, $expected, true ) ) {
				continue;
			}

			foreach ( $handlers as $handler ) {
				$methods = isset( $handler['methods'] ) ? (array) $handler['methods'] : array();
				$writes  = array_intersect( array( 'POST', 'PUT', 'PATCH', 'DELETE' ), array_keys( array_filter( $methods ) ) );

				if ( empty( $writes ) ) {
					continue;
				}

				$permission = isset( $handler['permission_callback'] ) ? $handler['permission_callback'] : null;

				if ( null === $permission || '__return_true' === $permission ) {
					$open[] = sprintf(
						/* translators: 1: REST route, 2: comma separated HTTP methods. */
						__( '%1$s accepts %2$s from anyone', 'security-check-report' ),
						$route,
						implode( ', ', $writes )
					);
				}
			}
		}

		$open = array_values( array_unique( $open ) );

		if ( empty( $open ) ) {
			return CASCR_Result::pass( __( 'Every REST route that changes data checks permissions first.', 'security-check-report' ) );
		}

		return CASCR_Result::fail(
			sprintf(
				/* translators: %d: number of unauthenticated write routes. */
				_n(
					'%d REST route accepts changes without checking permissions.',
					'%d REST routes accept changes without checking permissions.',
					count( $open ),
					'security-check-report'
				),
				count( $open )
			),
			8,
			self::cap( $open ),
			__( 'The route belongs to whichever plugin registered it. Report it to the author, or remove the plugin.', 'security-check-report' )
		);
	}

	/**
	 * Can the client address be faked?
	 *
	 * If the site sits directly on the internet but a forwarded header arrives
	 * anyway, that header came from the visitor. Any plugin that trusts it for
	 * rate limiting or blocking can be walked straight past.
	 *
	 * @return array
	 */
	public static function proxy_ip_configuration() {
		$headers = array( 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'HTTP_CF_CONNECTING_IP', 'HTTP_TRUE_CLIENT_IP' );
		$present = array();

		foreach ( $headers as $header ) {
			if ( ! empty( $_SERVER[ $header ] ) ) {
				$present[] = str_replace( 'HTTP_', '', $header );
			}
		}

		if ( empty( $present ) ) {
			return CASCR_Result::pass( __( 'No forwarded address headers arrive, so the client address cannot be faked through them.', 'security-check-report' ) );
		}

		$remote     = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		$is_private = '' !== $remote && ! filter_var(
			$remote,
			FILTER_VALIDATE_IP,
			FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
		);

		if ( $is_private ) {
			return CASCR_Result::pass(
				__( 'Forwarded address headers arrive from a proxy in front of the site, which is the expected setup.', 'security-check-report' ),
				$present
			);
		}

		return CASCR_Result::warn(
			__( 'Forwarded address headers arrive even though the request came straight from the internet, so anything trusting them can be fooled.', 'security-check-report' ),
			6,
			array_merge(
				$present,
				array(
					sprintf(
						/* translators: %s: remote IP address of the current request. */
						__( 'the connection came from %s', 'security-check-report' ),
						$remote
					),
				)
			),
			__( 'Configure security plugins to read the address from REMOTE_ADDR, or strip these headers at the edge.', 'security-check-report' )
		);
	}

	/**
	 * Shared remediation text for the header checks.
	 *
	 * @return string
	 */
	private static function header_fix() {
		return __( 'Send the headers from the web server so they cover static files too. Start with X-Content-Type-Options and Referrer-Policy, they never break anything.', 'security-check-report' );
	}
}
