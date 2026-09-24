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
	 * Days of remaining certificate lifetime that count as a failure.
	 */
	const CERT_FAIL_DAYS = 14;

	/**
	 * Days of remaining certificate lifetime that count as a warning.
	 *
	 * Ballot SC-081v3 takes the maximum certificate lifetime down to 100 days
	 * in March 2027 and to 47 in 2029, so a renewal that only happens when
	 * somebody remembers it will start to run out of room.
	 */
	const CERT_WARN_DAYS = 30;

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
	 * Peer verification is switched off on purpose: the question here is the
	 * expiry date, and a connection that is refused answers nothing at all.
	 * The price is that the trust chain and the host name go unchecked, which
	 * is why no result of this check calls a certificate trusted.
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

		return self::certificate_result( (int) $cert['validTo_time_t'], $protocol );
	}

	/**
	 * Turns an expiry date and a protocol version into a verdict.
	 *
	 * Split off from the connection handling so the thresholds can be exercised
	 * without a TLS server on the other end.
	 *
	 * @param int    $expires  Expiry timestamp from the certificate.
	 * @param string $protocol Negotiated protocol, empty when unknown.
	 * @return array
	 */
	protected static function certificate_result( $expires, $protocol ) {
		$remaining = $expires - time();

		$items = array(
			sprintf(
				/* translators: %s: certificate expiry date. */
				__( 'valid until %s', 'security-check-report' ),
				date_i18n( get_option( 'date_format' ), $expires )
			),
			__( 'the trust chain and the host name are not checked here', 'security-check-report' ),
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

		if ( $remaining < self::CERT_FAIL_DAYS * DAY_IN_SECONDS ) {
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

		if ( $remaining < self::CERT_WARN_DAYS * DAY_IN_SECONDS ) {
			return CASCR_Result::warn(
				sprintf(
					/* translators: %s: human readable time until expiry. */
					__( 'The TLS certificate expires in %s, which leaves little room if a renewal fails.', 'security-check-report' ),
					human_time_diff( time(), $expires )
				),
				4,
				$items,
				__( 'Renew it and let the renewal run automatically. Certificate lifetimes drop to 100 days in March 2027 and to 47 days in 2029, so a manual renewal will get tight.', 'security-check-report' )
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

		return CASCR_Result::pass(
			__( 'The TLS certificate is within its validity period and not about to expire.', 'security-check-report' ),
			$items
		);
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

		// Seconds are how the header is written, but nobody reads a six figure
		// number as a duration, and the yardstick belongs next to the value.
		if ( 0 === $max_age ) {
			$issues[] = sprintf(
				/* translators: %s: recommended minimum lifetime, already formatted. */
				__( 'the header carries no usable max-age, so it expires immediately instead of lasting at least %s', 'security-check-report' ),
				human_time_diff( 0, self::HSTS_MIN_AGE )
			);
		} elseif ( $max_age < self::HSTS_MIN_AGE ) {
			$issues[] = sprintf(
				/* translators: 1: current max-age as a duration, 2: recommended minimum as a duration. */
				__( 'max-age lasts %1$s, the recommendation is at least %2$s', 'security-check-report' ),
				human_time_diff( 0, $max_age ),
				human_time_diff( 0, self::HSTS_MIN_AGE )
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
			__( 'Use max-age=31536000; includeSubDomains, which is one year. Anything shorter than six months counts as weak here. Add preload only when every subdomain is on HTTPS for good.', 'security-check-report' )
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

		$directives    = self::csp_directives( $policy );
		$issues        = array();
		$unsafe_inline = false;
		$unsafe_eval   = false;
		$wildcard      = false;

		foreach ( $directives as $name => $sources ) {
			// A browser that understands 'strict-dynamic' or a nonce ignores
			// 'unsafe-inline' in the same directive. The strict policy everyone
			// copies carries it on purpose, as a fallback for older browsers,
			// and reporting that would send people to remove the fallback.
			$has_fallback = false;

			foreach ( $sources as $source ) {
				if ( "'strict-dynamic'" === $source || 0 === strpos( $source, "'nonce-" ) ) {
					$has_fallback = true;
				}
			}

			if ( ! $has_fallback && in_array( "'unsafe-inline'", $sources, true ) ) {
				$unsafe_inline = true;
			}

			if ( in_array( "'unsafe-eval'", $sources, true ) ) {
				$unsafe_eval = true;
			}

			// Only the bare star opens the door. A host wildcard such as
			// *.cdn.example.com names one place and is a normal thing to write.
			if ( in_array( $name, array( 'default-src', 'script-src' ), true ) && in_array( '*', $sources, true ) ) {
				$wildcard = true;
			}
		}

		if ( $unsafe_inline ) {
			$issues[] = __( "'unsafe-inline' allows injected inline scripts to run", 'security-check-report' );
		}

		if ( $unsafe_eval ) {
			$issues[] = __( "'unsafe-eval' allows strings to be executed as code", 'security-check-report' );
		}

		if ( $wildcard ) {
			$issues[] = __( 'a wildcard source allows scripts from anywhere', 'security-check-report' );
		}

		if ( ! isset( $directives['object-src'] ) && ! isset( $directives['default-src'] ) ) {
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
	 * Are the cookies the login page hands out marked properly?
	 *
	 * The request is unauthenticated, so the session cookies are out of reach:
	 * WordPress only issues those after a successful sign-in. What arrives here
	 * is the cookie the login form sets beforehand, which is why the wording
	 * stays with the cookies that were actually seen. A server that forgets the
	 * attributes on this one usually forgets them on the others as well.
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
			$parts = explode( ';', $cookie );
			$pair  = explode( '=', array_shift( $parts ), 2 );
			$name  = trim( $pair[0] );

			// Only the part behind the first semicolon holds attributes. A
			// search over the whole header would let a cookie called
			// "secure_session" pass for one that carries the Secure flag.
			$flags = array();

			foreach ( $parts as $attribute ) {
				$attribute = explode( '=', $attribute, 2 );
				$flags[]   = strtolower( trim( $attribute[0] ) );
			}

			if ( $https && ! in_array( 'secure', $flags, true ) ) {
				$issues[] = sprintf(
					/* translators: %s: cookie name. */
					__( '%s is not marked Secure', 'security-check-report' ),
					$name
				);
			}

			// WordPress sets HttpOnly on the authentication cookies itself, so
			// a cookie without it here points at something in front of it that
			// rewrites the header.
			if ( ! in_array( 'httponly', $flags, true ) ) {
				$issues[] = sprintf(
					/* translators: %s: cookie name. */
					__( '%s is readable from JavaScript, it has no HttpOnly attribute', 'security-check-report' ),
					$name
				);
			}

			if ( ! in_array( 'samesite', $flags, true ) ) {
				$issues[] = sprintf(
					/* translators: %s: cookie name. */
					__( '%s has no SameSite attribute', 'security-check-report' ),
					$name
				);
			}
		}

		if ( empty( $issues ) ) {
			return CASCR_Result::pass( __( 'The cookies the login page hands out before sign-in carry the right attributes.', 'security-check-report' ) );
		}

		return CASCR_Result::warn(
			__( 'The login page hands out cookies without the attributes that limit where a browser will send them back.', 'security-check-report' ),
			4,
			self::cap( array_unique( $issues ) ),
			__( 'Set HttpOnly, SameSite=Lax and, on an HTTPS site, Secure at the server. The session cookies appear only after a successful sign-in and are not part of this measurement.', 'security-check-report' )
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
		$score = 4;

		// The same filter wp_xmlrpc_server::login() consults. It turns away
		// every method that needs a login, which is what most of the security
		// plugins set, and it leaves the endpoint answering.
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- This is core's own filter, read here rather than introduced.
		$authenticated = (bool) apply_filters( 'xmlrpc_enabled', true );

		if ( ! $authenticated ) {
			$items[] = __( 'the xmlrpc_enabled filter refuses every method that needs a login, but the endpoint keeps answering', 'security-check-report' );
		}

		if ( $authenticated && false !== strpos( $body, 'system.multicall' ) ) {
			$items[] = __( 'system.multicall bundles many calls into one request. Since WordPress 4.4 the first failed login ends the rest, so it no longer multiplies password guesses, but one request still does the work of many', 'security-check-report' );
		}

		if ( false !== strpos( $body, 'pingback.ping' ) ) {
			$items[] = __( 'pingback.ping is available, which lets the site be used to probe other hosts', 'security-check-report' );
			$score   = 5;
		}

		return CASCR_Result::warn(
			__( 'The XML-RPC endpoint answers method calls.', 'security-check-report' ),
			$score,
			$items,
			__( 'If nothing uses XML-RPC, block xmlrpc.php in the web server, which is the only place that stops the requests before WordPress handles them. The xmlrpc_enabled filter only turns away the methods that need a login. Jetpack and the mobile apps are the usual reasons to leave it open.', 'security-check-report' )
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

		// Author 1 is often gone on an older site, and the redirect that gives
		// the login name away only happens with pretty permalinks. Probing a
		// few accounts that really exist, and accepting a plain 200 as an
		// answer, keeps the check working on both kinds of setup.
		$ids = get_users(
			array(
				'fields' => 'ID',
				'number' => 3,
			)
		);

		$ids     = empty( $ids ) ? array( 1 ) : $ids;
		$login   = false;
		$archive = false;
		$failed  = 0;

		foreach ( $ids as $id ) {
			$response = CASCR_Http::get( home_url( '/?author=' . (int) $id ), array( 'redirection' => 0 ) );

			if ( is_wp_error( $response ) ) {
				++$failed;
				continue;
			}

			$code     = wp_remote_retrieve_response_code( $response );
			$location = self::header( $response, 'location' );

			if ( in_array( $code, array( 301, 302 ), true ) && false !== strpos( $location, '/author/' ) ) {
				$login = true;
			} elseif ( 200 === $code ) {
				$archive = true;
			}
		}

		if ( $failed === count( $ids ) ) {
			++$unknown;
		}

		if ( $login ) {
			$methods[] = __( 'the ?author=N parameter redirects to the author archive and gives the login name away', 'security-check-report' );
		} elseif ( $archive ) {
			$methods[] = __( 'the ?author=N parameter answers with an author archive, which confirms which account IDs exist', 'security-check-report' );
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
			__( 'Require authentication on the users endpoint and stop the ?author redirect. A different display name changes nothing here: the author slug keeps the login name it was generated from, and that is what the redirect and the REST answer carry.', 'security-check-report' )
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

		$routes  = rest_get_server()->get_routes();
		$public  = array();
		$missing = array();

		foreach ( $routes as $route => $handlers ) {
			if ( self::is_public_by_design( $route ) ) {
				continue;
			}

			foreach ( $handlers as $handler ) {
				$methods = isset( $handler['methods'] ) ? (array) $handler['methods'] : array();
				$writes  = array_intersect( array( 'POST', 'PUT', 'PATCH', 'DELETE' ), array_keys( array_filter( $methods ) ) );

				if ( empty( $writes ) ) {
					continue;
				}

				$permission = isset( $handler['permission_callback'] ) ? $handler['permission_callback'] : null;

				if ( null === $permission ) {
					$missing[] = sprintf(
						/* translators: 1: REST route, 2: comma separated HTTP methods. */
						__( '%1$s accepts %2$s and names no permission callback at all', 'security-check-report' ),
						$route,
						implode( ', ', $writes )
					);
				} elseif ( '__return_true' === $permission ) {
					$public[] = sprintf(
						/* translators: 1: REST route, 2: comma separated HTTP methods. */
						__( '%1$s is registered as open to anyone for %2$s', 'security-check-report' ),
						$route,
						implode( ', ', $writes )
					);
				}
			}
		}

		$public  = array_values( array_unique( $public ) );
		$missing = array_values( array_unique( $missing ) );

		if ( empty( $public ) && empty( $missing ) ) {
			return CASCR_Result::pass( __( 'Every REST route that changes data decides who may call it.', 'security-check-report' ) );
		}

		// A route without any callback is a mistake WordPress itself complains
		// about. '__return_true' is the spelling the handbook prescribes for a
		// route that is meant to be open, so it is a question, not a verdict.
		if ( ! empty( $missing ) ) {
			return CASCR_Result::fail(
				sprintf(
					/* translators: %d: number of write routes without a permission callback. */
					_n(
						'%d REST route accepts changes without naming a permission callback.',
						'%d REST routes accept changes without naming a permission callback.',
						count( $missing ),
						'security-check-report'
					),
					count( $missing )
				),
				8,
				self::cap( array_merge( $missing, $public ) ),
				__( 'Since WordPress 5.5 every route has to name one. The route belongs to whichever plugin registered it, so report it to the author and remove the plugin until it is fixed.', 'security-check-report' )
			);
		}

		return CASCR_Result::warn(
			sprintf(
				/* translators: %d: number of write routes that are open on purpose. */
				_n(
					'%d REST route accepts changes from anyone who asks.',
					'%d REST routes accept changes from anyone who asks.',
					count( $public ),
					'security-check-report'
				),
				count( $public )
			),
			5,
			self::cap( $public ),
			__( 'Some routes are open on purpose and check the request inside the callback, a contact form or a shop cart for instance. Ask the plugin that registered the route whether this one is meant to be open, and remove the plugin until it is fixed if it is not.', 'security-check-report' )
		);
	}

	/**
	 * Is this a route that is unauthenticated on purpose?
	 *
	 * The batch endpoint has no callback of its own and checks permissions on
	 * each request it carries. The Store API serves a shop to visitors who are
	 * not logged in and authorises inside the callback. Reporting either would
	 * be a finding on an ordinary install and would teach people to skip past
	 * this check.
	 *
	 * @param string $route Registered route.
	 * @return bool
	 */
	private static function is_public_by_design( $route ) {
		foreach ( array( '/batch/v1', '/wc/store/v' ) as $prefix ) {
			if ( 0 === strpos( $route, $prefix ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Can the client address be faked?
	 *
	 * A forwarded header is only worth trusting when something in front of the
	 * site wrote it. From inside PHP the two cases look the same, so this check
	 * reports what it can prove and says so when it cannot prove anything.
	 *
	 * @return array
	 */
	public static function proxy_ip_configuration() {
		$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';

		// Under WP-CLI or cron there is no request to look at, and the friendly
		// branch below would report a clean result for a measurement that never
		// took place.
		if ( '' === $remote || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return CASCR_Result::inconclusive(
				__( 'This check reads the headers of the current request, and this run has none.', 'security-check-report' ),
				__( 'Open the report in the browser to have it checked.', 'security-check-report' )
			);
		}

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

		$is_private = ! filter_var(
			$remote,
			FILTER_VALIDATE_IP,
			FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
		);

		// A content delivery network connects from public addresses of its own,
		// so a private REMOTE_ADDR is not the only shape a correct setup takes.
		// An inbound CF-Connecting-IP together with a CF-Ray on the site's own
		// response is the one edge that can be confirmed from here.
		$behind_edge = ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) && '' !== self::header( CASCR_Http::home(), 'cf-ray' );

		if ( $is_private || $behind_edge ) {
			return CASCR_Result::pass(
				__( 'Forwarded address headers arrive from a proxy in front of the site, which is the expected setup.', 'security-check-report' ),
				$present
			);
		}

		return CASCR_Result::inconclusive(
			sprintf(
				/* translators: 1: comma separated list of forwarded address headers, 2: remote IP address of the current request. */
				__( 'Forwarded address headers arrive (%1$s) from %2$s, and a header written by a proxy looks the same from here as one a visitor sent along.', 'security-check-report' ),
				implode( ', ', $present ),
				$remote
			),
			__( 'If nothing sits in front of the site, have the security plugins read REMOTE_ADDR. If a proxy does, make sure it overwrites these headers rather than passing on whatever arrived.', 'security-check-report' )
		);
	}

	/**
	 * Splits a policy into directives, each one a list of its source tokens.
	 *
	 * Both the inline question and the wildcard question are about a single
	 * directive: a nonce in script-src says nothing about style-src, and a
	 * substring search over the whole header cannot tell the two apart.
	 *
	 * @param string $policy Policy header value.
	 * @return array<string, string[]> Source lists, keyed by directive name.
	 */
	private static function csp_directives( $policy ) {
		$directives = array();

		foreach ( explode( ';', strtolower( $policy ) ) as $part ) {
			$tokens = preg_split( '/\s+/', trim( $part ), -1, PREG_SPLIT_NO_EMPTY );

			if ( empty( $tokens ) ) {
				continue;
			}

			$name = array_shift( $tokens );

			$directives[ $name ] = $tokens;
		}

		return $directives;
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
