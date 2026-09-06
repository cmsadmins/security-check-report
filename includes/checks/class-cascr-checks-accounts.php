<?php
/**
 * Checks for accounts, roles and authentication.
 *
 * @package CmsAdmins\SecurityCheck
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Account and access checks.
 */
class CASCR_Checks_Accounts extends CASCR_Checks_Base {

	/**
	 * User meta key holding the last login timestamp.
	 */
	const META_LAST_LOGIN = 'cascr_last_login';

	/**
	 * Roles whose accounts can publish, install or administer.
	 *
	 * @var string[]
	 */
	private static $privileged_roles = array( 'administrator', 'editor', 'author', 'shop_manager' );

	/**
	 * Capabilities that turn an account into an administrator in all but name.
	 *
	 * @var string[]
	 */
	private static $escalation_caps = array(
		'edit_files',
		'edit_plugins',
		'edit_themes',
		'install_plugins',
		'install_themes',
		'update_plugins',
		'update_themes',
		'update_core',
		'manage_options',
		'promote_users',
		'edit_users',
		'create_users',
		'delete_users',
		'activate_plugins',
	);

	/**
	 * Accounts that can publish, install or administer.
	 *
	 * On multisite, network administrators hold every capability regardless of
	 * their role on the current site, so a role query alone would miss them.
	 *
	 * @param bool $admins_only Restrict to accounts that can administer.
	 * @return WP_User[]
	 */
	private static function privileged_users( $admins_only = false ) {
		$args = $admins_only
			? array( 'role' => 'administrator' )
			: array( 'role__in' => self::$privileged_roles );

		$ids = get_users(
			array_merge(
				$args,
				array(
					'number' => 200,
					'fields' => 'ID',
				)
			)
		);
		$ids = array_map( 'intval', $ids );

		if ( is_multisite() ) {
			foreach ( get_super_admins() as $login ) {
				$super = get_user_by( 'login', $login );

				if ( $super ) {
					$ids[] = (int) $super->ID;
				}
			}
		}

		$users = array();

		foreach ( array_unique( $ids ) as $id ) {
			$user = get_user_by( 'id', $id );

			if ( $user ) {
				$users[] = $user;
			}
		}

		return $users;
	}

	/**
	 * Do any privileged accounts use a guessable password?
	 *
	 * Hashes are compared against a list. No login attempt is made, so this
	 * leaves no trace in the login log and triggers no lockout.
	 *
	 * @return array
	 */
	public static function weak_password_users() {
		$passwords = self::config( 'weak_passwords' );

		if ( empty( $passwords ) ) {
			return CASCR_Result::inconclusive( __( 'The password list could not be loaded.', 'security-check-report' ) );
		}

		$users = self::privileged_users();

		if ( empty( $users ) ) {
			return CASCR_Result::pass( __( 'No privileged accounts were found.', 'security-check-report' ) );
		}

		$weak = array();

		foreach ( $users as $user ) {
			$candidates = array_merge(
				$passwords,
				array(
					$user->user_login,
					$user->user_login . '1',
					$user->user_login . '123',
					$user->user_login . '!',
				)
			);

			foreach ( $candidates as $candidate ) {
				if ( wp_check_password( $candidate, $user->user_pass, $user->ID ) ) {
					$weak[] = $user->user_login;
					break;
				}
			}
		}

		if ( empty( $weak ) ) {
			return CASCR_Result::pass(
				sprintf(
					/* translators: %d: number of accounts checked. */
					_n(
						'The %d privileged account does not use a password from the common list.',
						'None of the %d privileged accounts uses a password from the common list.',
						count( $users ),
						'security-check-report'
					),
					count( $users )
				)
			);
		}

		$count = count( $weak );

		return CASCR_Result::fail(
			sprintf(
				/* translators: %d: number of accounts with a guessable password. */
				_n(
					'%d privileged account uses a guessable password.',
					'%d privileged accounts use guessable passwords.',
					$count,
					'security-check-report'
				),
				$count
			),
			$count > 3 ? 10 : ( $count > 1 ? 9 : 8 ),
			self::cap( $weak ),
			__( 'Reset those passwords now and check the account activity afterwards.', 'security-check-report' )
		);
	}

	/**
	 * Does a predictable administrator name exist?
	 *
	 * @return array
	 */
	public static function admin_username() {
		$found = array();

		foreach ( array( 'admin', 'administrator', 'root', 'test', 'wordpress' ) as $login ) {
			$user = get_user_by( 'login', $login );

			if ( $user && user_can( $user, 'manage_options' ) ) {
				$found[] = $login;
			}
		}

		if ( empty( $found ) ) {
			return CASCR_Result::pass( __( 'No administrator uses a predictable login name.', 'security-check-report' ) );
		}

		return CASCR_Result::fail(
			__( 'An administrator account uses a name that every password guesser tries first.', 'security-check-report' ),
			8,
			$found,
			__( 'Create a new administrator with a different name, move the content over and delete the old account.', 'security-check-report' )
		);
	}

	/**
	 * How many administrators are there, and are they all still in use?
	 *
	 * @return array
	 */
	public static function admin_account_hygiene() {
		$admins = self::privileged_users( true );

		$count    = count( $admins );
		$findings = array();
		$score    = 0;

		if ( $count > 5 ) {
			$findings[] = sprintf(
				/* translators: %d: number of administrator accounts. */
				__( '%d accounts hold administrator rights', 'security-check-report' ),
				$count
			);
			$score = 5;
		}

		$user_one = get_user_by( 'id', 1 );
		if ( $user_one && user_can( $user_one, 'manage_options' ) ) {
			$findings[] = __( 'the account with ID 1 is an administrator, which is the first ID anyone tries', 'security-check-report' );
			$score      = max( $score, 4 );
		}

		$dormant = array();
		foreach ( $admins as $admin ) {
			$last = (int) get_user_meta( $admin->ID, self::META_LAST_LOGIN, true );

			if ( $last > 0 && ( time() - $last ) > YEAR_IN_SECONDS ) {
				$dormant[] = sprintf(
					/* translators: 1: user login, 2: human readable time since the last login. */
					__( '%1$s last signed in %2$s ago', 'security-check-report' ),
					$admin->user_login,
					human_time_diff( $last, time() )
				);
			}
		}

		if ( ! empty( $dormant ) ) {
			$findings = array_merge( $findings, $dormant );
			$score    = max( $score, 6 );
		}

		if ( empty( $findings ) ) {
			return CASCR_Result::pass(
				sprintf(
					/* translators: %d: number of administrator accounts. */
					_n(
						'%d account holds administrator rights.',
						'%d accounts hold administrator rights.',
						$count,
						'security-check-report'
					),
					$count
				)
			);
		}

		return CASCR_Result::warn(
			__( 'The set of administrator accounts is worth reviewing.', 'security-check-report' ),
			$score,
			self::cap( $findings ),
			__( 'Give people the lowest role that lets them do their work, and remove accounts that are no longer used.', 'security-check-report' )
		);
	}

	/**
	 * Do any non-administrator roles hold administrator-level capabilities?
	 *
	 * @return array
	 */
	public static function role_capability_drift() {
		$roles = wp_roles();

		if ( ! $roles instanceof WP_Roles ) {
			return CASCR_Result::inconclusive( __( 'The role definitions could not be read.', 'security-check-report' ) );
		}

		$findings = array();
		$snapshot = array();

		foreach ( $roles->roles as $slug => $role ) {
			$caps = isset( $role['capabilities'] ) ? array_keys( array_filter( $role['capabilities'] ) ) : array();
			sort( $caps );
			$snapshot[ $slug ] = md5( implode( ',', $caps ) );

			if ( 'administrator' === $slug ) {
				continue;
			}

			$escalation = array_intersect( self::$escalation_caps, $caps );

			if ( ! empty( $escalation ) ) {
				$findings[] = sprintf(
					/* translators: 1: role name, 2: comma separated capability names. */
					__( 'the role %1$s holds %2$s', 'security-check-report' ),
					isset( $role['name'] ) ? $role['name'] : $slug,
					implode( ', ', $escalation )
				);
			}

			if ( in_array( $slug, array( 'subscriber', 'contributor' ), true ) && in_array( 'unfiltered_html', $caps, true ) ) {
				$findings[] = sprintf(
					/* translators: %s: role name. */
					__( 'the role %s may post unfiltered HTML', 'security-check-report' ),
					isset( $role['name'] ) ? $role['name'] : $slug
				);
			}
		}

		if ( ! CASCR_Store::remember( 'roles', $snapshot ) ) {
			$baseline = CASCR_Store::baseline( 'roles', array() );

			foreach ( $snapshot as $slug => $hash ) {
				if ( ! isset( $baseline[ $slug ] ) ) {
					$findings[] = sprintf(
						/* translators: %s: role slug. */
						__( 'the role %s was added after the first scan', 'security-check-report' ),
						$slug
					);
				} elseif ( $baseline[ $slug ] !== $hash ) {
					$findings[] = sprintf(
						/* translators: %s: role slug. */
						__( 'the capabilities of the role %s changed after the first scan', 'security-check-report' ),
						$slug
					);
				}
			}
		}

		if ( empty( $findings ) ) {
			return CASCR_Result::pass( __( 'No role below administrator holds administrator-level capabilities.', 'security-check-report' ) );
		}

		return CASCR_Result::fail(
			__( 'Roles below administrator hold capabilities that amount to full control.', 'security-check-report' ),
			9,
			self::cap( $findings ),
			__( 'Some plugins add these on purpose. Anything you cannot account for should be removed.', 'security-check-report' )
		);
	}

	/**
	 * Can anyone register, and what do they get when they do?
	 *
	 * @return array
	 */
	public static function open_registration() {
		// On multisite the per-site option is ignored: registration is a
		// network setting. Reading users_can_register there would report
		// "closed" on a network that lets anyone sign up.
		if ( is_multisite() ) {
			return self::network_registration();
		}

		if ( ! get_option( 'users_can_register' ) ) {
			return CASCR_Result::pass( __( 'Registration is closed.', 'security-check-report' ) );
		}

		$role   = get_option( 'default_role' );
		$object = get_role( $role );
		$caps   = $object ? array_keys( array_filter( $object->capabilities ) ) : array();

		$dangerous = array_intersect( self::$escalation_caps, $caps );

		if ( ! empty( $dangerous ) ) {
			return CASCR_Result::fail(
				sprintf(
					/* translators: %s: name of the default role for new accounts. */
					__( 'Anyone can register and immediately receives the role %s, which carries administrator-level capabilities.', 'security-check-report' ),
					$role
				),
				10,
				$dangerous,
				__( 'Set the default role to Subscriber under Settings, General.', 'security-check-report' )
			);
		}

		if ( in_array( $role, array( 'author', 'editor' ), true ) || in_array( 'publish_posts', $caps, true ) ) {
			return CASCR_Result::fail(
				sprintf(
					/* translators: %s: name of the default role for new accounts. */
					__( 'Anyone can register and immediately receives the role %s, which may publish.', 'security-check-report' ),
					$role
				),
				8,
				array(),
				__( 'Set the default role to Subscriber under Settings, General.', 'security-check-report' )
			);
		}

		return CASCR_Result::warn(
			sprintf(
				/* translators: %s: name of the default role for new accounts. */
				__( 'Registration is open. New accounts receive the role %s.', 'security-check-report' ),
				$role
			),
			4,
			array(),
			__( 'If the site does not need public accounts, switch registration off under Settings, General.', 'security-check-report' )
		);
	}

	/**
	 * Do the administrators have a second factor?
	 *
	 * @return array
	 */
	public static function two_factor_coverage() {
		$plugins = self::active_from_list( 'two_factor_plugins' );

		$admins = self::privileged_users( true );

		if ( empty( $plugins ) ) {
			return CASCR_Result::fail(
				__( 'No second factor is available, so a stolen password is enough to reach the dashboard.', 'security-check-report' ),
				9,
				array(),
				__( 'Install a two-factor plugin and require it at least for administrators. Two Factor, maintained by the WordPress core team, is a solid free choice. ReportedIP Hive, which we build ourselves, covers TOTP, email and passkeys alongside its login protection.', 'security-check-report' ),
				self::hive_link()
			);
		}

		$meta_keys = array(
			'_two_factor_enabled_providers',
			'wp_2fa_totp_key',
			'wp_2fa_enabled_methods',
			'itsec_two_factor_enabled_providers',
		);

		$without  = array();
		$readable = false;

		foreach ( $admins as $admin ) {
			$has = false;

			foreach ( $meta_keys as $key ) {
				$value = get_user_meta( $admin->ID, $key, true );

				if ( ! empty( $value ) ) {
					$has      = true;
					$readable = true;
					break;
				}
			}

			if ( ! $has ) {
				$without[] = $admin->user_login;
			}
		}

		if ( ! $readable ) {
			// A second factor is available but this plugin cannot see who uses
			// it. Saying nothing is better than guessing either way.
			return CASCR_Result::inconclusive(
				__( 'A two-factor plugin is active, but which accounts use it cannot be read from here.', 'security-check-report' ),
				__( 'Check the coverage in the plugin itself.', 'security-check-report' )
			);
		}

		if ( empty( $without ) ) {
			return CASCR_Result::pass( __( 'Every administrator has a second factor.', 'security-check-report' ), $plugins );
		}

		return CASCR_Result::fail(
			sprintf(
				/* translators: %d: number of administrators without a second factor. */
				_n(
					'%d administrator has no second factor.',
					'%d administrators have no second factor.',
					count( $without ),
					'security-check-report'
				),
				count( $without )
			),
			8,
			self::cap( $without ),
			__( 'Set up the second factor for those accounts, or require it for the administrator role.', 'security-check-report' )
		);
	}

	/**
	 * Our own plugin, offered as one option among others.
	 *
	 * Named openly as ours in the remediation text above, so a reader can weigh
	 * the recommendation for what it is. The free alternative is named first.
	 *
	 * @return array
	 */
	private static function hive_link() {
		return array(
			'url'   => 'https://reportedip.com/products/wordpress-plugin/',
			'label' => __( 'ReportedIP Hive, our own plugin with TOTP, email and passkeys', 'security-check-report' ),
		);
	}

	/**
	 * Which application passwords exist, and are any of them forgotten?
	 *
	 * Application passwords bypass the second factor, which makes them the
	 * quietest way to keep access to a site after a break-in. Whether the
	 * feature is switched on matters far less than what is actually issued.
	 *
	 * @return array
	 */
	public static function application_password_inventory() {
		if ( ! class_exists( 'WP_Application_Passwords' ) ) {
			return CASCR_Result::pass( __( 'This WordPress version has no application passwords.', 'security-check-report' ) );
		}

		if ( function_exists( 'wp_is_application_passwords_available' ) && ! wp_is_application_passwords_available() ) {
			return CASCR_Result::pass( __( 'Application passwords are switched off on this site.', 'security-check-report' ) );
		}

		$users = self::privileged_users();

		$all    = array();
		$stale  = array();
		$cutoff = time() - 90 * DAY_IN_SECONDS;

		foreach ( $users as $user ) {
			$passwords = WP_Application_Passwords::get_user_application_passwords( $user->ID );

			if ( empty( $passwords ) ) {
				continue;
			}

			foreach ( $passwords as $password ) {
				$name    = isset( $password['name'] ) ? $password['name'] : __( 'no name', 'security-check-report' );
				$created = isset( $password['created'] ) ? (int) $password['created'] : 0;
				$used    = isset( $password['last_used'] ) ? (int) $password['last_used'] : 0;
				$last_ip = ! empty( $password['last_ip'] ) ? $password['last_ip'] : __( 'never used', 'security-check-report' );

				$entry = sprintf(
					/* translators: 1: user login, 2: application password name, 3: creation date, 4: last use. */
					__( '%1$s, "%2$s", created %3$s, %4$s', 'security-check-report' ),
					$user->user_login,
					$name,
					$created ? date_i18n( get_option( 'date_format' ), $created ) : __( 'unknown', 'security-check-report' ),
					$used
						? sprintf(
							/* translators: 1: human readable time since last use, 2: IP address. */
							__( 'last used %1$s ago from %2$s', 'security-check-report' ),
							human_time_diff( $used, time() ),
							$last_ip
						)
						: __( 'never used', 'security-check-report' )
				);

				$all[] = $entry;

				if ( 0 === $used && $created > 0 && $created < $cutoff ) {
					$stale[] = $entry;
				} elseif ( $used > 0 && $used < $cutoff ) {
					$stale[] = $entry;
				}
			}
		}

		if ( empty( $all ) ) {
			return CASCR_Result::pass( __( 'No application passwords are in use by privileged accounts.', 'security-check-report' ) );
		}

		if ( empty( $stale ) ) {
			return CASCR_Result::info(
				sprintf(
					/* translators: %d: number of application passwords in use. */
					_n(
						'%d application password is in use and was used recently.',
						'%d application passwords are in use and were used recently.',
						count( $all ),
						'security-check-report'
					),
					count( $all )
				),
				self::cap( $all )
			);
		}

		return CASCR_Result::warn(
			sprintf(
				/* translators: %d: number of forgotten application passwords. */
				_n(
					'%d application password has not been used in months.',
					'%d application passwords have not been used in months.',
					count( $stale ),
					'security-check-report'
				),
				count( $stale )
			),
			6,
			self::cap( $stale ),
			__( 'Revoke what is no longer needed. These credentials skip the second factor.', 'security-check-report' )
		);
	}

	/**
	 * What the network allows people to sign up for.
	 *
	 * @return array
	 */
	private static function network_registration() {
		$setting = get_site_option( 'registration', 'none' );

		if ( 'none' === $setting ) {
			return CASCR_Result::pass( __( 'Network registration is closed.', 'security-check-report' ) );
		}

		$open = array(
			'user' => __( 'anyone can create an account', 'security-check-report' ),
			'blog' => __( 'existing accounts can create new sites', 'security-check-report' ),
			'all'  => __( 'anyone can create an account and a new site', 'security-check-report' ),
		);

		$items = array( isset( $open[ $setting ] ) ? $open[ $setting ] : $setting );

		$role = get_option( 'default_role' );
		$caps = get_role( $role ) ? array_keys( array_filter( get_role( $role )->capabilities ) ) : array();

		$dangerous = array_intersect( self::$escalation_caps, $caps );

		if ( ! empty( $dangerous ) ) {
			return CASCR_Result::fail(
				sprintf(
					/* translators: %s: name of the default role for new accounts. */
					__( 'Network registration is open and new accounts receive the role %s on this site, which carries administrator-level capabilities.', 'security-check-report' ),
					$role
				),
				10,
				array_merge( $items, $dangerous ),
				__( 'Under Network Admin, Settings, set registration to none, or lower the default role of this site.', 'security-check-report' )
			);
		}

		return CASCR_Result::warn(
			sprintf(
				/* translators: %s: name of the default role for new accounts. */
				__( 'Network registration is open. New accounts receive the role %s on this site.', 'security-check-report' ),
				$role
			),
			4,
			$items,
			__( 'If the network does not need public sign-ups, set registration to none under Network Admin, Settings.', 'security-check-report' )
		);
	}

	/**
	 * Records the moment an account signs in.
	 *
	 * WordPress keeps no login history of its own, so the dormant-account part
	 * of admin_account_hygiene only sees logins from the moment this plugin was
	 * installed. That is stated in the report rather than guessed at.
	 *
	 * @param string $login User login name.
	 * @param mixed  $user  User object.
	 */
	public static function record_login( $login, $user = null ) {
		if ( $user instanceof WP_User ) {
			update_user_meta( $user->ID, self::META_LAST_LOGIN, time() );
		}
	}
}
