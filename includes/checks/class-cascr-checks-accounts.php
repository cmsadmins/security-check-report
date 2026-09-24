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
	 * How many accounts a single user query returns at most.
	 */
	const USER_QUERY_LIMIT = 200;

	/**
	 * Whether the last privileged_users() call ran into that limit.
	 *
	 * A site with more privileged accounts than the limit gets an answer about
	 * the first few hundred of them. Saying so is the difference between a
	 * result and a result that looks like the whole picture.
	 *
	 * @var bool
	 */
	private static $user_query_capped = false;

	/**
	 * Meta values that mean the second factor is off rather than set up.
	 *
	 * Google Authenticator stores the string "disabled", which is not empty,
	 * so an emptiness test reads it as protection.
	 *
	 * @var string[]
	 */
	private static $factor_off_values = array( '', '0', 'disabled', 'off', 'none' );

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
					'number' => self::USER_QUERY_LIMIT,
					'fields' => 'ID',
				)
			)
		);

		self::$user_query_capped = count( $ids ) >= self::USER_QUERY_LIMIT;

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
	 * Sentence to append when the account query hit its limit.
	 *
	 * @return string Empty string when every privileged account was seen.
	 */
	private static function query_limit_note() {
		if ( ! self::$user_query_capped ) {
			return '';
		}

		return ' ' . sprintf(
			/* translators: %d: maximum number of accounts a single query returns. */
			__( 'This site has more privileged accounts than one query returns, so only the first %d were looked at.', 'security-check-report' ),
			self::USER_QUERY_LIMIT
		);
	}

	/**
	 * Translated name of a role, falling back to its slug.
	 *
	 * The slug is what WordPress stores and what nobody recognises: the
	 * settings screen offers "Subscriber", not "subscriber".
	 *
	 * @param string $slug Role slug.
	 * @return string
	 */
	private static function role_name( $slug ) {
		$roles = wp_roles();

		if ( $roles instanceof WP_Roles ) {
			$names = $roles->get_names();

			if ( isset( $names[ $slug ] ) ) {
				return translate_user_role( $names[ $slug ] );
			}
		}

		return (string) $slug;
	}

	/**
	 * Does a meta value mean the account actually has a second factor?
	 *
	 * Plugins write an off state as often as they delete the meta, and every
	 * one of those values survives an emptiness test.
	 *
	 * @param mixed $value Stored meta value.
	 * @return bool
	 */
	private static function factor_is_set( $value ) {
		if ( is_array( $value ) ) {
			foreach ( $value as $entry ) {
				if ( self::factor_is_set( $entry ) ) {
					return true;
				}
			}

			return false;
		}

		// A stored object is whatever the plugin serialised; there is no off
		// value to recognise in it, so its presence has to count.
		if ( is_object( $value ) ) {
			return true;
		}

		return ! in_array( strtolower( trim( (string) $value ) ), self::$factor_off_values, true );
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
				) . self::query_limit_note()
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
		$summary  = array();
		$score    = 0;

		if ( $count > 5 ) {
			$summary[] = sprintf(
				/* translators: %d: number of administrator accounts. */
				_n(
					'%d account holds administrator rights.',
					'%d accounts hold administrator rights.',
					$count,
					'security-check-report'
				),
				$count
			);

			$findings[] = sprintf(
				/* translators: %d: number of administrator accounts. */
				_n(
					'%d account holds administrator rights',
					'%d accounts hold administrator rights',
					$count,
					'security-check-report'
				),
				$count
			);
			$score = 5;
		}

		$user_one = get_user_by( 'id', 1 );
		if ( $user_one && user_can( $user_one, 'manage_options' ) ) {
			$summary[]  = __( 'The account with ID 1 is an administrator.', 'security-check-report' );
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
			$summary[] = sprintf(
				/* translators: %d: number of administrator accounts that have not signed in for over a year. */
				_n(
					'%d administrator has not signed in for over a year.',
					'%d administrators have not signed in for over a year.',
					count( $dormant ),
					'security-check-report'
				),
				count( $dormant )
			);

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

		// The summary carries the finding itself, because the list below it is
		// only visible once the row is opened and the exports and the command
		// line show this sentence on its own.
		return CASCR_Result::warn(
			implode( ' ', $summary ),
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
		$drift    = array();
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
					$drift[] = sprintf(
						/* translators: %s: role slug. */
						__( 'the role %s was added after the first scan', 'security-check-report' ),
						$slug
					);
				} elseif ( $baseline[ $slug ] !== $hash ) {
					$drift[] = sprintf(
						/* translators: %s: role slug. */
						__( 'the capabilities of the role %s changed after the first scan', 'security-check-report' ),
						$slug
					);
				}
			}
		}

		// Two questions share this check, and only one of them is an
		// escalation. Installing a shop or a membership plugin adds roles, and
		// reporting that as full control below administrator says more than
		// the list underneath it can support.
		if ( ! empty( $findings ) ) {
			return CASCR_Result::fail(
				__( 'Roles below administrator hold capabilities that amount to full control.', 'security-check-report' ),
				9,
				self::cap( array_merge( $findings, $drift ) ),
				__( 'Some plugins add these on purpose. Anything you cannot account for should be removed.', 'security-check-report' )
			);
		}

		if ( ! empty( $drift ) ) {
			return CASCR_Result::warn(
				__( 'The role definitions changed since the first scan, but no role below administrator gained administrator-level capabilities.', 'security-check-report' ),
				5,
				self::cap( $drift ),
				__( 'Plugins add and adjust roles when they are installed. Match the list against what was installed, and remove what nobody asked for.', 'security-check-report' )
			);
		}

		return CASCR_Result::pass( __( 'No role below administrator holds administrator-level capabilities.', 'security-check-report' ) );
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
		$label  = self::role_name( $role );

		$dangerous = array_intersect( self::$escalation_caps, $caps );

		if ( ! empty( $dangerous ) ) {
			return CASCR_Result::fail(
				sprintf(
					/* translators: %s: name of the default role for new accounts. */
					__( 'Anyone can register and immediately receives the role %s, which carries administrator-level capabilities.', 'security-check-report' ),
					$label
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
					$label
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
				$label
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
		$plugins   = self::active_from_map( 'two_factor_plugins' );
		$meta_keys = array();

		foreach ( $plugins as $keys ) {
			$meta_keys = array_merge( $meta_keys, $keys );
		}

		$meta_keys = array_unique( $meta_keys );

		$admins = self::privileged_users( true );

		if ( empty( $plugins ) ) {
			return CASCR_Result::fail(
				__( 'No second factor is available, so a stolen password is enough to reach the dashboard.', 'security-check-report' ),
				9,
				array(),
				__( 'Install a two-factor plugin and require it at least for administrators. Two Factor is a widely used free plugin kept up by WordPress contributors and is a solid choice. ReportedIP Hive, which we build ourselves, covers TOTP, email and passkeys in its Full Edition; the copy in the plugin directory is Hive Light and brings login protection only.', 'security-check-report' ),
				self::hive_link()
			);
		}

		if ( empty( $meta_keys ) ) {
			// Something adds a second factor, but none of the active plugins
			// stores its state where this check can read it. Saying nothing is
			// better than guessing either way.
			return CASCR_Result::inconclusive(
				__( 'A two-factor plugin is active, but which accounts use it cannot be read from here.', 'security-check-report' ),
				__( 'Check the coverage in the plugin itself.', 'security-check-report' )
			);
		}

		$without = array();

		foreach ( $admins as $admin ) {
			$has = false;

			foreach ( $meta_keys as $key ) {
				$value = get_user_meta( $admin->ID, $key, true );

				if ( self::factor_is_set( $value ) ) {
					$has = true;
					break;
				}
			}

			if ( ! $has ) {
				$without[] = $admin->user_login;
			}
		}

		if ( empty( $without ) ) {
			return CASCR_Result::pass( __( 'Every administrator has a second factor.', 'security-check-report' ), array_keys( $plugins ) );
		}

		if ( count( $without ) === count( $admins ) ) {
			// The plugin is installed and nobody finished the setup, which is
			// the same exposure as having no second factor at all. Earlier
			// versions read that silence as "cannot tell" and stayed quiet.
			return CASCR_Result::fail(
				__( 'A two-factor plugin is active, but no administrator has set the second factor up.', 'security-check-report' ),
				9,
				self::cap( $without ),
				__( 'Finish the setup for every administrator and require the second factor for the role. ReportedIP Hive, which we build ourselves, enforces it per role in its Full Edition; the copy in the plugin directory is Hive Light and brings login protection only.', 'security-check-report' ),
				self::hive_link()
			);
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
			'label' => __( 'ReportedIP Hive, our own plugin: TOTP, email and passkeys are in the Full Edition', 'security-check-report' ),
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

		// WordPress refuses application passwords over plain HTTP, so on such a
		// site this says nothing about whether anyone switched them off, and
		// the ones already issued stay in the database either way.
		if ( function_exists( 'wp_is_application_passwords_available' ) && ! wp_is_application_passwords_available() ) {
			return CASCR_Result::inconclusive(
				__( 'Application passwords are unavailable here. WordPress requires HTTPS for them, so whether they were switched off deliberately cannot be told apart from that, and passwords issued earlier are not listed.', 'security-check-report' ),
				__( 'Serve the site over HTTPS and run the check again. Until then, review the existing application passwords in each user profile.', 'security-check-report' )
			);
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
			return CASCR_Result::pass( __( 'No application passwords are in use by privileged accounts.', 'security-check-report' ) . self::query_limit_note() );
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
				) . self::query_limit_note(),
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

		$role  = get_option( 'default_role' );
		$label = self::role_name( $role );
		$caps  = get_role( $role ) ? array_keys( array_filter( get_role( $role )->capabilities ) ) : array();

		$dangerous = array_intersect( self::$escalation_caps, $caps );

		if ( ! empty( $dangerous ) ) {
			return CASCR_Result::fail(
				sprintf(
					/* translators: %s: name of the default role for new accounts. */
					__( 'Network registration is open and new accounts receive the role %s on this site, which carries administrator-level capabilities.', 'security-check-report' ),
					$label
				),
				10,
				array_merge( $items, $dangerous ),
				__( 'Under Network Admin, Settings, Registration Settings, choose "Registration is disabled", or lower the default role of this site.', 'security-check-report' )
			);
		}

		return CASCR_Result::warn(
			sprintf(
				/* translators: %s: name of the default role for new accounts. */
				__( 'Network registration is open. New accounts receive the role %s on this site.', 'security-check-report' ),
				$label
			),
			4,
			$items,
			__( 'If the network does not need public sign-ups, choose "Registration is disabled" under Network Admin, Settings, Registration Settings.', 'security-check-report' )
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
