<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the installation.
 * You don't have to use the website, you can copy this file to "wp-config.php"
 * and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * Database settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://developer.wordpress.org/advanced-administration/wordpress/wp-config/
 *
 * @package WordPress
 */

// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** Database username */
define( 'DB_USER', 'wp_user' );

/** Database password */
define( 'DB_PASSWORD', 'IAMsoSTRONG25-26' );

/** Database hostname */
define( 'DB_HOST', 'localhost' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

/**#@+
 * Authentication unique keys and salts.
 *
 * Change these to different unique phrases! You can generate these using
 * the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}.
 *
 * You can change these at any point in time to invalidate all existing cookies.
 * This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define( 'AUTH_KEY',         'H%5p/&fQssD.-kw|)O~3$!Oa6`ZNmm{ Sd.fXk|Z[KETlw4s!^XNr|Mi7er]/P4t' );
define( 'SECURE_AUTH_KEY',  'LdaZCei+j.ilxKk|yBahg(=[~8*[-nrmlyVlVQ+z@${3:!bIv4UE#h[.AiH4%Eq]' );
define( 'LOGGED_IN_KEY',    'qo8Vs3-1/`Mdk_%@Z*9|/SD&i1nGX<y8qP}OK<ynGM}iFo_9t{d%9&Xk>TKFG0!%' );
define( 'NONCE_KEY',        'jn<~W^y^6Un,:wn.W;unOLdz/t;{4Dc!.{,09jyoHW;<`.+<ZAm}0^]0Trf3[(3X' );
define( 'AUTH_SALT',        '5%R[:6n-WT]8K^_I+iV3=&noe~*7r%XU@Fe)>gQ0B_*E2K<WO}1pMJ^Os[r!+D}(' );
define( 'SECURE_AUTH_SALT', ',aUV>?gsnwq3diIls%2b,4/8+CWW+K>-92YUWh(rnH^cT4PY.,?gg6aC__R%RDG&' );
define( 'LOGGED_IN_SALT',   'm_o,3Z8Z.7.Xb:PU2Y>BKb*LeGm4/wOMsZ7;p98;z4j6(B-&TcN&E>*cw%ho3lQ<' );
define( 'NONCE_SALT',       'G#k:PN?l]Bt]e4$llJ=A7V05AERrcl9YA(,$2BUGLeh|;9jxtNA<D3!y0X]e:LBH' );

/**#@-*/

/**
 * WordPress database table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 *
 * At the installation time, database tables are created with the specified prefix.
 * Changing this value after WordPress is installed will make your site think
 * it has not been installed.
 *
 * @link https://developer.wordpress.org/advanced-administration/wordpress/wp-config/#table-prefix
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the documentation.
 *
 * @link https://developer.wordpress.org/advanced-administration/debug/debug-wordpress/
 */
define( 'WP_DEBUG', true );
define( 'WP_DEBUG_LOG', true );
define( 'WP_DEBUG_DISPLAY', false );


define('WP_HOME', 'http://wonderful-stuff.store');
define('WP_SITEURL', 'http://wonderful-stuff.store');



define('WP_LOGIN_FILE', 'real-secret-login.php');

/* Add any custom values between this line and the "stop editing" line. */



/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
