<?php
/**
 * Refusing a file by its name.
 *
 * @package   SugarCommerce\FileInspect
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\FileInspect;

/**
 * Class Filename
 *
 * The check that runs before an upload starts — a statement of intent, since
 * anybody can rename a file, but the cheapest refusal there is, made before a
 * byte has been stored.
 *
 * Every part of the name is checked, not just the last: a double extension
 * like `invoice.pdf.exe` is how the real one is hidden.
 */
final class Filename {

	/**
	 * Extensions that run on a double-click, or render as a page.
	 *
	 * A sensible default for a host that serves files to strangers. HTML and
	 * SVG are here because served from your own domain they execute script
	 * in your origin.
	 */
	public const EXECUTABLE = array(
		'exe', 'scr', 'bat', 'cmd', 'com', 'msi', 'dll', 'cpl', 'jar',
		'js', 'mjs', 'vbs', 'vbe', 'wsf', 'wsh', 'ps1', 'psm1',
		'sh', 'bash', 'zsh', 'app', 'dmg', 'pkg', 'deb', 'rpm', 'apk',
		'html', 'htm', 'svg', 'xhtml', 'phtml', 'php', 'php5', 'phar',
	);

	/**
	 * Why a filename is refused, or '' when it is acceptable.
	 *
	 * @since 1.0.0
	 *
	 * @param string   $filename The name as given.
	 * @param string[] $banned   Extensions refused anywhere in the name.
	 *
	 * @return string
	 */
	public static function refusal( string $filename, array $banned = self::EXECUTABLE ): string {
		$filename = trim( (string) preg_replace( '/[\x00-\x1f\x7f]/u', '', $filename ) );

		if ( '' === $filename ) {
			return 'A filename is required.';
		}

		foreach ( explode( '.', mb_strtolower( $filename ) ) as $part ) {
			if ( in_array( $part, $banned, true ) ) {
				return 'Files of type .' . $part . ' cannot be stored.';
			}
		}

		return '';
	}

	/**
	 * The extension, lower-cased, without the dot.
	 *
	 * @since 1.0.0
	 *
	 * @param string $filename The name.
	 *
	 * @return string
	 */
	public static function extension( string $filename ): string {
		return mb_strtolower( (string) pathinfo( $filename, PATHINFO_EXTENSION ) );
	}
}
