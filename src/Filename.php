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
	 * in your origin; the PHP variants and `.htaccess` because an upload
	 * that lands under a web root can be executed or reconfigure it.
	 *
	 * @var list<string>
	 */
	public const array EXECUTABLE = array(
		'exe', 'scr', 'bat', 'cmd', 'com', 'msi', 'msp', 'dll', 'cpl', 'jar',
		'pif', 'hta', 'lnk', 'reg', 'scf',
		'js', 'jse', 'mjs', 'vbs', 'vbe', 'wsf', 'wsh', 'ps1', 'psm1',
		'sh', 'bash', 'zsh', 'app', 'dmg', 'pkg', 'deb', 'rpm', 'apk',
		'html', 'htm', 'shtml', 'svg', 'svgz', 'xhtml', 'xht', 'xhtm', 'mht', 'mhtml',
		'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phps', 'pht', 'phtm', 'phtml', 'phar',
		'htaccess',
	);

	/**
	 * Characters that are invisible, or that change the order the rest of a
	 * name is displayed in: zero-width characters, direction marks,
	 * embeddings, overrides and isolates, and the byte order mark.
	 *
	 * `Invoice\u{202E}fdp.exe` displays as `Invoiceexe.pdf`.
	 */
	private const string INVISIBLE = '[\x{061C}\x{180E}\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2069}\x{FEFF}]';

	/**
	 * The subset of {@see self::INVISIBLE} that reorders what follows it —
	 * embeddings, overrides and isolates. A filename has no honest use for
	 * one.
	 */
	private const string REORDERING = '[\x{202A}-\x{202E}\x{2066}-\x{2069}]';

	/**
	 * Names Windows reserves for devices, with or without an extension. A
	 * file called `CON.wav` cannot be saved there at all.
	 */
	private const string RESERVED = '/^(CON|PRN|AUX|NUL|COM[0-9¹²³]|LPT[0-9¹²³])(?=\.|$)/iu';

	/**
	 * Why a filename is refused, or '' when it is acceptable.
	 *
	 * Each part between dots is compared with its surrounding whitespace
	 * removed, since Windows drops trailing dots and spaces when it saves
	 * a file — `setup.exe .` is saved as `setup.exe`. A colon separates a
	 * part too, because on NTFS `setup.exe:x` is a stream of `setup.exe`.
	 * A name carrying a direction override or isolate is refused outright:
	 * it displays as something other than what it is.
	 *
	 * @since 1.0.0
	 *
	 * @param string        $filename The name as given.
	 * @param array<string> $banned   Extensions refused anywhere in the name,
	 *                                in any case.
	 *
	 * @return string
	 */
	public static function refusal( string $filename, array $banned = self::EXECUTABLE ): string {
		$filename = trim( (string) preg_replace( '/[\x00-\x1f\x7f]/u', '', $filename ) );

		if ( '' === $filename ) {
			return 'A filename is required.';
		}

		if ( 1 === preg_match( '/' . self::REORDERING . '/u', $filename ) ) {
			return 'The filename contains characters that change how it is displayed.';
		}

		$visible = (string) preg_replace( '/' . self::INVISIBLE . '/u', '', mb_strtolower( $filename ) );
		$banned  = array_map( mb_strtolower( ... ), $banned );

		foreach ( preg_split( '/[.:]/', $visible ) ?: array() as $part ) {
			$part = (string) preg_replace( '/^[\s\p{Z}]+|[\s\p{Z}]+$/u', '', $part );

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

	/**
	 * The name a stored file ends up with when somebody renames it, or ''
	 * when what they typed will not do.
	 *
	 * The extension is kept whatever is typed. The file was inspected under
	 * it, previews and players decide from it, and the computer it is
	 * downloaded to opens it by it — so a rename from `.wav` to `.exe` would
	 * be a different file as far as all three are concerned. Typing the
	 * extension anyway is harmless: it is not doubled.
	 *
	 * What is typed is cleaned the way a filename needs:
	 *
	 *   - control characters, zero-width characters, direction marks,
	 *     overrides and isolates go — `Invoice\u{202E}fdp.exe` displays as
	 *     `Invoiceexe.pdf`, and is how a name is made to lie about its
	 *     extension;
	 *   - runs of whitespace become one space;
	 *   - slashes and backslashes become hyphens, because a name with a
	 *     separator in it is a path to some unzip tools and save dialogs, and
	 *     so do the other characters Windows will not save (`: * ? " < > |`);
	 *   - leading and trailing dots and spaces go: a leading dot hides a file,
	 *     and Windows drops a trailing one;
	 *   - a name Windows reserves for a device (`CON`, `NUL`, `COM1` …) gets
	 *     an underscore, since it could not be saved there otherwise.
	 *
	 * @since 1.1.0
	 *
	 * @param string $current The file's name now, whose extension is kept.
	 * @param string $typed   What was typed, with or without the extension.
	 * @param int    $max     Most characters in the result, extension
	 *                        included. 255 is what file systems allow.
	 *
	 * @return string '' when nothing is left with a letter or digit in it.
	 */
	public static function rename( string $current, string $typed, int $max = 255 ): string {
		$extension = pathinfo( $current, PATHINFO_EXTENSION );
		$suffix    = '' === $extension ? '' : '.' . $extension;

		$base = (string) preg_replace( '/[\x00-\x1F\x7F]|' . self::INVISIBLE . '/u', '', $typed );
		$base = trim( (string) preg_replace( '/\s+/u', ' ', $base ) );
		$base = str_replace( array( '/', '\\', ':', '*', '?', '"', '<', '>', '|' ), '-', $base );

		if ( '' !== $suffix && str_ends_with( mb_strtolower( $base ), mb_strtolower( $suffix ) ) ) {
			$base = mb_substr( $base, 0, -mb_strlen( $suffix ) );
		}

		$base = trim( $base, ' .' );

		if ( 1 !== preg_match( '/[\p{L}\p{N}]/u', $base ) ) {
			return '';
		}

		$base = (string) preg_replace( self::RESERVED, '$1_', $base );

		return rtrim( mb_substr( $base, 0, max( 1, $max - mb_strlen( $suffix ) ) ), ' .' ) . $suffix;
	}
}
