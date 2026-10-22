<?php
/**
 * The names inside a zip, from a fragment of it.
 *
 * @package   SugarCommerce\FileInspect
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\FileInspect;

/**
 * Class ZipDirectory
 *
 * Reads the central directory records out of whatever bytes it is given —
 * typically the head and tail of an object, fetched with two ranged reads —
 * rather than parsing the archive. That is enough to list what is inside,
 * which is all an inspection needs, and a parser that must be correct about
 * a hostile file is a far larger thing to be responsible for.
 */
final class ZipDirectory {

	/**
	 * The signature of a central directory file header.
	 */
	private const string RECORD = "PK\x01\x02";

	/**
	 * Names listed in the fragment, in order.
	 *
	 * @since 1.0.0
	 *
	 * @param string $bytes Part of an archive; the tail is where the
	 *                      directory lives.
	 * @param int    $limit Stop after this many. A hostile file can carry
	 *                      thousands, and if the first hundred are clean a
	 *                      person can look at the rest.
	 *
	 * @return list<string>
	 */
	public static function names( string $bytes, int $limit = 100 ): array {
		$names  = array();
		$offset = 0;

		while ( count( $names ) < $limit && false !== $at = strpos( $bytes, self::RECORD, $offset ) ) {
			$offset = $at + 4;

			// The name's length is 28 bytes past the signature, and the name
			// itself begins 46 bytes past it.
			$length = ord( $bytes[ $at + 28 ] ?? "\0" ) | ( ord( $bytes[ $at + 29 ] ?? "\0" ) << 8 );

			if ( $length > 0 && $length < 4096 ) {
				$names[] = substr( $bytes, $at + 46, $length );
			}
		}

		return $names;
	}
}
