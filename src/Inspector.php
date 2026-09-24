<?php
/**
 * Looking at what was actually uploaded.
 *
 * @package   SugarCommerce\FileInspect
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\FileInspect;

/**
 * Class Inspector
 *
 * Not a virus engine. It answers a narrower question that matters more to a
 * host: is this file what its name says it is, and is it the kind of thing
 * you are willing to be a distribution channel for.
 *
 * Signals, in order of how certain they are:
 *
 *   - **Executable content.** MZ, ELF, Mach-O, a shebang. Blocked whatever
 *     the file is called. There is nothing to weigh up.
 *   - **A file that is not what it claims.** A `.wav` that is a PDF, a `.pdf`
 *     that is a zip. Flagged rather than blocked — a mislabelled file is
 *     usually a mistake, and refusing on a guess is worse than looking.
 *   - **An archive carrying something you would not have taken directly.**
 *     Zipping a binary is the documented way round an extension rule, and
 *     also how a legitimate application ships. Flagged, for the same reason.
 *   - **Words in the name** that the caller wants a person to see. Policy,
 *     so it is the caller's list; empty by default.
 */
final readonly class Inspector {

	/**
	 * How much of a file to read from the start.
	 *
	 * Every signature here is in the first few hundred bytes. The rest is
	 * room for an archive small enough that its directory is in reach too.
	 */
	public const int HEAD = 65536;

	/**
	 * Content that is executable on some platform, whatever it is called.
	 */
	private const array EXECUTABLE = array(
		"MZ"               => 'a Windows executable',
		"\x7fELF"          => 'a Linux executable',
		"\xfe\xed\xfa\xce" => 'a macOS executable',
		"\xfe\xed\xfa\xcf" => 'a macOS executable',
		"\xce\xfa\xed\xfe" => 'a macOS executable',
		"\xcf\xfa\xed\xfe" => 'a macOS executable',
		"\xca\xfe\xba\xbe" => 'a macOS universal binary',
		"#!"               => 'a shell script',
	);

	/**
	 * What a file of each extension should begin with.
	 *
	 * Only formats with a signature worth checking. A `.txt` has no magic,
	 * so there is nothing to disagree with.
	 *
	 * @var array<string, string[]>
	 */
	private const array EXPECTED = array(
		'pdf'  => array( '%PDF' ),
		'zip'  => array( "PK\x03\x04", "PK\x05\x06" ),
		'png'  => array( "\x89PNG" ),
		'jpg'  => array( "\xff\xd8\xff" ),
		'jpeg' => array( "\xff\xd8\xff" ),
		'gif'  => array( 'GIF8' ),
		'mp3'  => array( "ID3", "\xff\xfb", "\xff\xf3", "\xff\xf2" ),
		'wav'  => array( 'RIFF' ),
		'flac' => array( 'fLaC' ),
		'ogg'  => array( 'OggS' ),
		'mp4'  => array( 'ftyp' ),
		'mov'  => array( 'ftyp' ),
		'm4a'  => array( 'ftyp' ),
		'epub' => array( "PK\x03\x04" ),
	);

	/**
	 * @param string[] $banned  Extensions an archive must not contain.
	 * @param string[] $suspect Phrases in a filename worth a person's look.
	 */
	public function __construct(
		private array $banned = Filename::EXECUTABLE,
		private array $suspect = array(),
	) {}

	/**
	 * Inspect a file.
	 *
	 * @since 1.0.0
	 *
	 * @param string $filename What the uploader called it.
	 * @param string $head     The first bytes of the file.
	 * @param string $tail     The last bytes, for an archive's directory;
	 *                         '' when $head already reaches the end.
	 *
	 * @return Verdict
	 */
	public function scan( string $filename, string $head, string $tail = '' ): Verdict {
		foreach ( self::EXECUTABLE as $magic => $what ) {
			if ( str_starts_with( $head, $magic ) ) {
				return Verdict::blocked( 'The file is ' . $what . '. Executables are not accepted.' );
			}
		}

		$extension = Filename::extension( $filename );

		if ( '' !== $mismatch = self::mismatch( $extension, $head ) ) {
			return Verdict::flagged( $mismatch );
		}

		if ( '' !== $inside = $this->inside_archive( $extension, $head . $tail ) ) {
			return Verdict::flagged( $inside );
		}

		foreach ( $this->suspect as $phrase ) {
			if ( str_contains( mb_strtolower( $filename ), $phrase ) ) {
				return Verdict::flagged( sprintf( 'The filename mentions "%s".', $phrase ) );
			}
		}

		return Verdict::clean();
	}

	/**
	 * Whether the content disagrees with the extension.
	 *
	 * @param string $extension Lower-cased, without the dot.
	 * @param string $head      First bytes.
	 *
	 * @return string The reason, or ''.
	 */
	private static function mismatch( string $extension, string $head ): string {
		$expected = self::EXPECTED[ $extension ] ?? array();

		if ( ! $expected || '' === $head ) {
			return '';
		}

		foreach ( $expected as $magic ) {
			// ftyp sits four bytes in, after the box length, rather than at
			// the start like every other signature here.
			$found = 'ftyp' === $magic
				? str_starts_with( substr( $head, 4 ), $magic )
				: str_starts_with( $head, $magic );

			if ( $found ) {
				return '';
			}
		}

		return sprintf( 'The contents do not look like a .%s file.', $extension );
	}

	/**
	 * Whether an archive carries something that would not be accepted alone.
	 *
	 * @param string $extension Lower-cased, without the dot.
	 * @param string $bytes     Head and tail of the file.
	 *
	 * @return string The reason, or ''.
	 */
	private function inside_archive( string $extension, string $bytes ): string {
		if ( 'zip' !== $extension ) {
			return '';
		}

		foreach ( ZipDirectory::names( $bytes ) as $name ) {
			if ( '' !== Filename::refusal( 'x.' . Filename::extension( $name ), $this->banned ) ) {
				return sprintf( 'The archive contains %s.', $name );
			}
		}

		return '';
	}
}
