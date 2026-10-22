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
	 *
	 * @var array<string, string>
	 */
	private const array EXECUTABLE = array(
		"MZ"               => 'a Windows executable',
		"\x7fELF"          => 'a Linux executable',
		"\xfe\xed\xfa\xce" => 'a macOS executable',
		"\xfe\xed\xfa\xcf" => 'a macOS executable',
		"\xce\xfa\xed\xfe" => 'a macOS executable',
		"\xcf\xfa\xed\xfe" => 'a macOS executable',
		"\xca\xfe\xba\xbe" => 'a macOS universal binary',
		"\xca\xfe\xba\xbf" => 'a macOS universal binary',
		"#!"               => 'a shell script',
	);

	/**
	 * What a file of each extension should begin with.
	 *
	 * Only formats with a signature worth checking. A `.txt` has no magic,
	 * so there is nothing to disagree with.
	 *
	 * @var array<string, list<string>>
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
	 * How a page a browser would render begins, once leading whitespace and
	 * a byte order mark are skipped — the patterns a browser sniffs for when
	 * a file is served without a type it trusts.
	 *
	 * @var list<string>
	 */
	private const array MARKUP = array(
		'<!doctype html', '<html', '<head', '<body', '<script', '<iframe',
		'<object', '<embed', '<svg',
	);

	/**
	 * What in an XML document makes it run script when it is rendered: an
	 * SVG or XHTML vocabulary, or a script element.
	 *
	 * @var list<string>
	 */
	private const array ACTIVE_XML = array( '<svg', '/1999/xhtml', '<script' );

	/**
	 * Zip-based formats whose members are expected to include pages, so
	 * are not read as archives unless they are called `.zip`.
	 *
	 * @var list<string>
	 */
	private const array ZIP_DOCUMENTS = array( 'epub' );

	/**
	 * Most characters of an archive member's name quoted in a reason.
	 */
	private const int QUOTED = 120;

	/**
	 * An inspector with the caller's policy.
	 *
	 * @param array<string> $banned  Extensions an archive must not contain.
	 * @param array<string> $suspect Phrases in a filename worth a person's
	 *                               look, matched case-insensitively.
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
	 * @return Verdict Its reason may quote names chosen by the uploader;
	 *                 they arrive as valid UTF-8 without control or
	 *                 direction characters, but still need escaping
	 *                 wherever they are shown.
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

		if ( '' !== $markup = self::markup( $head ) ) {
			return Verdict::flagged( $markup );
		}

		if ( '' !== $inside = $this->inside_archive( $extension, $head, $tail ) ) {
			return Verdict::flagged( $inside );
		}

		foreach ( $this->suspect as $phrase ) {
			$phrase = mb_strtolower( $phrase );

			if ( '' !== $phrase && str_contains( mb_strtolower( $filename ), $phrase ) ) {
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
	 * Whether the content is a page a browser would render, whatever the
	 * extension says.
	 *
	 * A browser handed a file with no type, or one it does not trust,
	 * sniffs the first bytes, and HTML or SVG it finds there runs script in
	 * the origin that served it. A format with a signature of its own is
	 * already flagged when it starts with anything else, so this is what
	 * catches a page in a `.txt`, a `.csv` or a file with no extension.
	 *
	 * @param string $head First bytes.
	 *
	 * @return string The reason, or ''.
	 */
	private static function markup( string $head ): string {
		$start = strtolower( ltrim( substr( $head, str_starts_with( $head, "\xef\xbb\xbf" ) ? 3 : 0, 1024 ), " \t\n\r\x0c" ) );

		foreach ( self::MARKUP as $tag ) {
			if ( str_starts_with( $start, $tag ) && in_array( substr( $start, strlen( $tag ), 1 ), array( ' ', '>', "\t", "\n", "\r", "\x0c", '/' ), true ) ) {
				return 'The file is a page a browser would run.';
			}
		}

		if ( str_starts_with( $start, '<?xml' ) ) {
			$document = strtolower( $head );

			foreach ( self::ACTIVE_XML as $needle ) {
				if ( str_contains( $document, $needle ) ) {
					return 'The file is XML a browser would run as a page.';
				}
			}
		}

		return '';
	}

	/**
	 * Whether an archive carries something that would not be accepted alone.
	 *
	 * A file is read as an archive when it is called `.zip`, or when its
	 * bytes are a zip whatever it is called — renaming one to `.bin` is not
	 * a way past this. Each member's name is checked the way an upload's
	 * would be, so a double extension inside is caught too.
	 *
	 * @param string $extension Lower-cased, without the dot.
	 * @param string $head      First bytes of the file.
	 * @param string $tail      Last bytes, or ''.
	 *
	 * @return string The reason, or ''.
	 */
	private function inside_archive( string $extension, string $head, string $tail ): string {
		$zip = 'zip' === $extension
			|| ( str_starts_with( $head, "PK\x03\x04" ) && ! in_array( $extension, self::ZIP_DOCUMENTS, true ) );

		if ( ! $zip ) {
			return '';
		}

		foreach ( ZipDirectory::names( $head . $tail ) as $name ) {
			$parts = preg_split( '#[/\\\\]#', $name ) ?: array( $name );
			$leaf  = (string) end( $parts );

			// A directory's entry ends in a separator and has no leaf.
			if ( '' !== $leaf && '' !== Filename::refusal( $leaf, $this->banned ) ) {
				return sprintf( 'The archive contains %s.', self::quote( $name ) );
			}
		}

		return '';
	}

	/**
	 * A name from inside a file, made fit to put in a sentence: valid UTF-8,
	 * without control, zero-width or direction characters, and cut short.
	 *
	 * @param string $name As the archive carries it.
	 *
	 * @return string
	 */
	private static function quote( string $name ): string {
		$name = mb_scrub( $name, 'UTF-8' );
		$name = (string) preg_replace( '/[\x00-\x1F\x7F\x{0080}-\x{009F}\x{061C}\x{180E}\x{200B}-\x{200F}\x{2028}-\x{202E}\x{2060}-\x{2069}\x{FEFF}]/u', '', $name );

		return mb_strlen( $name ) > self::QUOTED ? mb_substr( $name, 0, self::QUOTED ) . '…' : $name;
	}
}
