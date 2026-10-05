<?php
/**
 * Filename tests.
 *
 * @package SugarCommerce\FileInspect\Tests
 */

declare( strict_types=1 );

namespace SugarCommerce\FileInspect\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SugarCommerce\FileInspect\{Filename, ZipDirectory};

/**
 * Class FilenameTest
 */
final class FilenameTest extends TestCase {

	/**
	 * @return array<string, array{string}>
	 */
	public static function refused(): array {
		return array(
			'a binary'             => array( 'setup.exe' ),
			'upper case'           => array( 'SETUP.EXE' ),
			'a double extension'   => array( 'invoice.pdf.exe' ),
			'a page in our origin' => array( 'readme.html' ),
			'an svg'               => array( 'logo.svg' ),
		);
	}

	#[DataProvider( 'refused' )]
	public function test_a_name_that_would_run_is_refused( string $name ): void {
		$this->assertNotSame( '', Filename::refusal( $name ) );
	}

	public function test_an_ordinary_name_is_accepted(): void {
		$this->assertSame( '', Filename::refusal( 'Midnight Drive - Master.wav' ) );
		$this->assertSame( '', Filename::refusal( 'stems.zip' ) );
	}

	public function test_an_empty_name_is_refused(): void {
		$this->assertNotSame( '', Filename::refusal( "  \x00 " ) );
	}

	/* ─── Renaming (1.1.0) ──────────────────────────────────────────── */

	#[DataProvider( 'renames' )]
	public function test_a_rename_keeps_the_extension( string $typed, string $expected ): void {
		$this->assertSame( $expected, Filename::rename( 'Midnight Drive - Master.wav', $typed ) );
	}

	/**
	 * @return array<string, array{0: string, 1: string}>
	 */
	public static function renames(): array {
		return array(
			'plain'                     => array( 'Midnight Drive (Final)', 'Midnight Drive (Final).wav' ),
			'typed with the extension'  => array( 'Final.wav', 'Final.wav' ),
			'extension in another case' => array( 'Final.WAV', 'Final.wav' ),
			'a different extension'     => array( 'Final.exe', 'Final.exe.wav' ),
			'a path'                    => array( '../../etc/passwd', '-..-etc-passwd.wav' ),
			'a windows path'            => array( 'C:\\Music\\Final', 'C:-Music-Final.wav' ),
			'bidi override'             => array( "evil\u{202E}vaw.exe", 'evilvaw.exe.wav' ),
			'zero-width space'          => array( "Fi\u{200B}nal", 'Final.wav' ),
			'control characters'        => array( "Fi\x00nal\r\n", 'Final.wav' ),
			'runs of whitespace'        => array( "  Final \t  Mix  ", 'Final Mix.wav' ),
			'a hidden file'             => array( '.Final', 'Final.wav' ),
			'nothing but dots'          => array( '...', '' ),
			'blank'                     => array( '   ', '' ),
			'punctuation only'          => array( '— !', '' ),
			'one letter'                => array( 'x', 'x.wav' ),
			'another script'            => array( 'Музыка', 'Музыка.wav' ),
		);
	}

	public function test_a_file_without_an_extension_stays_without_one(): void {
		$this->assertSame( 'Read Me', Filename::rename( 'README', 'Read Me' ) );
	}

	public function test_a_long_name_is_cut_before_the_extension(): void {
		$name = Filename::rename( 'a.flac', str_repeat( 'x', 400 ) );

		$this->assertSame( 255, mb_strlen( $name ) );
		$this->assertStringEndsWith( 'x.flac', $name );
		$this->assertSame( 20, mb_strlen( Filename::rename( 'a.flac', str_repeat( 'é', 400 ), 20 ) ), 'Characters, not bytes.' );
	}

	public function test_a_cut_does_not_leave_a_trailing_dot_or_space(): void {
		$this->assertSame( 'ab.wav', Filename::rename( 'a.wav', 'ab .cd', 7 ) );
	}

	public function test_the_list_is_the_callers(): void {
		$this->assertSame( '', Filename::refusal( 'setup.exe', array() ) );
		$this->assertNotSame( '', Filename::refusal( 'notes.txt', array( 'txt' ) ) );
	}

	public function test_the_zip_directory_is_read_from_a_fragment(): void {
		$record = static fn( string $name ): string => "PK\x01\x02" . str_repeat( "\x00", 24 ) . pack( 'v', strlen( $name ) ) . str_repeat( "\x00", 16 ) . $name;

		$this->assertSame( array( 'a.wav', 'b.wav' ), ZipDirectory::names( 'junk' . $record( 'a.wav' ) . $record( 'b.wav' ) ) );
		$this->assertSame( array( 'a.wav' ), ZipDirectory::names( $record( 'a.wav' ) . $record( 'b.wav' ), limit: 1 ) );
	}
}
