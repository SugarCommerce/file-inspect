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
