<?php
/**
 * Inspector tests.
 *
 * @package SugarCommerce\FileInspect\Tests
 */

declare( strict_types=1 );

namespace SugarCommerce\FileInspect\Tests;

use PHPUnit\Framework\TestCase;
use SugarCommerce\FileInspect\Inspector;

/**
 * Class InspectorTest
 *
 * The extension check before an upload is a statement of intent; anybody can
 * rename a file. This is the part that looks at what arrived.
 */
final class InspectorTest extends TestCase {

	private Inspector $scanner;

	protected function setUp(): void {
		$this->scanner = new Inspector( suspect: array( 'get-rich' ) );
	}

	/* ── executables ─────────────────────────────────────────────────── */

	public function test_a_windows_binary_is_blocked_whatever_it_is_called(): void {
		$verdict = $this->scanner->scan( 'Midnight Drive - Master.wav', "MZ\x90\x00\x03" );

		$this->assertSame( 'blocked', $verdict->state );
		$this->assertFalse( $verdict->allowed() );
		$this->assertStringContainsString( 'Windows executable', $verdict->reason );
	}

	public function test_a_linux_binary_is_blocked(): void {
		$this->assertSame( 'blocked', $this->scanner->scan( 'notes.pdf', "\x7fELF\x02\x01" )->state );
	}

	public function test_a_mac_binary_is_blocked(): void {
		$this->assertSame( 'blocked', $this->scanner->scan( 'sample.mp3', "\xcf\xfa\xed\xfe\x07" )->state );
	}

	public function test_a_shell_script_is_blocked(): void {
		$this->assertSame( 'blocked', $this->scanner->scan( 'install.txt', "#!/bin/sh\necho hi" )->state );
	}

	/* ── what a file claims to be ────────────────────────────────────── */

	public function test_a_real_pdf_passes(): void {
		$this->assertSame( 'ok', $this->scanner->scan( 'Licence.pdf', '%PDF-1.7 ...' )->state );
	}

	public function test_a_wav_that_is_not_a_wav_is_flagged(): void {
		$verdict = $this->scanner->scan( 'master.wav', '%PDF-1.7' );

		$this->assertSame( 'flagged', $verdict->state );
		// Flagged, not blocked: a mislabelled file is usually a mistake, and
		// refusing a seller's product on a guess is worse than looking.
		$this->assertTrue( $verdict->allowed() );
		$this->assertStringContainsString( '.wav', $verdict->reason );
	}

	public function test_an_mp4_signature_is_found_where_it_actually_lives(): void {
		// ftyp sits after the four-byte box length, unlike every other magic.
		$this->assertSame( 'ok', $this->scanner->scan( 'trailer.mp4', "\x00\x00\x00\x20ftypisom" )->state );
	}

	public function test_a_format_with_no_signature_is_left_alone(): void {
		$this->assertSame( 'ok', $this->scanner->scan( 'notes.txt', 'just some words' )->state );
	}

	public function test_an_empty_file_is_not_flagged_for_its_extension(): void {
		$this->assertSame( 'ok', $this->scanner->scan( 'empty.pdf', '' )->state );
	}

	public function test_each_accepted_signature_for_a_format_is_accepted(): void {
		foreach ( array( 'ID3x', "\xff\xfbx", "\xff\xf3x" ) as $magic ) {
			$this->assertSame( 'ok', $this->scanner->scan( 'track.mp3', $magic )->state );
		}
	}

	/* ── archives ────────────────────────────────────────────────────── */

	/**
	 * Zipping a binary is the documented way round the extension rule. It is
	 * also how a legitimate Windows application ships, which is why this
	 * flags rather than refuses.
	 */
	public function test_an_archive_containing_an_executable_is_flagged(): void {
		$verdict = $this->scanner->scan( 'plugin.zip', "PK\x03\x04", $this->central( 'setup.exe' ) );

		$this->assertSame( 'flagged', $verdict->state );
		$this->assertStringContainsString( 'setup.exe', $verdict->reason );
	}

	public function test_an_ordinary_archive_passes(): void {
		$verdict = $this->scanner->scan( 'stems.zip', "PK\x03\x04", $this->central( 'kick.wav' ) );

		$this->assertSame( 'ok', $verdict->state );
	}

	public function test_only_archives_are_read_as_archives(): void {
		// The same bytes inside something that is not a zip are just bytes.
		$this->assertSame( 'ok', $this->scanner->scan( 'notes.txt', $this->central( 'setup.exe' ) )->state );
	}

	/* ── filenames ───────────────────────────────────────────────────── */

	public function test_a_suspect_filename_is_flagged_for_a_person_to_read(): void {
		$verdict = $this->scanner->scan( 'get-rich-method.pdf', '%PDF-1.4' );

		$this->assertSame( 'flagged', $verdict->state );
		$this->assertTrue( $verdict->allowed() );
	}

	public function test_an_ordinary_filename_is_not(): void {
		$this->assertSame( 'ok', $this->scanner->scan( 'Mixing Guide.pdf', '%PDF-1.4' )->state );
	}

	/**
	 * What counts as suspect is the caller's policy, so by default nothing.
	 */
	public function test_no_phrase_is_suspect_by_default(): void {
		$this->assertSame( 'ok', ( new Inspector() )->scan( 'get-rich-method.pdf', '%PDF-1.4' )->state );
	}

	/**
	 * What an archive must not carry is the caller's too.
	 */
	public function test_the_banned_list_decides_what_an_archive_may_carry(): void {
		$lenient = new Inspector( banned: array() );

		$this->assertSame( 'ok', $lenient->scan( 'plugin.zip', "PK\x03\x04", $this->central( 'setup.exe' ) )->state );
	}

	/**
	 * Certainty wins. A file that is both executable and badly named is not
	 * a judgement call.
	 */
	public function test_an_executable_beats_every_other_signal(): void {
		$this->assertSame( 'blocked', $this->scanner->scan( 'get-rich.zip', "MZ\x90" )->state );
	}

	/**
	 * A central directory record for one name, as a real archive carries it.
	 */
	private function central( string $name ): string {
		return "PK\x01\x02"
			. str_repeat( "\x00", 24 )
			. pack( 'v', strlen( $name ) )
			. str_repeat( "\x00", 16 )
			. $name;
	}
}
