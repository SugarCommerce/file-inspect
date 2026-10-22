# File Inspect

Look at the bytes a file actually contains: executable signatures refused whatever the name, contents that disagree with the extension, archives carrying what you would not accept directly, and double extensions that hide the real one. Pure functions, no I/O, zero dependencies.

## Why

An extension check before an upload is a statement of intent — anybody can rename a file. The honest answer is in the bytes that arrived, and a host that serves files to strangers needs to ask it:

- **Is it executable?** `MZ`, `\x7fELF`, Mach-O, a shebang. There is nothing to weigh up.
- **Is it what it says?** A `.wav` that is a PDF is usually a mistake, occasionally not.
- **Is the archive a way round the rules?** Zipping a binary is how an extension check is beaten, and also how a legitimate application ships.

This answers those from two ranged reads — the head and tail of an object — without downloading it, and without a zip parser that must be right about a hostile file.

## Features

- 🚫 **Executable signatures** — Windows, Linux, macOS and shell scripts, blocked whatever the name.
- 🏷️ **Extension against contents** — PDF, zip, PNG, JPEG, GIF, MP3, WAV, FLAC, OGG, MP4/MOV/M4A, EPUB.
- 🗜️ **Archive contents** — names read from the central directory of anything that is a zip, whatever it is called, and checked against your banned list the way an upload's name is.
- 🌐 **Pages in disguise** — HTML or SVG a browser would sniff and run, in a `.txt` or a file with no extension, is flagged.
- 🔤 **Double extensions** — `invoice.pdf.exe` is refused on its name alone, and so are `setup.exe .` (which Windows saves as `setup.exe`), `setup.exe:stream`, and names carrying a direction override.
- ✏️ **Renames that cannot lie** — the stored extension is kept, and direction overrides, control characters and path separators are taken out of what was typed.
- 🧑‍⚖️ **Three outcomes** — clean, flagged for a person, or blocked. Policy is yours: the banned extensions and the suspect phrases are constructor arguments.

## Requirements

PHP 8.5+

## Installation

```bash
composer require sugarcommerce/file-inspect
```

## Before the upload

```php
use SugarCommerce\FileInspect\Filename;

$reason = Filename::refusal( $submitted_name );   // '' when acceptable
```

## After it

```php
use SugarCommerce\FileInspect\Inspector;

$inspector = new Inspector( suspect: array( 'keygen', 'cracked' ) );

$head = $storage->range( $key, 0, Inspector::HEAD - 1 );
$tail = $size > Inspector::HEAD ? $storage->range( $key, $size - Inspector::HEAD, $size - 1 ) : '';

$verdict = $inspector->scan( $name, $head, $tail );

if ( ! $verdict->allowed() ) {
    $storage->delete( $key );            // blocked: the bytes do not stay
}

$record->review_state = $verdict->state; // ok | flagged | blocked
$record->review_note  = $verdict->reason;
```

## Renaming a stored file

```php
Filename::rename( 'Midnight Drive - Master.wav', 'Final Mix' );            // 'Final Mix.wav'
Filename::rename( 'Midnight Drive - Master.wav', 'Final Mix.wav' );        // 'Final Mix.wav' — not doubled
Filename::rename( 'Midnight Drive - Master.wav', 'Final.exe' );            // 'Final.exe.wav'
Filename::rename( 'Midnight Drive - Master.wav', "evil\u{202E}vaw.exe" );  // 'evilvaw.exe.wav'
Filename::rename( 'Midnight Drive - Master.wav', '...' );                  // '' — refuse it
```

The extension is the one the file was inspected under, so it stays whatever is typed: a rename from `.wav` to `.exe` would make it a different file to your previews, your players and the computer it is downloaded to. What is typed loses control characters, zero-width characters, direction marks, overrides and isolates (`Invoice\u{202E}fdp.exe` *displays* as `Invoiceexe.pdf`), has its whitespace collapsed, its slashes turned into hyphens — a separator is a path to some unzip tools and save dialogs — along with the other characters Windows will not save (`: * ? " < > |`), and its leading and trailing dots and spaces trimmed. A device name Windows reserves (`CON`, `NUL`, `COM1` …) gets an underscore. A name with no letter or digit left is `''`. The result is cut to 255 characters (or `$max`) before the extension, never through it.

## What it does not do

It is not a virus scanner. It does not look inside nested archives, decompress anything, catch a polyglot that carries a valid signature for its extension, or promise a flagged file is harmful or a clean one safe. A verdict's reason can quote a name from inside an archive: it comes back as valid UTF-8 with no control or direction characters, but escape it wherever you show it. It answers "is this what it claims, and is it the kind of thing we host" — cheaply, before a person has to.

## Testing

```bash
composer install
composer test
```

69 tests: executable signatures, extension against contents for every listed format, pages under harmless names, archive names from the central directory however the archive is named, double extensions, trailing dots, streams and direction overrides, the three verdicts, and renames — kept and doubled extensions, overrides and isolates, separators and Windows-reserved characters and names, dots, scripts and lengths.

## License

GPL-2.0-or-later
