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
- 🗜️ **Archive contents** — names read from the central directory, checked against your banned list.
- 🔤 **Double extensions** — `invoice.pdf.exe` is refused on its name alone.
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

## What it does not do

It is not a virus scanner. It does not look inside nested archives, decompress anything, or promise a flagged file is harmful or a clean one safe. It answers "is this what it claims, and is it the kind of thing we host" — cheaply, before a person has to.

## License

GPL-2.0-or-later
