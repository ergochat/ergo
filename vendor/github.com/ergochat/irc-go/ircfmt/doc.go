// written by Daniel Oaks <daniel@danieloaks.net>
// released under the ISC license

/*
Package ircfmt handles IRC formatting codes, escaping and unescaping.

This allows for a simpler representation of strings that contain colour codes,
bold codes, and such, without having to write and handle raw bytes when
assembling outgoing messages.

This lets you turn raw IRC messages into our escaped versions, and turn escaped
versions back into raw messages suitable for sending on IRC connections. This
is designed to be used on things like PRIVMSG / NOTICE commands, MOTD blocks,
and such.

The escape character we use in this library is the dollar sign ("$"), along
with the given escape characters:

	--------------------------------
	 Name           | Escape | Raw
	--------------------------------
	 Dollarsign     |   $$   |  $
	 Bold           |   $b   | 0x02
	 Colour         |   $c   | 0x03
	 Monospace      |   $m   | 0x11
	 Reverse Colour |   $v   | 0x16
	 Italic         |   $i   | 0x1d
	 Strikethrough  |   $s   | 0x1e
	 Underscore     |   $u   | 0x1f
	 Reset          |   $r   | 0x0f
	--------------------------------

Colours are escaped in a slightly different way, using the actual names of them
rather than just the raw numbers.

In our escaped format, the colours for the fore and background are contained in
square brackets after the colour ("$c") escape. For example:

	Red foreground:
		Escaped:  This is a $c[red]cool message!
		Raw:      This is a 0x034cool message!

	Blue foreground, green background:
		Escaped:  This is a $c[blue,green]rad message!
		Raw:      This is a 0x032,3rad message!

When assembling a raw message, we make sure to use the full colour code
("02" vs just "2") when it could become confused due to numbers just after the
colour escape code. For instance, lines like this will be unescaped correctly:

	No number after colour escape:
		Escaped:  This is a $c[red]cool message!
		Raw:      This is a 0x034cool message!

	Number after colour escape:
		Escaped:  This is $c[blue]20% cooler!
		Raw:      This is 0x030220% cooler

Here are the colour names and codes we recognise:

	--------------------
	 Code | Name
	--------------------
	  00  | white
	  01  | black
	  02  | blue
	  03  | green
	  04  | red
	  05  | brown
	  06  | magenta
	  07  | orange
	  08  | yellow
	  09  | light green
	  10  | cyan
	  11  | light cyan
	  12  | light blue
	  13  | pink
	  14  | grey
	  15  | light grey
	  99  | default
	--------------------

These other colours aren't given names:
https://modern.ircdocs.horse/formatting.html#colors-16-98
*/
package ircfmt
