# MOTD Formatting Codes

If `motd-formatting` is enabled in the config file, you can use special escape codes to
easily get bold, coloured, italic, and other types of specially-formatted text.

Our formatting character is '$', and this followed by specific letters means that the text
after it is formatted in the given way. Here are the character pairs and what they output:

    --------------------------
     Escape | Output
    --------------------------
       $$   | Dollar sign ($)
       $b   | Bold
       $c   | Color code
       $i   | Italics
       $u   | Underscore
       $r   | Reset
    --------------------------


## Color codes

After the color code (`$c`), you can use square brackets to specify which foreground and
background colors to output. For example:

This line outputs red text:
    `This is $c[red]really cool text!`

This line outputs red text with a light blue background:
    `This is $c[red,light blue]22% cooler!`

If you're familiar with IRC colors you can also use the raw numbers you're used to:
    `This is $c13pink text`

Here are the color names we support, and which IRC colors they map to:

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
    --------------------

In addition, some newer clients can make use of the colour codes 16-98, though they don't
have any names assigned. Take a look at this table to see which colours these numbers are:
https://modern.ircdocs.horse/formatting.html#colors-16-98
