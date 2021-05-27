package confusables

// these are overrides for the standard confusables table:
// a mapping to "" means "don't map", a mapping to a replacement means
// "replace with this", no entry means "defer to the standard table"

var tweaksMap = map[rune]string{
	// ASCII-to-ASCII mapping that we are removing:
	0x6d: "", // m -> rn
	// these characters are confusable with m, hence the official table
	// maps them to rn (`grep "LATIN SMALL LETTER R, LATIN SMALL LETTER N" confusables.txt`)
	0x118E3: "m", // 118E3 ; 0072 006E ;     MA      # ( 𑣣 → rn ) WARANG CITI DIGIT THREE → LATIN SMALL LETTER R, LATIN SMALL LETTER N
	0x11700: "m", // 11700 ; 0072 006E ;     MA      # ( 𑜀 → rn ) AHOM LETTER KA → LATIN SMALL LETTER R, LATIN SMALL LETTER N
	// the table thinks this is confusable with  m̦ but I think it's confusable with m:
	0x0271:  "m", // 0271 ;	0072 006E 0326 ;	MA	# ( ɱ → rn̦ ) LATIN SMALL LETTER M WITH HOOK → LATIN SMALL LETTER R, LATIN SMALL LETTER N, COMBINING COMMA BELOW	# →m̡→

	/*
	// ASCII-to-ASCII mapping that we are removing:
	0x49: "", // I -> l
	// these characters are confusable with I, hence the official table
	// maps them to l (`grep "LATIN SMALL LETTER L" confusables.txt`)
	0x0399: "I", // 0399 ;	006C ;	MA	# ( Ι → l ) GREEK CAPITAL LETTER IOTA → LATIN SMALL LETTER L	# 
	0x0406: "I", // 0406 ;	006C ;	MA	# ( І → l ) CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I → LATIN SMALL LETTER L	# 
	0x04C0: "I", // 04C0 ;	006C ;	MA	# ( Ӏ → l ) CYRILLIC LETTER PALOCHKA → LATIN SMALL LETTER L	# 

	// ASCII-to-ASCII mapping that we are removing:
	0x31: "", // 1 -> l
	// these characters are confusable with 1, hence the official table
	// maps them to l (`grep "LATIN SMALL LETTER L" confusables.txt`)
	// [nothing yet]

	// ASCII-to-ASCII mapping that we are removing:
	0x30: "", // 0 -> O
	// these characters are confusable with 0, hence the official table
	// maps them to O (`grep "LATIN CAPITAL LETTER O\>" confusables.txt`)
	// [nothing yet]
	*/
}
