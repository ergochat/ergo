// Copyright (c) 2018 Shivaram Lingamneni
// released under the MIT license

package passwd

import "golang.org/x/crypto/bcrypt"
import "golang.org/x/crypto/sha3"

const (
	MinCost     = bcrypt.MinCost
	DefaultCost = 12 // ballpark: 250 msec on a modern Intel CPU
)

// implements Dropbox's strategy of applying an initial pass of a "normal"
// (i.e., fast) cryptographically secure hash with 512 bits of output before
// applying bcrypt. This allows the use of, e.g., Diceware/XKCD-style passphrases
// that may be longer than the 80-character bcrypt limit.
// https://blogs.dropbox.com/tech/2016/09/how-dropbox-securely-stores-your-passwords/

// we are only using this for user-generated passwords, as opposed to the server
// and operator passwords that are hashed by `oragono genpasswd` and then
// hard-coded by the server admins into the config file, to avoid breaking
// backwards compatibility (since we can't upgrade the config file on the fly
// the way we can with the database).

func GenerateFromPassword(password []byte, cost int) (result []byte, err error) {
	sum := sha3.Sum512(password)
	return bcrypt.GenerateFromPassword(sum[:], cost)
}

func CompareHashAndPassword(hashedPassword, password []byte) error {
	sum := sha3.Sum512(password)
	return bcrypt.CompareHashAndPassword(hashedPassword, sum[:])
}
