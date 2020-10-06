package migrations

import (
	"golang.org/x/crypto/bcrypt"
)

// See the v12-to-v13 schema change. The format of this hash is:
// 30 bytes of global salt, 30 bytes of per-passphrase salt, then the bcrypt hash
func CheckOragonoPassphraseV0(hash, passphrase []byte) error {
	globalSalt := hash[:30]
	passphraseSalt := hash[30:60]
	bcryptHash := hash[60:]
	assembledPasswordBytes := make([]byte, 0, 60+len(passphrase)+2)
	assembledPasswordBytes = append(assembledPasswordBytes, globalSalt...)
	assembledPasswordBytes = append(assembledPasswordBytes, '-')
	assembledPasswordBytes = append(assembledPasswordBytes, passphraseSalt...)
	assembledPasswordBytes = append(assembledPasswordBytes, '-')
	assembledPasswordBytes = append(assembledPasswordBytes, passphrase...)
	return bcrypt.CompareHashAndPassword(bcryptHash, assembledPasswordBytes)
}
