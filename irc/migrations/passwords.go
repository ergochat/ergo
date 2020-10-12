package migrations

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"strconv"

	"github.com/GehirnInc/crypt/md5_crypt"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
)

var (
	ErrHashInvalid     = errors.New("password hash invalid for algorithm")
	ErrHashCheckFailed = errors.New("passphrase did not match stored hash")

	hmacServerKeyText    = []byte("Server Key")
	athemePBKDF2V2Prefix = []byte("$z")
	athemeRawSHA1Prefix  = []byte("$rawsha1$")
)

type PassphraseCheck func(hash, passphrase []byte) (err error)

func CheckAthemePassphrase(hash, passphrase []byte) (err error) {
	if bytes.HasPrefix(hash, athemeRawSHA1Prefix) {
		return checkAthemeRawSha1(hash, passphrase)
	} else if bytes.HasPrefix(hash, athemePBKDF2V2Prefix) {
		return checkAthemePBKDF2V2(hash, passphrase)
	} else if len(hash) < 60 {
		return checkAthemePosixCrypt(hash, passphrase)
	} else {
		return checkAthemePBKDF2(hash, passphrase)
	}
}

func checkAthemePosixCrypt(hash, passphrase []byte) (err error) {
	// crypto/posix: the platform's crypt(3) function
	// MD5 on linux, DES on MacOS: forget MacOS
	md5crypt := md5_crypt.New()
	return md5crypt.Verify(string(hash), []byte(passphrase))
}

type pbkdf2v2Algo struct {
	Hash       func() hash.Hash
	OutputSize int
	SCRAM      bool
	SaltB64    bool
}

func athemePBKDF2V2ParseAlgo(algo string) (result pbkdf2v2Algo, err error) {
	// https://github.com/atheme/atheme/blob/a11e85efc67d86fc4738e3e2a4f220bfa69153f0/include/atheme/pbkdf2.h#L34-L52
	algoInt, err := strconv.Atoi(algo)
	if err != nil {
		return result, ErrHashInvalid
	}
	hashCode := algoInt % 10
	algoCode := algoInt - hashCode

	switch algoCode {
	case 0:
		// e.g., #define PBKDF2_PRF_HMAC_MD5             3U
		// no SCRAM, no SHA256
	case 20:
		// e.g., #define PBKDF2_PRF_HMAC_MD5_S64         23U
		// no SCRAM, base64
		result.SaltB64 = true
	case 40:
		// e.g., #define PBKDF2_PRF_SCRAM_MD5            43U
		// SCRAM, no base64
		result.SCRAM = true
	case 60:
		// e.g., #define PBKDF2_PRF_SCRAM_MD5_S64        63U
		result.SaltB64 = true
		result.SCRAM = true
	default:
		return result, ErrHashInvalid
	}

	switch hashCode {
	case 3:
		result.Hash, result.OutputSize = md5.New, (128 / 8)
	case 4:
		result.Hash, result.OutputSize = sha1.New, (160 / 8)
	case 5:
		result.Hash, result.OutputSize = sha256.New, (256 / 8)
	case 6:
		result.Hash, result.OutputSize = sha512.New, (512 / 8)
	default:
		return result, ErrHashInvalid
	}

	return result, nil
}

func checkAthemePBKDF2V2(hash, passphrase []byte) (err error) {
	// crypto/pbkdf2v2, the default as of september 2020:
	// "the format for pbkdf2v2 is $z$alg$iter$salt$digest
	// where the z is literal,
	// the alg is one from  https://github.com/atheme/atheme/blob/master/include/atheme/pbkdf2.h#L34-L52
	// iter is the iteration count.
	// if the alg ends in _S64 then the salt is base64-encoded, otherwise taken literally
	// (an ASCII salt, inherited from the pbkdf2 module).
	// if alg is a SCRAM one, then digest is actually serverkey$storedkey (see RFC 5802).
	// digest, serverkey and storedkey are base64-encoded."
	parts := bytes.Split(hash, []byte{'$'})
	if len(parts) < 6 {
		return ErrHashInvalid
	}
	algo, err := athemePBKDF2V2ParseAlgo(string(parts[2]))
	if err != nil {
		return err
	}

	iter, err := strconv.Atoi(string(parts[3]))
	if err != nil {
		return ErrHashInvalid
	}

	salt := parts[4]
	if algo.SaltB64 {
		salt, err = base64.StdEncoding.DecodeString(string(salt))
		if err != nil {
			return err
		}
	}

	// if SCRAM, parts[5] is ServerKey; otherwise it's the actual PBKDF2 output
	// either way, it's what we'll test against
	expected, err := base64.StdEncoding.DecodeString(string(parts[5]))
	if err != nil {
		return err
	}

	var key []byte
	if algo.SCRAM {
		if len(parts) != 7 {
			return ErrHashInvalid
		}
		stretch := pbkdf2.Key(passphrase, salt, iter, algo.OutputSize, algo.Hash)
		mac := hmac.New(algo.Hash, stretch)
		mac.Write(hmacServerKeyText)
		key = mac.Sum(nil)
	} else {
		if len(parts) != 6 {
			return ErrHashInvalid
		}
		key = pbkdf2.Key(passphrase, salt, iter, len(expected), algo.Hash)
	}

	if subtle.ConstantTimeCompare(key, expected) == 1 {
		return nil
	} else {
		return ErrHashCheckFailed
	}
}

func checkAthemePBKDF2(hash, passphrase []byte) (err error) {
	// crypto/pbkdf2:
	// "SHA2-512, 128000 iterations, 16-ASCII-character salt, hexadecimal encoding of digest,
	// digest appended directly to salt, for a single string consisting of only 144 characters"
	if len(hash) != 144 {
		return ErrHashInvalid
	}

	salt := hash[:16]
	digest := make([]byte, 64)
	cnt, err := hex.Decode(digest, hash[16:])
	if err != nil || cnt != 64 {
		return ErrHashCheckFailed
	}

	key := pbkdf2.Key(passphrase, salt, 128000, 64, sha512.New)
	if subtle.ConstantTimeCompare(key, digest) == 1 {
		return nil
	} else {
		return ErrHashCheckFailed
	}
}

func checkAthemeRawSha1(hash, passphrase []byte) (err error) {
	return checkRawHash(hash[len(athemeRawSHA1Prefix):], passphrase, sha1.New())
}

func checkRawHash(expected, passphrase []byte, h hash.Hash) (err error) {
	var rawExpected []byte
	size := h.Size()
	if len(expected) == 2*size {
		rawExpected = make([]byte, h.Size())
		_, err = hex.Decode(rawExpected, expected)
		if err != nil {
			return ErrHashInvalid
		}
	} else if len(expected) == size {
		rawExpected = expected
	} else {
		return ErrHashInvalid
	}

	h.Write(passphrase)
	hashedPassphrase := h.Sum(nil)
	if subtle.ConstantTimeCompare(rawExpected, hashedPassphrase) == 1 {
		return nil
	} else {
		return ErrHashCheckFailed
	}
}

func checkAnopeEncSha256(hashBytes, ivBytes, passphrase []byte) (err error) {
	if len(ivBytes) != 32 {
		return ErrHashInvalid
	}
	// https://github.com/anope/anope/blob/2cf507ed662620d0b97c8484fbfbfa09265e86e1/modules/encryption/enc_sha256.cpp#L67
	var iv [8]uint32
	for i := 0; i < 8; i++ {
		iv[i] = binary.BigEndian.Uint32(ivBytes[i*4 : (i+1)*4])
	}
	result := anopeSum256(passphrase, iv)
	if subtle.ConstantTimeCompare(result[:], hashBytes) == 1 {
		return nil
	} else {
		return ErrHashCheckFailed
	}
}

func CheckAnopePassphrase(hash, passphrase []byte) (err error) {
	pieces := bytes.Split(hash, []byte{':'})
	if len(pieces) < 2 {
		return ErrHashInvalid
	}
	switch string(pieces[0]) {
	case "plain":
		// base64, standard encoding
		expectedPassphrase, err := base64.StdEncoding.DecodeString(string(pieces[1]))
		if err != nil {
			return ErrHashInvalid
		}
		if subtle.ConstantTimeCompare(passphrase, expectedPassphrase) == 1 {
			return nil
		} else {
			return ErrHashCheckFailed
		}
	case "md5":
		// raw MD5
		return checkRawHash(pieces[1], passphrase, md5.New())
	case "sha1":
		// raw SHA-1
		return checkRawHash(pieces[1], passphrase, sha1.New())
	case "bcrypt":
		if bcrypt.CompareHashAndPassword(pieces[1], passphrase) == nil {
			return nil
		} else {
			return ErrHashCheckFailed
		}
	case "sha256":
		// SHA-256 with an overridden IV
		if len(pieces) != 3 {
			return ErrHashInvalid
		}
		hashBytes, err := hex.DecodeString(string(pieces[1]))
		if err != nil {
			return ErrHashInvalid
		}
		ivBytes, err := hex.DecodeString(string(pieces[2]))
		if err != nil {
			return ErrHashInvalid
		}
		return checkAnopeEncSha256(hashBytes, ivBytes, passphrase)
	default:
		return ErrHashInvalid
	}
}
