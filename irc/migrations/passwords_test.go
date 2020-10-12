// Copyright (c) 2020 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package migrations

import (
	"encoding/base64"
	"testing"
)

func TestAthemePassphrases(t *testing.T) {
	var err error

	// modules/crypto/crypt3-md5:
	err = CheckAthemePassphrase([]byte("$1$hcspif$nCm4r3S14Me9ifsOPGuJT."), []byte("shivarampassphrase"))
	if err != nil {
		t.Errorf("failed to check passphrase: %v", err)
	}

	err = CheckAthemePassphrase([]byte("$1$hcspif$nCm4r3S14Me9ifsOPGuJT."), []byte("sh1varampassphrase"))
	if err == nil {
		t.Errorf("accepted invalid passphrase")
	}

	err = CheckAthemePassphrase([]byte("$1$diwesm$9MjapdOyhyC.2FdHzKMzK."), []byte("1Ss1GN4q-3e8SgIJblfQxw"))
	if err != nil {
		t.Errorf("failed to check passphrase: %v", err)
	}
	err = CheckAthemePassphrase([]byte("$1$hcspif$nCm4r3S14Me9ifsOPGuJT."), []byte("sh1varampassphrase"))
	if err == nil {
		t.Errorf("accepted invalid passphrase")
	}

	// modules/crypto/pbkdf2:
	err = CheckAthemePassphrase([]byte("khMlbBBIFya2ihyN42abc3e768663e2c4fd0e0020e46292bf9fdf44e9a51d2a2e69509cb73b4b1bf9c1b6355a1fc9ea663fcd6da902287159494f15b905e5e651d6a60f2ec834598"), []byte("password"))
	if err != nil {
		t.Errorf("failed to check passphrase: %v", err)
	}

	err = CheckAthemePassphrase([]byte("khMlbBBIFya2ihyN42abc3e768663e2c4fd0e0020e46292bf9fdf44e9a51d2a2e69509cb73b4b1bf9c1b6355a1fc9ea663fcd6da902287159494f15b905e5e651d6a60f2ec834598"), []byte("passw0rd"))
	if err == nil {
		t.Errorf("accepted invalid passphrase")
	}

	// modules/crypto/pbkdf2v2:
	err = CheckAthemePassphrase([]byte("$z$65$64000$1kz1I9YJPJ2gkJALbrpL2DoxRDhYPBOg60KNJMK/6do=$Cnfg6pYhBNrVXiaXYH46byrC+3HKet/XvYwvI1BvZbs=$m0hrT33gcF90n2TU3lm8tdm9V9XC4xEV13KsjuT38iY="), []byte("password"))
	if err != nil {
		t.Errorf("failed to check passphrase: %v", err)
	}

	err = CheckAthemePassphrase([]byte("$z$65$64000$1kz1I9YJPJ2gkJALbrpL2DoxRDhYPBOg60KNJMK/6do=$Cnfg6pYhBNrVXiaXYH46byrC+3HKet/XvYwvI1BvZbs=$m0hrT33gcF90n2TU3lm8tdm9V9XC4xEV13KsjuT38iY="), []byte("passw0rd"))
	if err == nil {
		t.Errorf("accepted invalid passphrase")
	}

	weirdHash := []byte("$z$6$64000$rWfIGzPY9qiIt7m5$VdFroDOlTQSLlFUJtpvlbp2i7sH3ZUndqwdnOvoDvt6b2AzLjaAK/lhSO/QaR2nA3Wm4ObHdl3WMW32NdtSMdw==")
	err = CheckAthemePassphrase(weirdHash, []byte("pHQpwje5CjS3_Lx0RaeS7w"))
	if err != nil {
		t.Errorf("failed to check passphrase: %v", err)
	}
	err = CheckAthemePassphrase(weirdHash, []byte("pHQpwje5CjS3-Lx0RaeS7w"))
	if err == nil {
		t.Errorf("accepted invalid passphrase")
	}
}

func TestAthemeRawSha1(t *testing.T) {
	var err error

	shivaramHash := []byte("$rawsha1$49fffa5543f21dd6effe88a79633e4073e36a828")
	err = CheckAthemePassphrase(shivaramHash, []byte("shivarampassphrase"))
	if err != nil {
		t.Errorf("failed to check passphrase: %v", err)
	}
	err = CheckAthemePassphrase(shivaramHash, []byte("edpassphrase"))
	if err == nil {
		t.Errorf("accepted invalid passphrase")
	}
}

func TestOragonoLegacyPassphrase(t *testing.T) {
	shivaramHash, err := base64.StdEncoding.DecodeString("ZPLKvCGipalUo9AlDIlMzAuY/ACWvM3yr1kh7k0/wa7lLlCwaPpe2ht9LNZZlZ9FPUWggUi7D4jyg2WnJDJhJDE0JDRsN0gwVmYvNHlyNjR1U212U2Q0YU9EVmRvWngwcXNGLkkyYVc4eUZISGxYaGE4SWVrRzRt")
	if err != nil {
		panic(err)
	}
	edHash, err := base64.StdEncoding.DecodeString("ZPLKvCGipalUo9AlDIlMzAuY/ACWvM3yr1kh7k0/+42q72mFnpDZWgjmqp1Zd77rEUO8ItYe4aGwWelUJDJhJDE0JHFqSGJ5NWVJbnJTdXBRT29pUmNUUWV5U2xmWjZETlRNcXlSMExUb2RmY3l1Skw2c3BTb3lh")
	if err != nil {
		panic(err)
	}

	err = CheckOragonoPassphraseV0(shivaramHash, []byte("shivarampassphrase"))
	if err != nil {
		t.Errorf("failed to check passphrase: %v", err)
	}
	err = CheckOragonoPassphraseV0(shivaramHash, []byte("edpassphrase"))
	if err == nil {
		t.Errorf("accepted invalid passphrase")
	}

	err = CheckOragonoPassphraseV0(edHash, []byte("edpassphrase"))
	if err != nil {
		t.Errorf("failed to check passphrase: %v", err)
	}
	err = CheckOragonoPassphraseV0(edHash, []byte("shivarampassphrase"))
	if err == nil {
		t.Errorf("accepted invalid passphrase")
	}
}

func TestAnopePassphraseRawSha1(t *testing.T) {
	var err error
	shivaramHash := []byte("sha1:49fffa5543f21dd6effe88a79633e4073e36a828")
	err = CheckAnopePassphrase(shivaramHash, []byte("shivarampassphrase"))
	if err != nil {
		t.Errorf("failed to check passphrase: %v", err)
	}
	err = CheckAnopePassphrase(shivaramHash, []byte("edpassphrase"))
	if err == nil {
		t.Errorf("accepted invalid passphrase")
	}

	edHash := []byte("sha1:ea44e256819de972c25fef0aa277396067d6024f")
	err = CheckAnopePassphrase(edHash, []byte("edpassphrase"))
	if err != nil {
		t.Errorf("failed to check passphrase: %v", err)
	}
	err = CheckAnopePassphrase(edHash, []byte("shivarampassphrase"))
	if err == nil {
		t.Errorf("accepted invalid passphrase")
	}
}

func TestAnopePassphraseRawMd5(t *testing.T) {
	var err error
	shivaramHash := []byte("md5:ce4bd864f37ffaa1b871aef22eea82ff")
	err = CheckAnopePassphrase(shivaramHash, []byte("shivarampassphrase"))
	if err != nil {
		t.Errorf("failed to check passphrase: %v", err)
	}
	err = CheckAnopePassphrase(shivaramHash, []byte("edpassphrase"))
	if err == nil {
		t.Errorf("accepted invalid passphrase")
	}

	edHash := []byte("md5:dbf8be80e8dccdd33915b482e4390426")
	err = CheckAnopePassphrase(edHash, []byte("edpassphrase"))
	if err != nil {
		t.Errorf("failed to check passphrase: %v", err)
	}
	err = CheckAnopePassphrase(edHash, []byte("shivarampassphrase"))
	if err == nil {
		t.Errorf("accepted invalid passphrase")
	}
}

func TestAnopePassphrasePlain(t *testing.T) {
	var err error
	// not actually a hash
	weirdHash := []byte("plain:YVxzMC1fMmZ+ZjM0OEAhN2FzZGYxNDJAIyFhZmE=")
	err = CheckAnopePassphrase(weirdHash, []byte("a\\s0-_2f~f348@!7asdf142@#!afa"))
	if err != nil {
		t.Errorf("failed to check passphrase: %v", err)
	}
	err = CheckAnopePassphrase(weirdHash, []byte("edpassphrase"))
	if err == nil {
		t.Errorf("accepted invalid passphrase")
	}
}

func TestAnopePassphraseBcrypt(t *testing.T) {
	var err error
	shivaramHash := []byte("bcrypt:$2a$10$UyNgHyniPukGf/3A6vzBx.VMNfej0h4WzATg4ahKW2H86a0QLcVIK")
	err = CheckAnopePassphrase(shivaramHash, []byte("shivarampassphrase"))
	if err != nil {
		t.Errorf("failed to check passphrase: %v", err)
	}
	err = CheckAnopePassphrase(shivaramHash, []byte("edpassphrase"))
	if err == nil {
		t.Errorf("accepted invalid passphrase")
	}
}

func TestAnopePassphraseEncSha256(t *testing.T) {
	var err error
	shivaramHash := []byte("sha256:ff337943c8c4219cd330a3075a699492e0f8b1a823bb76af0129f1f117ba0630:60250c3053f7b34e35576fc5063b8b396fe7b9ab416842117991a8e027aa72f6")
	err = CheckAnopePassphrase(shivaramHash, []byte("shivarampassphrase"))
	if err != nil {
		t.Errorf("failed to check passphrase: %v", err)
	}
	err = CheckAnopePassphrase(shivaramHash, []byte("edpassphrase"))
	if err == nil {
		t.Errorf("accepted invalid passphrase")
	}

	edHash := []byte("sha256:93a430c8c3c6917dc6e9a32ac1aba90bc5768265278a45b86eacd636fc723d8f:10ea72683a499c155d72cd3571cb80e5050280620f789a44492c0e0c7956942f")
	err = CheckAnopePassphrase(edHash, []byte("edpassphrase"))
	if err != nil {
		t.Errorf("failed to check passphrase: %v", err)
	}
	err = CheckAnopePassphrase(edHash, []byte("shivarampassphrase"))
	if err == nil {
		t.Errorf("accepted invalid passphrase")
	}

	weirdHash := []byte("sha256:06d11a06025354e37a7ddf48913a1c9831ffab47d04e4c22a89fd7835abcb6cc:3137788c2749da0419bc9df320991d2d72495c7065da4f39004fd21710601409")
	err = CheckAnopePassphrase(weirdHash, []byte("1Ss1GN4q-3e8SgIJblfQxw"))
	if err != nil {
		t.Errorf("failed to check passphrase: %v", err)
	}
	err = CheckAnopePassphrase(weirdHash, []byte("shivarampassphrase"))
	if err == nil {
		t.Errorf("accepted invalid passphrase")
	}
}
