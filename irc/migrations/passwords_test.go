// Copyright (c) 2020 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package migrations

import (
	"encoding/base64"
	"testing"
)

func TestAthemePassphrases(t *testing.T) {
	var err error

	err = CheckAthemePassphrase([]byte("$1$hcspif$nCm4r3S14Me9ifsOPGuJT."), []byte("shivarampassphrase"))
	if err != nil {
		t.Errorf("failed to check passphrase: %v", err)
	}

	err = CheckAthemePassphrase([]byte("$1$hcspif$nCm4r3S14Me9ifsOPGuJT."), []byte("sh1varampassphrase"))
	if err == nil {
		t.Errorf("accepted invalid passphrase")
	}

	err = CheckAthemePassphrase([]byte("khMlbBBIFya2ihyN42abc3e768663e2c4fd0e0020e46292bf9fdf44e9a51d2a2e69509cb73b4b1bf9c1b6355a1fc9ea663fcd6da902287159494f15b905e5e651d6a60f2ec834598"), []byte("password"))
	if err != nil {
		t.Errorf("failed to check passphrase: %v", err)
	}

	err = CheckAthemePassphrase([]byte("khMlbBBIFya2ihyN42abc3e768663e2c4fd0e0020e46292bf9fdf44e9a51d2a2e69509cb73b4b1bf9c1b6355a1fc9ea663fcd6da902287159494f15b905e5e651d6a60f2ec834598"), []byte("passw0rd"))
	if err == nil {
		t.Errorf("accepted invalid passphrase")
	}

	err = CheckAthemePassphrase([]byte("$z$65$64000$1kz1I9YJPJ2gkJALbrpL2DoxRDhYPBOg60KNJMK/6do=$Cnfg6pYhBNrVXiaXYH46byrC+3HKet/XvYwvI1BvZbs=$m0hrT33gcF90n2TU3lm8tdm9V9XC4xEV13KsjuT38iY="), []byte("password"))
	if err != nil {
		t.Errorf("failed to check passphrase: %v", err)
	}

	err = CheckAthemePassphrase([]byte("$z$65$64000$1kz1I9YJPJ2gkJALbrpL2DoxRDhYPBOg60KNJMK/6do=$Cnfg6pYhBNrVXiaXYH46byrC+3HKet/XvYwvI1BvZbs=$m0hrT33gcF90n2TU3lm8tdm9V9XC4xEV13KsjuT38iY="), []byte("passw0rd"))
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
