// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/DanielOaks/oragono/irc"
	"github.com/docopt/docopt-go"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	version := irc.SEM_VER
	usage := `oragono.
Usage:
	oragono initdb [--conf <filename>]
	oragono upgradedb [--conf <filename>]
	oragono genpasswd [--conf <filename>]
	oragono createcerts [--conf <filename>]
	oragono run [--conf <filename>]
	oragono -h | --help
	oragono --version
Options:
	--conf <filename>  Configuration file to use [default: ircd.yaml].
	-h --help          Show this screen.
	--version          Show version.`

	arguments, _ := docopt.Parse(usage, nil, true, version, false)

	configfile := arguments["--conf"].(string)
	config, err := irc.LoadConfig(configfile)
	if err != nil {
		log.Fatal("Config file did not load successfully:", err.Error())
	}

	if arguments["genpasswd"].(bool) {
		fmt.Print("Enter Password: ")
		bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatal("Error reading password:", err.Error())
		}
		password := string(bytePassword)
		encoded, err := irc.GenerateEncodedPassword(password)
		if err != nil {
			log.Fatalln("encoding error:", err)
		}
		fmt.Print("\n")
		fmt.Println(encoded)
	} else if arguments["initdb"].(bool) {
		irc.InitDB(config.Server.Database)
		log.Println("database initialized: ", config.Server.Database)
	} else if arguments["upgradedb"].(bool) {
		irc.UpgradeDB(config.Server.Database)
		log.Println("database upgraded: ", config.Server.Database)
	} else if arguments["createcerts"].(bool) {
		log.Println("creating self-signed certificates")

		for name, conf := range config.Server.TLSListeners {
			log.Printf(" creating cert for %s listener\n", name)
			host := config.Server.Name
			validFrom := time.Now()
			validFor := 365 * 24 * time.Hour
			notAfter := validFrom.Add(validFor)

			priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)

			serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
			serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
			if err != nil {
				log.Fatalf("failed to generate serial number: %s", err)
			}

			template := x509.Certificate{
				SerialNumber: serialNumber,
				Subject: pkix.Name{
					Organization: []string{"Oragono"},
				},
				NotBefore: validFrom,
				NotAfter:  notAfter,

				KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				BasicConstraintsValid: true,
			}

			// TODO: allow explicitly listing allowed addresses/names
			template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"))
			template.IPAddresses = append(template.IPAddresses, net.ParseIP("::1"))
			template.DNSNames = append(template.DNSNames, host)
			template.DNSNames = append(template.DNSNames, "localhost")

			derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
			if err != nil {
				log.Fatalf("Failed to create certificate: %s", err)
			}

			certOut, err := os.Create(conf.Cert)
			if err != nil {
				log.Fatalf("failed to open %s for writing: %s", conf.Cert, err)
			}
			pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
			certOut.Close()
			log.Printf("  wrote %s\n", conf.Cert)

			keyOut, err := os.OpenFile(conf.Key, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
			if err != nil {
				log.Print("failed to open %s for writing:", conf.Key, err)
				return
			}
			b, err := x509.MarshalECPrivateKey(priv)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
				os.Exit(2)
			}
			pemBlock := pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
			pem.Encode(keyOut, &pemBlock)
			keyOut.Close()
			log.Printf("  wrote %s\n", conf.Key)
		}
	} else if arguments["run"].(bool) {
		irc.Log.SetLevel(config.Server.Log)
		server := irc.NewServer(config)
		log.Println(irc.SEM_VER, "running")
		defer log.Println(irc.SEM_VER, "exiting")
		server.Run()
	}
}
