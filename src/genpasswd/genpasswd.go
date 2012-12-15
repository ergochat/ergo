package main

import (
	"code.google.com/p/go.crypto/bcrypt"
	"encoding/base64"
	"flag"
	"fmt"
)

func main() {
	flag.Parse()
	password := flag.Arg(0)
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(hash))
}
