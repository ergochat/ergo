module github.com/ergochat/ergo

go 1.16

require (
	code.cloudfoundry.org/bytefmt v0.0.0-20200131002437-cf55d5288a48
	github.com/GehirnInc/crypt v0.0.0-20200316065508-bb7000b8a962
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/docopt/docopt-go v0.0.0-20180111231733-ee0de3bc6815
	github.com/ergochat/confusables v0.0.0-20201108231250-4ab98ab61fb1
	github.com/ergochat/go-ident v0.0.0-20200511222032-830550b1d775
	github.com/go-sql-driver/mysql v1.6.0
	github.com/go-test/deep v1.0.6 // indirect
	github.com/gorilla/websocket v1.4.2
	github.com/goshuirc/irc-go v0.0.0-20210318074529-bdc2c2cd2fef
	github.com/onsi/ginkgo v1.12.0 // indirect
	github.com/onsi/gomega v1.9.0 // indirect
	github.com/oragono/confusables v0.0.0-20201108231250-4ab98ab61fb1 // indirect
	github.com/oragono/go-ident v0.0.0-20200511222032-830550b1d775 // indirect
	github.com/stretchr/testify v1.4.0 // indirect
	github.com/tidwall/buntdb v1.2.3
	github.com/tidwall/rtree v0.0.0-20201027154624-32188eeb08a8 // indirect
	github.com/toorop/go-dkim v0.0.0-20201103131630-e1cd1a0a5208
	golang.org/x/crypto v0.0.0-20210415154028-4f45737414dc
	golang.org/x/text v0.3.6
	gopkg.in/yaml.v2 v2.4.0
)

replace github.com/gorilla/websocket => github.com/ergochat/websocket v1.4.2-oragono1
