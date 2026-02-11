module github.com/ergochat/ergo

go 1.26

require (
	code.cloudfoundry.org/bytefmt v0.0.0-20200131002437-cf55d5288a48
	github.com/GehirnInc/crypt v0.0.0-20200316065508-bb7000b8a962
	github.com/docopt/docopt-go v0.0.0-20180111231733-ee0de3bc6815
	github.com/ergochat/confusables v0.0.0-20201108231250-4ab98ab61fb1
	github.com/ergochat/go-ident v0.0.0-20230911071154-8c30606d6881
	github.com/ergochat/irc-go v0.5.0-rc2
	github.com/go-sql-driver/mysql v1.9.3
	github.com/gofrs/flock v0.8.1
	github.com/gorilla/websocket v1.4.2
	github.com/okzk/sdnotify v0.0.0-20180710141335-d9becc38acbd
	github.com/onsi/ginkgo v1.12.0 // indirect
	github.com/onsi/gomega v1.9.0 // indirect
	github.com/stretchr/testify v1.4.0 // indirect
	github.com/tidwall/buntdb v1.3.2
	github.com/xdg-go/scram v1.0.2
	golang.org/x/crypto v0.46.0
	golang.org/x/term v0.38.0
	golang.org/x/text v0.32.0
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/emersion/go-msgauth v0.7.0
	github.com/ergochat/webpush-go/v2 v2.0.0
	github.com/golang-jwt/jwt/v5 v5.3.0
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/tidwall/btree v1.4.2 // indirect
	github.com/tidwall/gjson v1.14.3 // indirect
	github.com/tidwall/grect v0.1.4 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	github.com/tidwall/rtred v0.1.2 // indirect
	github.com/tidwall/tinyqueue v0.1.1 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
)

replace github.com/gorilla/websocket => github.com/ergochat/websocket v1.4.2-oragono1

replace github.com/xdg-go/scram => github.com/ergochat/scram v1.0.2-ergo1
