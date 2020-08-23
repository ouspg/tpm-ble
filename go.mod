module github.com/ouspg/tpm-ble

go 1.13

require (
	github.com/godbus/dbus/v5 v5.0.3
	github.com/jarijaas/openssl v0.0.0-20200630155839-c36f4d70f4e2
	github.com/muka/go-bluetooth v0.0.0-20200819055636-48af5af2c29a
	github.com/sirupsen/logrus v1.6.0
	github.com/spacemonkeygo/openssl v0.0.0-20181017203307-c2dcc5cca94a // indirect
	golang.org/x/sys v0.0.0-20200728102440-3e129f6d46b1
)

replace github.com/muka/go-bluetooth v0.0.0-20200819055636-48af5af2c29a => ./go-bluetooth/
