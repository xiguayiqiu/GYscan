module GYscan-Win-C2

go 1.24.5

require (
	github.com/fatih/color v1.16.0
	github.com/fsnotify/fsnotify v1.7.0
	github.com/google/gopacket v1.1.19
	github.com/miekg/dns v1.1.59
	github.com/shirou/gopsutil v3.21.11+incompatible
	github.com/sirupsen/logrus v1.9.3
	golang.org/x/sys v0.36.0
	golang.org/x/text v0.30.0
	gopkg.in/yaml.v3 v3.0.1
)

replace nuclei => ./tools/nuclei

require (
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	golang.org/x/mod v0.28.0 // indirect
	golang.org/x/net v0.44.0 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/tools v0.37.0 // indirect
)
