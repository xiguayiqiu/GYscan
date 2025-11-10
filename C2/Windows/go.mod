module GYscan-Win-C2

go 1.24.5

require (
	github.com/fatih/color v1.16.0
	github.com/miekg/dns v1.1.59
	github.com/sirupsen/logrus v1.9.3
	golang.org/x/text v0.30.0
	gopkg.in/yaml.v3 v3.0.1
)

replace nuclei => ./tools/nuclei

require (
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	golang.org/x/mod v0.28.0 // indirect
	golang.org/x/net v0.44.0 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
	golang.org/x/tools v0.37.0 // indirect
)
