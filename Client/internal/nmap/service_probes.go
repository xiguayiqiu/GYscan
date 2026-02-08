package nmap

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	ServiceProbeVersion = "1.0"
)

var (
	ftpControlRegex       = regexp.MustCompile(`(?i)^220[- ]`)
	ftpFeaturesRegex      = regexp.MustCompile(`(?i)features|extensions|sIZE|MLST|MLSD`)
	ftpAuthRegex          = regexp.MustCompile(`(?i)(vsftpd|proftpd|pure-ftpd|wU-ftpd|filezilla)`)
	sshGreetingRegex      = regexp.MustCompile(`(?i)^SSH-([0-9.]+)-`)
	opensshRegex          = regexp.MustCompile(`(?i)openssh[_-]([0-9.]+)`)
	dropbearRegex         = regexp.MustCompile(`(?i)dropbear_ssh_([0-9.]+)`)
	smtpGreetingRegex     = regexp.MustCompile(`(?i)^220[- ]`)
	smtpAuthRegex         = regexp.MustCompile(`(?i)(postfix|exim|sendmail|qmail|microsoft.?esmtps?)`)
	httpServerRegex       = regexp.MustCompile(`(?i)server:`)
	httpProductRegex      = regexp.MustCompile(`(?i)(apache|nginx|iis|lighttpd|caddy|tomcat|jetty)`)
	httpsRegex            = regexp.MustCompile(`(?i)ssl|https|tls`)
	mysqlGreetingRegex    = regexp.MustCompile(`(?i)mysql`)
	mysqlVersionRegex     = regexp.MustCompile(`(\d+\.\d+\.\d+)`)
	postgresGreetingRegex = regexp.MustCompile(`(?i)postgresql`)
	redisGreetingRegex    = regexp.MustCompile(`(?i)redis`)
	mongodbGreetingRegex  = regexp.MustCompile(`(?i)mongodb`)
	oracleGreetingRegex   = regexp.MustCompile(`(?i)oracle|tns`)
	mssqlGreetingRegex    = regexp.MustCompile(`(?i)sql server|microsoft sql`)
	ldapGreetingRegex     = regexp.MustCompile(`(?i)ldap|openldap`)
	imapGreetingRegex     = regexp.MustCompile(`(?i)\* ok.*imap`)
	pop3GreetingRegex     = regexp.MustCompile(`(?i)\+ok.*pop3`)
	dnsGreetingRegex      = regexp.MustCompile(`(?i)version.bind|response`)
	ntpGreetingRegex      = regexp.MustCompile(`(?i)ntp`)
	snmpGreetingRegex     = regexp.MustCompile(`(?i)snmp`)
	tftpGreetingRegex     = regexp.MustCompile(`(?i)tftp`)
	syslogGreetingRegex   = regexp.MustCompile(`(?i)syslog`)
	sipGreetingRegex      = regexp.MustCompile(`(?i)sip|via:|contact:`)
	rdpGreetingRegex      = regexp.MustCompile(`(?i)rdp|nla`)
	vncGreetingRegex      = regexp.MustCompile(`(?i)vnc|RFB`)
	ftp220Regex           = regexp.MustCompile(`(?i)^220 `)
)

func GenerateXMLOutput(results []NmapResult, config ScanConfig, startTime, endTime time.Time) string {
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="GYscan" version="`)
	sb.WriteString(ServiceProbeVersion)
	sb.WriteString(`" xmloutputversion="1.04">
`)
	sb.WriteString(fmt.Sprintf("<args>%s</args>\n", generateArgsString(config)))
	sb.WriteString(fmt.Sprintf("<started>%s</started>\n", startTime.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("<finished>%s</finished>\n", endTime.Format(time.RFC3339)))

	for _, result := range results {
		sb.WriteString(generateHostXML(result, config))
	}

	sb.WriteString("</nmaprun>\n")
	return sb.String()
}

func generateArgsString(config ScanConfig) string {
	var args []string
	args = append(args, "GYscan")
	args = append(args, "scan")
	if config.Target != "" {
		args = append(args, config.Target)
	}
	if config.Ports != "" {
		args = append(args, "-p", config.Ports)
	}
	if config.Threads != 0 {
		args = append(args, "-n", fmt.Sprintf("%d", config.Threads))
	}
	return strings.Join(args, " ")
}

func generateHostXML(result NmapResult, config ScanConfig) string {
	var sb strings.Builder
	sb.WriteString("<host>\n")
	sb.WriteString(fmt.Sprintf("<status state=\"%s\" reason=\"echo-reply\"/>\n", result.Status))

	addrType := "ipv4"
	if strings.Contains(result.IP, ":") {
		addrType = "ipv6"
	}
	vendor := ""
	if result.MACVendor != "" {
		vendor = result.MACVendor
	}
	sb.WriteString(fmt.Sprintf("<address addr=\"%s\" addrtype=\"%s\" vendor=\"%s\"/>\n", result.IP, addrType, vendor))

	if result.Hostname != "" {
		sb.WriteString(fmt.Sprintf("<hostnames>\n<hostname name=\"%s\" type=\"user\"/>\n</hostnames>\n", result.Hostname))
	}

	sb.WriteString("<ports>\n")
	openCount := 0
	filteredCount := 0

	for _, portInfo := range result.Ports {
		if portInfo.State == PortStateOpen {
			openCount++
			sb.WriteString(fmt.Sprintf("<port protocol=\"%s\" portid=\"%d\">\n", portInfo.Protocol, portInfo.Port))
			sb.WriteString(fmt.Sprintf("<state state=\"%s\"/>\n", portInfo.State))
			sb.WriteString(fmt.Sprintf("<service name=\"%s\" conf=\"10\"/>\n", portInfo.Service))
			sb.WriteString("</port>\n")
		} else if portInfo.State == PortStateFiltered {
			filteredCount++
		}
	}

	if filteredCount > 0 {
		sb.WriteString(fmt.Sprintf("<extraports state=\"filtered\" count=\"%d\"/>\n", filteredCount))
	}

	sb.WriteString("</ports>\n")

	if result.OS != "" {
		sb.WriteString("<os>\n")
		sb.WriteString(fmt.Sprintf("<osmatch name=\"%s\" accuracy=\"95\"/>\n", result.OS))
		sb.WriteString("</os>\n")
	}

	if result.NetworkDistance > 0 {
		sb.WriteString(fmt.Sprintf("<distance value=\"%d\"/>\n", result.NetworkDistance))
	}

	if len(result.Services) > 0 {
		sb.WriteString("<serviceinfo>\n")
		for _, service := range result.Services {
			sb.WriteString(fmt.Sprintf("<service name=\"%s\"/>\n", service))
		}
		sb.WriteString("</serviceinfo>\n")
	}

	sb.WriteString("</host>\n")
	return sb.String()
}

func GenerateJSONOutput(results []NmapResult, config ScanConfig, startTime, endTime time.Time) string {
	var sb strings.Builder
	sb.WriteString("{\n")
	sb.WriteString(fmt.Sprintf(`  "nmaprun": {
    "scanner": "GYscan",
    "version": "%s",
    "xmloutputversion": "1.04",
    "args": "%s",
    "start": %d,
    "started": "%s",
    "finished": "%s"
  },
`, ServiceProbeVersion, generateArgsString(config),
		startTime.Unix(), startTime.Format(time.RFC3339),
		endTime.Format(time.RFC3339)))

	sb.WriteString(`  "scaninfo": {
    "type": "`)
	sb.WriteString(config.ScanType)
	sb.WriteString(`",
    "protocol": "tcp",
    "services": "`)
	sb.WriteString(config.Ports)
	sb.WriteString(`"
  },
`)

	sb.WriteString(`  "hosts": [
`)
	for i, result := range results {
		if i > 0 {
			sb.WriteString(",\n")
		}
		sb.WriteString(generateHostJSON(result, config))
	}
	sb.WriteString("\n  ]\n")
	sb.WriteString("}\n")
	return sb.String()
}

func generateHostJSON(result NmapResult, config ScanConfig) string {
	var sb strings.Builder
	sb.WriteString("    {\n")
	sb.WriteString(fmt.Sprintf(`      "status": { "state": "%s", "reason": "response" },
`, result.Status))
	sb.WriteString(fmt.Sprintf(`      "addresses": [ { "addr": "%s", "addrtype": "ipv4" } ],
`, result.IP))

	if result.Hostname != "" {
		sb.WriteString(fmt.Sprintf(`      "hostnames": [ { "name": "%s", "type": "user" } ],
`, result.Hostname))
	}

	sb.WriteString(`      "ports": {
        "port": [
`)
	first := true
	for portID, portInfo := range result.Ports {
		if portInfo.State == PortStateOpen {
			if !first {
				sb.WriteString(",\n")
			}
			first = false
			sb.WriteString(fmt.Sprintf(`          {
            "protocol": "%s",
            "portid": %d,
            "state": { "state": "%s" },
            "service": { "name": "%s", "conf": 10 }
          }`, portInfo.Protocol, portID, portInfo.State, portInfo.Service))
		}
	}
	sb.WriteString("\n        ]\n      }")

	if result.OS != "" {
		sb.WriteString(",\n")
		sb.WriteString(fmt.Sprintf(`      "os": { "name": "%s", "accuracy": 95 }`, result.OS))
	}

	if result.NetworkDistance > 0 {
		sb.WriteString(",\n")
		sb.WriteString(fmt.Sprintf(`      "distance": { "value": %d }`, result.NetworkDistance))
	}

	sb.WriteString("\n    }")
	return sb.String()
}

func SaveXMLOutput(results []NmapResult, config ScanConfig, filename string, startTime, endTime time.Time) error {
	xmlContent := GenerateXMLOutput(results, config, startTime, endTime)
	return writeToFile(filename, xmlContent)
}

func SaveJSONOutput(results []NmapResult, config ScanConfig, filename string, startTime, endTime time.Time) error {
	jsonContent := GenerateJSONOutput(results, config, startTime, endTime)
	return writeToFile(filename, jsonContent)
}

func writeToFile(filename, content string) error {
	return nil
}
