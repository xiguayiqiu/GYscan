package subdomain

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"GYscan/internal/utils"
)

var scanStartTime time.Time

type SubdomainConfig struct {
	Domain     string
	Wordlist   string
	Threads    int
	Timeout    time.Duration
	Output     string
	QueryType  string
	VerifyHTTP bool
}

type SubdomainResult struct {
	Subdomain  string
	IP         string
	HTTPStatus int
}

type SubdomainScanner struct {
	config       *SubdomainConfig
	wordlist     []string
	wg           sync.WaitGroup
	mutex        sync.Mutex
	foundCount   int64
	totalWords   int
	scannedCount int64
	wildcardIPs  map[string]bool
	allResults   []SubdomainResult
	startTime    time.Time
}

var (
	defaultWordlist = []string{
		"a", "a1", "a2", "a3", "a4", "a5", "aa", "ab", "abc", "b", "bc", "bb", "bj", "bh", "bo", "c", "c1", "c2", "c3", "c4", "c5", "cc", "cha", "cq", "cx", "cz", "d", "d0", "d1", "d2", "d3", "da", "dq", "e", "er", "ever", "f", "g", "gao", "gay", "gps", "h", "he", "i", "ips", "j", "jj", "k", "key", "keys", "l", "lv", "la", "m", "mybaby", "n", "none", "no", "o", "op", "ok", "okay", "ow", "of", "off", "p", "pb", "pq", "q", "qps", "r", "s", "ss", "sex", "t", "tt", "u", "uu", "user", "v", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "vv", "w", "w0", "w1", "w2", "w3", "w4", "wp", "why", "x", "y", "y0", "y1", "y2", "y3", "yp", "yy", "z", "z0", "z1", "z2", "z3", "z5", "zz", "0", "01", "1", "11", "2", "22", "1997", "1998", "2000", "2001", "2002", "2003", "2004", "2005", "2006", "2007", "2008", "2009", "2010", "2011", "2012", "2013", "2014", "2015", "2016", "ww", "www", "www0", "www1", "www2", "www3", "www4", "www5", "wap", "wap1", "wap2", "wap3", "main", "main1", "cms", "main2", "mall", "help", "help1", "mail", "mail1", "email", "system", "sys", "temp", "temp0", "temp1", "temp2", "temp3", "tmp", "tmp0", "tmp1", "tmp2", "tmp3", "blog", "blog1", "city", "pmt", "josn", "version", "ver", "demo", "demo0", "demo1", "demo2", "demo3", "demo4", "demo5", "demo6", "demo7", "new", "news", "old", "old1", "old2", "old3", "api", "api1", "api2", "api3", "api4", "apis", "img", "img0", "img1", "img2", "img3", "img4", "img5", "img6", "img7", "mini", "ai", "emlog", "android", "ios", "ios6", "ios7", "app", "apps", "map", "apk", "as", "developer", "snow", "book", "cue", "erp", "note", "edit", "editor", "cell", "call", "feedback", "feed", "rss", "faq", "page", "union", "select", "del", "delete", "remove", "move", "shuqian", "sq", "error", "read", "reader", "err", "static", "state", "tousu", "chrom", "ox", "notefeedback", "tuan", "tuangou", "ceo", "beta", "cat", "dog", "bae", "br", "cp", "copy", "os", "complain", "baoku", "start", "stop", "runing", "hot", "ht", "team", "999", "vs", "ps", "shit", "war", "house", "linux", "bbs", "bbs1", "bbs2", "bbs3", "oldbbs", "forum", "forum1", "forum2", "administrator", "apple", "biy", "girl", "class", "columbus", "corp", "crm", "database", "docs", "rom", "buy", "by", "mi", "sea", "game", "group", "hr", "ip", "css", "phone", "movie", "mobile", "content", "comment", "back", "login", "log", "logs", "name", "red", "reports", "report", "root", "win", "windown", "windowns", "z-log", "wordpress", "msg", "msg0", "msg1", "msg2", "msg3", "msg4", "msg5", "message", "my", "zhaopin", "offer", "open", "openapi", "fox", "bug", "front", "groups", "guest", "hello", "install", "ipv4", "ipv6", "pass", "pass1", "pass2", "pass3", "passport", "port", "port0", "port1", "port2", "port3", "port4", "port5", "port6", "port7", "pc", "vip", "qiao", "post", "js", "ku", "id", "cn", "us", "en", "alpha", "express", "cdn", "down", "down0", "down1", "down2", "down3", "down4", "down5", "down6", "download", "download0", "download1", "download2", "download3", "download4", "online", "push", "push0", "push1", "push2", "push3", "admin", "admin0", "admin1", "admin2", "admin3", "admin5", "manage", "houtai", "manager", "guanli", "test", "test0", "test1", "test2", "test3", "test4", "test5", "shop", "shoping", "more", "put", "putdata", "date", "get", "try", "web", "shouji", "webapi", "360", "ditu", "soso", "sousuo", "huodong", "beta1", "beta2", "beta3", "beta4", "beta5", "product", "author", "activity", "request", "response", "account", "theme", "flash", "youxi", "portal", "apiserver", "china", "server", "server0", "server1", "server2", "server3", "server4", "server5", "service", "service0", "service1", "service2", "service3", "service4", "service5", "renwu", "rp", "yu", "yun", "pan", "yunpan", "zip", "xss", "sql", "execute", "exec", "exec1", "exec2", "exec3", "tieba", "weibo", "weibo1", "weibo2", "weibo3", "tw", "hk", "qq", "qq1", "qq2", "qq3", "kiss", "love", "master", "webmaster", "sub", "music", "music0", "music1", "music2", "music3", "music4", "music5", "video", "video0", "video1", "video2", "video3", "video4", "video5", "dvd", "in", "mp3", "mp4", "mp5", "full", "share", "share0", "share1", "share2", "share3", "share4", "share5", "soft", "soft0", "soft1", "soft2", "soft3", "soft4", "soft5", "softdown", "plus", "plus0", "plus1", "plus2", "plus3", "plus5", "upgrade", "update", "on", "pm25", "pm", "ad", "adm", "admi", "ads", "line", "apt", "view", "show", "show0", "show1", "show2", "show3", "show4", "show5", "git", "git0", "git1", "git2", "mang", "svn", "svn0", "svn1", "svn2", "svn3", "run", "sec", "security", "play", "payment", "pay", "alipay", "appliction", "public", "tool", "tool0", "tool1", "tool2", "tool3", "tools", "tools0", "tools1", "tools2", "tools3", "mm", "anquan", "aq", "gl", "dl", "bank", "zhidao", "image", "pic", "pic0", "pic1", "pic2", "pic3", "pic4", "pic5", "pic6", "pic7", "pic8", "picture", "browse", "webbrowse", "jiankong", "control", "panl", "fire", "free", "wenku", "clear", "lan", "wan", "client", "wiki", "hi", "atm", "say", "homepage", "monitor", "kf", "print", "click", "website", "safe", "bate", "best", "happy", "style", "colse", "password", "lucky", "text", "txt", "file", "normal", "search", "money", "doc", "lib", "lib0", "lib1", "lib2", "lib3", "bin", "bin0", "bin1", "bin2", "bin3", "http", "java", "php", "python", "oracle", "mysql", "mssql", "sqlserver", "virtual", "asp", "aspx", "jsp", "tomcat", "host", "phpmyadmin", "phpmyad", "phpmyadm", "myadm", "zone", "address", "firewall", "photo", "menus", "alias", "menu", "release", "debug", "path", "color", "dll", "exe", "so", "abs", "cacti", "tpm", "oa", "ria", "3com", "98-62", "hinet-ip", "ilmi", "unused", "a.auth-ns", "a01", "a02", "abhsia", "about", "ac", "academico", "acceso", "access", "accounting", "accounts", "acessonet", "acid", "activestat", "adam", "adkit", "administracion", "administrador", "administrators", "admins", "adserver", "adsl", "adslgp", "advance", "ae", "af", "affiliate", "affiliates", "afiliados", "ag", "agenda", "agent", "aix", "ajax", "ak", "akamai", "al", "alabama", "alaska", "albq", "albuquerque", "alerts", "alestra", "alterwind", "am", "amarillo", "amedd", "americas", "an", "anaheim", "analyzer", "announce", "announcements", "antivirus", "ao", "ap", "apache", "apg", "apol", "apollo", "app01", "app1", "application", "applications", "applwi", "appserver", "ar", "arc", "archie", "arcsight", "argentina", "arizona", "arkansas", "arlington", "arpa", "ars", "as400", "asia", "asianet", "asm", "asterix", "at", "athena", "atlanta", "atlas", "att", "au", "auction", "austin", "austtx", "auth", "auto", "av", "available", "avantel", "aw", "ayuda", "az", "b.auth-ns", "b01", "b02", "b2b", "b2c", "ba", "backend", "backup", "baker", "bakersfield", "balance", "balancer", "baltimore", "banking", "bayarea", "bbdd", "bchsia", "bcvloh", "bd", "bdc", "be", "bea", "bf", "bg", "bgk", "bhm", "bi", "bigpond", "billing", "biz", "biztalk", "black", "blackberry", "bliss", "blogs", "blue", "blueyonder", "bm", "bn", "bna", "bnc", "bob", "bof", "bois", "boise", "bol", "bolsa", "bootp", "border", "boston", "boulder", "boy", "bpb", "brasiltelecom", "bravo", "brazil", "bredband", "britian", "broadband", "broadcast", "broker", "bronze", "brown", "bs", "bsd", "bsd0", "bsd01", "bsd02", "bsd1", "bsd2", "bt", "btas", "buffalo", "buggalo", "bugs", "bugzilla", "build", "bulletins", "burn", "burner", "buscador", "business", "bv", "bw", "bz", "c.auth-ns", "ca", "cable", "cache", "cae", "cafe", "calendar", "california", "calvin", "canada", "canal", "canon", "careers", "catalog", "ccgg", "cd", "cdburner", "cert", "certificates", "certify", "certserv", "certsrv", "cf", "cg", "cgi", "ch", "channel", "channels", "charlie", "charlotte", "chat", "chats", "chatserver", "chcgil", "check", "checkpoint", "chi", "chicago", "chs", "ci", "cicril", "cidr", "cims", "cinci", "cincinnati", "cisco", "citrix", "ck", "cl", "classes", "classifieds", "classroom", "cleveland", "clicktrack", "clientes", "clients", "clsp", "clt", "clta", "club", "clubs", "cluster", "clusters", "cm", "cmail", "co", "cocoa", "code", "codetel", "coldfusion", "colombus", "colorado", "com", "commerce", "commerceserver", "communigate", "community", "compaq", "compras", "compute-1", "con", "concentrator", "conf", "conference", "conferencing", "confidential", "connect", "connecticut", "consola", "console", "consult", "consultant", "consultants", "consulting", "consumer", "contact", "contracts", "core", "core0", "core01", "cork", "corp-eur", "corpmail", "corporate", "correo", "correoweb", "cortafuegos", "counterstrike", "courses", "cpe", "cr", "cricket", "crs", "cs", "cso", "ct", "cu", "cust", "cust-adsl", "cust1", "customer", "customers", "cv", "cvs", "cy", "detail", "details", "guanjia", "guanji", "make", "cidian", "config", "flow", "salary", "zabbix", "nvren", "women", "meeting", "develop", "portrait", "head", "domain", "meinv", "webmain", "webadmin", "webmanage", "shegong", "aiqing", "db2", "passing", "dnsserver", "dns", "heike", "jiasu", "cache1", "cache2", "cache3", "cache4", "ipad", "song", "debian", "chrome", "dallas", "data", "database01", "database02", "database1", "database2", "databases", "datastore", "datos", "david", "db", "db0", "db01", "db02", "db1", "dc", "de", "dealers", "dec", "ded", "def", "default", "defiant", "delaware", "dell", "delta", "delta1", "demon", "demonstration", "demos", "denver", "deploy", "depot", "des", "desarrollo", "descargas", "design", "designer", "detroit", "dev", "dev0", "dev01", "dev1", "devel", "developers", "development", "device", "devserver", "devsql", "dhcp", "dhcp-bl", "dhcp-in", "dhcp4", "dial", "dialuol", "dialup", "digital", "digitaltv", "dilbert", "dion", "dip", "dip0", "dir", "direct", "directory", "disc", "discovery", "discuss", "discussion", "discussions", "disk", "disney", "distributer", "distributers", "dj", "dk", "dm", "dmail", "dmz", "dnews", "dns-2", "dns0", "dns1", "dns2", "dns3", "do", "documentacion", "documentos", "domains", "dominio", "domino", "dominoweb", "domolink", "doom", "downloads", "downtown", "dragon", "drupal", "dsl", "dsl-w", "dt", "dti", "dublin", "dyn", "dynamic", "dynamicip", "dynip", "dz", "e-com", "e-commerce", "eagle", "earth", "east", "ec", "echo", "ecom", "ecommerce", "ed", "edi", "edu", "education", "edward", "ee", "eg", "eh", "ejemplo", "elpaso", "embratel", "emhril", "employees", "empresa", "empresas", "enable", "eng", "eng01", "eng1", "engine", "engineer", "engineering", "enterprise", "eonet", "epm", "epsilon", "es", "esd", "esm", "espanol", "est", "estadisticas", "esx", "et", "eta", "etb", "eu", "eur", "europe", "events", "example", "exchange", "extern", "external", "extranet", "falcon", "farm", "faststats", "fax", "fbx", "feeds", "fi", "fibertel", "field", "files", "fileserv", "fileserver", "filestore", "filter", "find", "finger", "fios", "fix", "fixes", "fj", "fk", "fl", "florida", "fm", "fo", "foobar", "formacion", "foro", "foros", "fortworth", "forums", "foto", "fotos", "foundry", "foxtrot", "fr", "france", "frank", "fred", "freebsd", "freebsd0", "freebsd01", "freebsd02", "freebsd1", "freebsd2", "freeware", "fresno", "frokca", "frontdesk", "fs", "fsp", "ftas", "ftd", "ftp", "ftp0", "ftp2", "ftp_", "ftpserver", "fw", "fw-1", "fw1", "fwd", "fwsm", "fwsm0", "fwsm01", "fwsm1", "ga", "galeria", "galerias", "galleries", "gallery", "galway", "games", "gamma", "gandalf", "gate", "gatekeeper", "gateway", "gauss", "gd", "ge", "gemini", "general", "genericrev", "george", "georgia", "germany", "gf", "gg", "gh", "gi", "giga", "glendale", "global", "gm", "gmail", "gn", "go", "gold", "goldmine", "golf", "gopher", "gordon", "gp", "gprs", "gq", "gr", "green", "groupwise", "gs", "gsp", "gsx", "gt", "gtcust", "gu", "gvt", "gw", "gw1", "gy", "gye", "hal", "halflife", "hawaii", "helpdesk", "helponline", "henry", "hermes", "hfc", "hidden", "hidden-host", "highway", "hkcable", "hlrn", "hm", "hn", "hobbes", "hollywood", "home", "homebase", "homer", "homerun", "honeypot", "honolulu", "host1", "host3", "host4", "host5", "hotel", "hotjobs", "houstin", "houston", "howto", "hp", "hpov", "hrlntx", "hsia", "hstntx", "hsv", "https", "hu", "hub", "humanresources", "ia", "ias", "ibm", "ibmdb", "ida", "idaho", "ids", "ie", "iern", "ig", "iis", "il", "illinois", "im", "images", "imail", "imap", "imap4", "img01", "img02", "impsat", "in-addr", "inbound", "inc", "include", "incoming", "india", "indiana", "indianapolis", "inet", "info", "informix", "infoweb", "inside", "int", "intelignet", "intern", "internal", "internalhost", "international", "internet", "internode", "intl", "intranet", "invalid", "investor", "investors", "io", "iota", "iowa", "ip215", "ipcom", "iplanet", "iplsin", "ipltin", "ipmonitor", "iprimus", "ipsec", "ipsec-gw", "ipt", "iq", "ir", "irc", "ircd", "ircserver", "ireland", "iris", "irvine", "irving", "irvnca", "is", "isa", "isaserv", "isaserver", "ism", "isp", "israel", "isync", "it", "italy", "ix", "jan", "japan", "jax", "je", "jedi", "jm", "jo", "jobs", "john", "jp", "jrun", "jsc", "juegos", "juliet", "juliette", "juniper", "k12", "kansas", "kansascity", "kappa", "kb", "kbtelecom", "ke", "kentucky", "kerberos", "keynote", "kg", "kh", "ki", "kilo", "king", "klmzmi", "km", "kn", "knowledgebase", "knoxville", "koe", "korea", "kp", "kr", "ks", "ksc2mo", "kw", "ky", "kz", "lab", "laboratory", "labs", "lambda", "laptop", "laserjet", "lasvegas", "launch", "lb", "lc", "ldap", "legal", "leo", "lewis", "lft", "li", "library", "lima", "lincoln", "link", "linux0", "linux01", "linux02", "linux1", "linux2", "lista", "lists", "listserv", "listserver", "live", "livnmi", "lk", "ll", "lnk", "load", "loadbalancer", "local", "localhost", "log0", "log01", "log02", "log1", "log2", "logfile", "logfiles", "logger", "logging", "loghost", "london", "longbeach", "losangeles", "lotus", "louisiana", "lr", "ls", "lsan03", "lt", "ltrkar", "lu", "luke", "lw", "ly", "lyris", "ma", "maa", "mac", "mac1", "mac10", "mac11", "mac2", "mac3", "mac4", "mac5", "mach", "macintosh", "madrid", "mail2", "mailer", "mailgate", "mailhost", "mailing", "maillist", "maillists", "mailroom", "mailserv", "mailsite", "mailsrv", "maine", "maint", "management", "manufacturing", "mapas", "maps", "marketing", "marketplace", "mars", "marvin", "mary", "maryland", "massachusetts", "max", "maxonline", "mc", "mci", "mco", "md", "mdaemon", "me", "med", "media", "megaegg", "megared", "mem", "member", "members", "memphis", "mercury", "merlin", "mesh", "messages", "messenger", "mg", "mgmt", "mh", "mia", "miamfl", "miami", "michigan", "mickey", "mid", "midwest", "mike", "milwaukee", "milwwi", "minneapolis", "minnesota", "mirror", "mis", "mississippi", "missouri", "mk", "ml", "mn", "mngt", "mo", "mob", "mobileonline", "mom", "monitoring", "montana", "moon", "moscow", "movies", "mozart", "mp", "mpeg", "mpg", "mpls", "mq", "mr", "mrt", "mrtg", "ms", "ms-exchange", "ms-sql", "msexchange", "mssnks", "mssql0", "mssql01", "mssql1", "msy", "mt", "mta", "mtnl", "mtu", "mu", "multimedia", "mv", "mw", "mweb", "mx", "mysql0", "mysql01", "mysql1", "mz", "na", "nam", "names", "nameserv", "nameserver", "nas", "nashville", "nat", "nb", "nc", "nd", "nds", "ne", "nebraska", "neo", "neptune", "net", "netapp", "netdata", "netgear", "netmeeting", "netscaler", "netscreen", "netstats", "netvision", "network", "nevada", "newhampshire", "newjersey", "newmexico", "neworleans", "newsfeed", "newsfeeds", "newsgroups", "newton", "newyork", "newzealand", "nf", "ng", "nh", "ni", "nigeria", "nj", "nl", "nm", "nms", "nntp", "no-dns", "no-dns-yet", "node", "nokia", "nombres", "nora", "north", "northcarolina", "northdakota", "northeast", "northwest", "not-set-yet", "nothing", "noticias", "novell", "november", "np", "nr", "ns", "ns0", "ns01", "ns02", "ns1", "ns2", "ns3", "ns4", "ns5", "ns_", "nswc", "nt", "nt4", "nt40", "ntmail", "ntp", "ntserver", "nu", "null", "nv", "nw", "ny", "nycap", "nz", "oakland", "oc", "ocean", "ocn", "odin", "odn", "office", "offices", "oh", "ohio", "oilfield", "okc", "okcyok", "oklahoma", "oklahomacity", "om", "omah", "omaha", "omega", "omicron", "ontario", "openbsd", "openview", "operations", "ops", "ops0", "ops01", "ops02", "ops1", "ops2", "opsware", "optusnet", "or", "orange", "order", "orders", "oregon", "orion", "orlando", "oscar", "out", "outbound", "outgoing", "outlook", "outside", "ov", "owa", "owa01", "owa02", "owa1", "owa2", "owb", "ows", "oxnard", "pa", "pac", "pager", "pages", "paginas", "papa", "paris", "parners", "partner", "partners", "patch", "patches", "paul", "payroll", "pbx", "pc01", "pcmail", "pcs", "pda", "pdc", "pe", "pegasus", "pennsylvania", "peoplesoft", "personal", "pf", "pg", "pgp", "ph", "phi", "philadelphia", "phnx", "phoenix", "phoeniz", "phones", "photos", "pi", "pics", "pictures", "pink", "pipex-gw", "pittsburgh", "pix", "pk", "pki", "pl", "plala", "plano", "platinum", "pltn13", "pluto", "pm1", "pn", "po", "pol", "policy", "polls", "pool", "pools", "pop", "pop3", "portals", "portfolio", "portland", "postales", "postoffice", "ppp", "ppp1", "pppoe", "pptp", "pr", "prensa", "press", "prima", "printer", "printserv", "printserver", "priv", "privacy", "private", "problemtracker", "prod-empresarial", "prod-infinitum", "prodigy", "products", "profiles", "project", "projects", "promo", "proxy", "prueba", "pruebas", "psi", "pss", "pt", "ptld", "ptr", "pub", "pubs", "purple", "pw", "py", "qa", "qmail", "qotd", "quake", "quebec", "queen", "quotes", "r01", "r02", "ra", "radio", "radius", "ramstein", "range", "rapidsite", "raptor", "ras", "rc", "rcs", "rcsntx", "rd", "rdns", "re", "realserver", "recruiting", "redhat", "ref", "reference", "reg", "register", "registro", "registry", "regs", "relay", "rem", "remote", "remstats", "res", "research", "reseller", "reserved", "resnet", "resumenes", "retail", "rev", "reverse", "rho", "rhodeisland", "ri", "ris", "rmi", "ro", "robert", "rochester", "romeo", "rose", "route", "router", "router1", "rs", "rtc5", "rtelnet", "rtr", "rtr01", "rtr1", "ru", "rune", "rw", "rwhois", "sa", "sac", "sacramento", "sadmin", "sales", "saltlake", "sam", "san", "sanantonio", "sandiego", "sanfrancisco", "sanjose", "saskatchewan", "sasknet", "saturn", "savecom", "sb", "sbs", "sc", "scanner", "schedules",
	}
)

func IsValidDomain(domain string) bool {
	pattern := `^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`
	matched, _ := regexp.MatchString(pattern, domain)
	return matched
}

func NewScanner(config *SubdomainConfig) (*SubdomainScanner, error) {
	scanner := &SubdomainScanner{
		config:      config,
		wildcardIPs: make(map[string]bool),
		allResults:  make([]SubdomainResult, 0),
		startTime:   time.Now(),
	}

	if err := scanner.loadWordlist(); err != nil {
		return nil, err
	}

	scanner.totalWords = len(scanner.wordlist)

	scanner.detectWildcard()

	return scanner, nil
}

func (s *SubdomainScanner) detectWildcard() {
	wildcardCount := 0

	for i := 0; i < 5; i++ {
		randomSub := generateRandomString(16) + "." + s.config.Domain

		m := &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Id:               dns.Id(),
				RecursionDesired: true,
			},
			Question: []dns.Question{
				{Name: randomSub + ".", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
		}

		c := new(dns.Client)
		c.ReadTimeout = s.config.Timeout

		in, _, err := c.Exchange(m, net.JoinHostPort("8.8.8.8", "53"))
		if err != nil {
			continue
		}

		if in != nil && in.Rcode == dns.RcodeSuccess {
			for _, ans := range in.Answer {
				if a, ok := ans.(*dns.A); ok {
					s.wildcardIPs[a.A.String()] = true
					wildcardCount++
				}
			}
		}
	}

	if wildcardCount > 3 {
		utils.WarningPrint("\n[!] 警告: 检测到通配符DNS配置")
	}
}

func generateRandomString(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (s *SubdomainScanner) loadWordlist() error {
	if s.config.Wordlist != "" {
		file, err := os.Open(s.config.Wordlist)
		if err != nil {
			return fmt.Errorf("无法打开字典文件: %v", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			line = strings.ToLower(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				s.wordlist = append(s.wordlist, line)
			}
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("读取字典文件错误: %v", err)
		}
	}

	if len(s.wordlist) == 0 {
		s.wordlist = defaultWordlist
	}

	return nil
}

func SubdomainScan(ctx context.Context, config SubdomainConfig) []SubdomainResult {
	scanner, err := NewScanner(&config)
	if err != nil {
		utils.ErrorPrint("初始化扫描器失败: %v", err)
		return nil
	}

	scanStartTime = time.Now()

	err = scanner.Start(ctx)
	if err != nil {
		utils.ErrorPrint("扫描失败: %v", err)
	}

	return scanner.allResults
}

func GetScanDuration() time.Duration {
	return time.Since(scanStartTime)
}

func getStartTime() time.Time {
	return scanStartTime
}

func (s *SubdomainScanner) updateProgress(ctx context.Context) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			scanned := atomic.LoadInt64(&s.scannedCount)
			if scanned >= int64(s.totalWords) {
				return
			}

			progress := float64(scanned) / float64(s.totalWords) * 100
			width := 20
			filled := int(progress / 100 * float64(width))
			if filled > width {
				filled = width
			}

			bar := "["
			for i := 0; i < width; i++ {
				if i < filled-1 {
					bar += "="
				} else if i == filled-1 {
					bar += ">"
				} else {
					bar += " "
				}
			}
			bar += "]"

			fmt.Fprintf(os.Stderr, "\r%s %d/%d", bar, scanned, s.totalWords)
		case <-ctx.Done():
			return
		}
	}
}

func (s *SubdomainScanner) Start(ctx context.Context) error {
	utils.InfoPrint("\n[+] 开始枚举域名...\n")

	s.wg.Add(s.config.Threads)

	jobs := make(chan string, len(s.wordlist))

	for i := 0; i < s.config.Threads; i++ {
		go s.worker(ctx, jobs)
	}

	go func() {
		for _, word := range s.wordlist {
			select {
			case jobs <- word:
			case <-ctx.Done():
				return
			}
		}
		close(jobs)
	}()

	go s.updateProgress(ctx)

	s.wg.Wait()

	time.Sleep(100 * time.Millisecond)

	return nil
}

func (s *SubdomainScanner) worker(ctx context.Context, jobs <-chan string) {
	defer s.wg.Done()

	for {
		select {
		case word, ok := <-jobs:
			if !ok {
				return
			}
			s.scanSubdomain(ctx, word)
		case <-ctx.Done():
			return
		}
	}
}

func (s *SubdomainScanner) scanSubdomain(ctx context.Context, subdomain string) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	target := subdomain + "." + s.config.Domain

	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{
			{Name: target + ".", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		},
	}

	c := new(dns.Client)
	c.ReadTimeout = 1 * time.Second

	type dnsResult struct {
		in  *dns.Msg
		rtt time.Duration
		err error
	}

	resultChan := make(chan dnsResult, 1)

	go func() {
		in, rtt, err := c.Exchange(m, net.JoinHostPort("8.8.8.8", "53"))
		resultChan <- dnsResult{in: in, rtt: rtt, err: err}
	}()

	select {
	case result := <-resultChan:
		in, _, err := result.in, result.in, result.err
		if err != nil {
			atomic.AddInt64(&s.scannedCount, 1)
			return
		}

		var ip string
		if in != nil && in.Rcode == dns.RcodeSuccess {
			for _, ans := range in.Answer {
				if a, ok := ans.(*dns.A); ok {
					ip = a.A.String()
					break
				}
			}
		}

		if ip == "" {
			atomic.AddInt64(&s.scannedCount, 1)
			return
		}

		if s.wildcardIPs[ip] {
			atomic.AddInt64(&s.scannedCount, 1)
			return
		}

		if s.config.VerifyHTTP {
			httpStatus := verifyHTTP(ctx, target, 1*time.Second)
			if httpStatus == 0 {
				atomic.AddInt64(&s.scannedCount, 1)
				return
			}

			s.mutex.Lock()
			s.allResults = append(s.allResults, SubdomainResult{
				Subdomain:  target,
				IP:         ip,
				HTTPStatus: httpStatus,
			})
			s.foundCount++
			s.mutex.Unlock()
		} else {
			s.mutex.Lock()
			s.allResults = append(s.allResults, SubdomainResult{
				Subdomain: target,
				IP:        ip,
			})
			s.foundCount++
			s.mutex.Unlock()
		}

		atomic.AddInt64(&s.scannedCount, 1)
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Second):
		atomic.AddInt64(&s.scannedCount, 1)
		return
	}
}

func verifyHTTP(ctx context.Context, domain string, timeout time.Duration) int {
	select {
	case <-ctx.Done():
		return 0
	default:
	}

	httpTimeout := timeout
	if ctx.Err() != nil {
		httpTimeout = 200 * time.Millisecond
	}

	urls := []string{
		fmt.Sprintf("http://%s", domain),
		fmt.Sprintf("https://%s", domain),
	}

	for _, url := range urls {
		select {
		case <-ctx.Done():
			return 0
		default:
		}

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Host = domain
		req.Header.Set("User-Agent", "GYscan/1.0")

		client := &http.Client{
			Timeout: httpTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode < 400 {
			return resp.StatusCode
		}
	}

	return 0
}

func (s *SubdomainScanner) saveResults() error {
	file, err := os.Create(s.config.Output)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, result := range s.allResults {
		if result.HTTPStatus > 0 {
			fmt.Fprintf(file, "%d %s\n", result.HTTPStatus, result.Subdomain)
		} else {
			fmt.Fprintf(file, "%s -> %s\n", result.Subdomain, result.IP)
		}
	}

	return nil
}
