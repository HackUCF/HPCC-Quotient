package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"quotient/checks"

	"golang.org/x/exp/slices"

	"github.com/BurntSushi/toml"
)

var (
	supportedEvents = []string{"rvb", "koth"}
)

type Config struct {
	// General engine settings
	Event         string
	EventType     string
	DBConnectURL  string
	BindAddress   string
	Gateway       string
	Interface     string
	Subnet        string
	Timezone      string
	JWTPrivateKey string
	JWTPublicKey  string

	// LDAP settings
	LdapConnectUrl   string
	LdapBindDn       string
	LdapBindPassword string
	LdapBaseDn       string
	LdapAdminGroupDn string
	LdapTeamGroupDn  string

	// Optional settings
	EasyPCR     bool
	Verbose     bool
	Port        int
	Https       bool
	Cert        string `toml:"cert,omitempty" json:"cert,omitempty"`
	Key         string `toml:"key,omitempty" json:"key,omitempty"`
	StartPaused bool
	// Restrict information
	DisableInfoPage      bool
	DisableHeadToHead    bool
	DisableExternalPorts bool

	// Round settings
	Delay  int
	Jitter int

	// Defaults for checks
	Points       int
	Timeout      int
	SlaThreshold int
	SlaPenalty   int

	Admin []Admin
	Box   []Box
}

// mostly used for Form and NOT FOR DATABASE... maybe change later
type Admin struct {
	ID   uint
	Name string
	Pw   string
}

type Box struct {
	Name string
	IP   string
	FQDN string `toml:"FQDN,omitempty" json:"fqdn,omitempty"`

	// Internal use but not in config file
	Runners []checks.Runner `toml:"-"`

	Custom []checks.Custom `toml:"Custom,omitempty" json:"custom,omitempty"`
	Dns    []checks.Dns    `toml:"Dns,omitempty" json:"dns,omitempty"`
	Ftp    []checks.Ftp    `toml:"Ftp,omitempty" json:"ftp,omitempty"`
	Imap   []checks.Imap   `toml:"Imap,omitempty" json:"imap,omitempty"`
	Ldap   []checks.Ldap   `toml:"Ldap,omitempty" json:"ldap,omitempty"`
	Ping   []checks.Ping   `toml:"Ping,omitempty" json:"ping,omitempty"`
	Pop3   []checks.Pop3   `toml:"Pop3,omitempty" json:"pop3,omitempty"`
	Rdp    []checks.Rdp    `toml:"Rdp,omitempty" json:"rdp,omitempty"`
	Smb    []checks.Smb    `toml:"Smb,omitempty" json:"smb,omitempty"`
	Smtp   []checks.Smtp   `toml:"Smtp,omitempty" json:"smtp,omitempty"`
	Sql    []checks.Sql    `toml:"Sql,omitempty" json:"sql,omitempty"`
	Ssh    []checks.Ssh    `toml:"Ssh,omitempty" json:"ssh,omitempty"`
	Tcp    []checks.Tcp    `toml:"Tcp,omitempty" json:"tcp,omitempty"`
	Vnc    []checks.Vnc    `toml:"Vnc,omitempty" json:"vnc,omitempty"`
	Web    []checks.Web    `toml:"Web,omitempty" json:"web,omitempty"`
	WinRM  []checks.WinRM  `toml:"Winrm,omitempty" json:"winrm,omitempty"`
}

// NewConfig creates a new Config from the given file path
func NewConfig(path string) (*Config, error) {
	fileContent, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("configuration file (%s) not found: %w", path, err)
	}

	var conf Config
	md, err := toml.Decode(string(fileContent), &conf)
	if err != nil {
		return nil, fmt.Errorf("failed to decode configuration: %w", err)
	}

	// Log undecoded keys as warnings
	for _, undecoded := range md.Undecoded() {
		log.Printf("[WARN] Undecoded configuration key \"%s\" will not be used", undecoded.String())
	}

	// Override with environment variables if present
	if dbURL := os.Getenv("DB_CONNECT_URL"); dbURL != "" {
		conf.DBConnectURL = dbURL
	}

	return &conf, nil
}

// ValidateConfig validates and sets defaults for the configuration
func (c *Config) ValidateConfig() error {
	var errs []error

	// Validate required fields
	requiredFields := map[string]string{
		"Event":         c.Event,
		"EventType":     c.EventType,
		"DBConnectURL":  c.DBConnectURL,
		"BindAddress":   c.BindAddress,
		"Gateway":       c.Gateway,
		"Interface":     c.Interface,
		"Subnet":        c.Subnet,
		"JWTPrivateKey": c.JWTPrivateKey,
		"JWTPublicKey":  c.JWTPublicKey,
		"Timezone":      c.Timezone,
	}

	for field, value := range requiredFields {
		if value == "" {
			errs = append(errs, fmt.Errorf("%s is required", field))
		}
	}

	// Validate event type
	if !slices.Contains(supportedEvents, c.EventType) {
		errs = append(errs, errors.New("invalid event type"))
	}

	// Validate admin users
	if len(c.Admin) == 0 {
		errs = append(errs, errors.New("at least one admin user is required"))
	} else {
		for _, admin := range c.Admin {
			if admin.Name == "" || admin.Pw == "" {
				errs = append(errs, fmt.Errorf("admin %s missing required properties", admin.Name))
			}
		}
	}

	// Set defaults and validate optional fields
	c.setDefaults()

	// Validate HTTPS configuration
	if c.Https && (c.Cert == "" || c.Key == "") {
		errs = append(errs, errors.New("HTTPS requires cert and key pair"))
	}

	// Validate timing configuration
	if c.Jitter >= c.Delay {
		errs = append(errs, errors.New("jitter must be smaller than delay"))
	}
	if c.Timeout >= c.Delay-c.Jitter {
		errs = append(errs, errors.New("timeout must be smaller than delay minus jitter"))
	}

	// Validate boxes
	if err := c.validateBoxes(); err != nil {
		errs = append(errs, err)
	}

	// Initialize engine pause if needed
	if c.StartPaused {
		enginePauseWg.Add(1)
		enginePause = true
	}

	return errors.Join(errs...)
}

// setDefaults sets default values for optional configuration fields
func (c *Config) setDefaults() {
	if c.Delay == 0 {
		c.Delay = 60
	}
	if c.Jitter == 0 {
		c.Jitter = 5
	}
	if c.Port == 0 {
		if c.Https {
			c.Port = 443
		} else {
			c.Port = 80
		}
	}
	if c.Timeout == 0 {
		c.Timeout = c.Delay / 2
	}
	if c.Points == 0 {
		c.Points = 1
	}
	if c.SlaThreshold == 0 {
		c.SlaThreshold = 5
	}
	if c.SlaPenalty == 0 {
		c.SlaPenalty = c.SlaThreshold * c.Points
	}
}

// validateBoxes validates box configuration and parses environment
func (c *Config) validateBoxes() error {
	var errs []error

	// Sort boxes by IP
	sort.SliceStable(c.Box, func(i, j int) bool {
		return c.Box[i].IP < c.Box[j].IP
	})

	// Check for duplicate box names
	boxNames := make(map[string]bool)
	for _, box := range c.Box {
		if box.Name == "" {
			errs = append(errs, errors.New("box missing name"))
			continue
		}
		if boxNames[box.Name] {
			errs = append(errs, fmt.Errorf("duplicate box name: %s", box.Name))
		}
		boxNames[box.Name] = true
	}

	// Parse environment and validate services
	if err := parseEnvironment(c.Box); err != nil {
		errs = append(errs, err)
	}

	// Check for duplicate service names within boxes
	for _, box := range c.Box {
		serviceNames := make(map[string]bool)
		for _, runner := range box.Runners {
			name := runner.GetService().Name
			if serviceNames[name] {
				errs = append(errs, fmt.Errorf("duplicate service name '%s' in box %s", name, box.Name))
			}
			serviceNames[name] = true
		}
	}

	return errors.Join(errs...)
}

func parseEnvironment(boxes []Box) error {
	var errs []error

	for i, box := range boxes {
		if err := validateBox(&box); err != nil {
			return err
		}

		// Normalize box identifiers
		boxes[i].IP = strings.ToLower(box.IP)
		boxes[i].FQDN = strings.ToLower(box.FQDN)

		// Process all service types
		processors := []func(*Box, int) error{
			processCustomServices,
			processDnsServices,
			processFtpServices,
			processImapServices,
			processLdapServices,
			processPingServices,
			processPop3Services,
			processRdpServices,
			processSmbServices,
			processSmtpServices,
			processSqlServices,
			processSshServices,
			processTcpServices,
			processVncServices,
			processWebServices,
			processWinRMServices,
		}

		for _, processor := range processors {
			if err := processor(&boxes[i], i); err != nil {
				errs = append(errs, err)
			}
		}
	}

	return errors.Join(errs...)
}

// validateBox validates basic box configuration
func validateBox(box *Box) error {
	if box.Name == "" {
		return errors.New("box missing name")
	}
	if box.IP == "" && box.FQDN == "" {
		return fmt.Errorf("box %s missing IP/FQDN", box.Name)
	}
	return nil
}

// processService is a generic service processor
func processService[T checks.Runner](box *Box, services []T, serviceType string, processor func(*T, *Box) error) error {
	var errs []error
	for i := range services {
		if err := processor(&services[i], box); err != nil {
			errs = append(errs, err)
		}
		box.Runners = append(box.Runners, services[i])
	}
	return errors.Join(errs...)
}

// Service-specific processors
func processCustomServices(box *Box, _ int) error {
	return processService(box, box.Custom, "custom", func(c *checks.Custom, b *Box) error {
		if c.Display == "" {
			c.Display = "custom"
		}
		if c.Name == "" {
			c.Name = b.Name + "-" + c.Display
		}
		if len(c.CredLists) < 1 && !strings.Contains(c.Command, "USERNAME") && !strings.Contains(c.Command, "PASSWORD") {
			c.Anonymous = true
		}
		return configureService(&c.Service, *b)
	})
}

func processDnsServices(box *Box, _ int) error {
	return processService(box, box.Dns, "dns", func(c *checks.Dns, b *Box) error {
		c.Anonymous = true
		if c.Display == "" {
			c.Display = "dns"
		}
		if c.Name == "" {
			c.Name = b.Name + "-" + c.Display
		}
		if len(c.Record) < 1 {
			return fmt.Errorf("dns check %s has no records", c.Name)
		}
		if c.Port == 0 {
			c.Port = 53
		}
		return configureService(&c.Service, *b)
	})
}

func processFtpServices(box *Box, _ int) error {
	return processService(box, box.Ftp, "ftp", func(c *checks.Ftp, b *Box) error {
		if c.Display == "" {
			c.Display = "ftp"
		}
		if c.Name == "" {
			c.Name = b.Name + "-" + c.Display
		}
		if c.Port == 0 {
			c.Port = 21
		}
		for _, f := range c.File {
			if f.Regex != "" && f.Hash != "" {
				return errors.New("can't have both regex and hash for ftp file check")
			}
		}
		return configureService(&c.Service, *b)
	})
}

func processImapServices(box *Box, _ int) error {
	return processService(box, box.Imap, "imap", func(c *checks.Imap, b *Box) error {
		if c.Display == "" {
			c.Display = "imap"
		}
		if c.Name == "" {
			c.Name = b.Name + "-" + c.Display
		}
		if c.Port == 0 {
			c.Port = 143
		}
		return configureService(&c.Service, *b)
	})
}

func processLdapServices(box *Box, _ int) error {
	return processService(box, box.Ldap, "ldap", func(c *checks.Ldap, b *Box) error {
		if c.Display == "" {
			c.Display = "ldap"
		}
		if c.Name == "" {
			c.Name = b.Name + "-" + c.Display
		}
		if c.Port == 0 {
			c.Port = 636
		}
		if c.Anonymous {
			return errors.New("anonymous ldap not supported")
		}
		return configureService(&c.Service, *b)
	})
}

func processPingServices(box *Box, _ int) error {
	return processService(box, box.Ping, "ping", func(c *checks.Ping, b *Box) error {
		c.Anonymous = true
		if c.Count == 0 {
			c.Count = 1
		}
		if c.Display == "" {
			c.Display = "ping"
		}
		if c.Name == "" {
			c.Name = b.Name + "-" + c.Display
		}
		return configureService(&c.Service, *b)
	})
}

func processPop3Services(box *Box, _ int) error {
	return processService(box, box.Pop3, "pop3", func(c *checks.Pop3, b *Box) error {
		if c.Display == "" {
			c.Display = "pop3"
		}
		if c.Name == "" {
			c.Name = b.Name + "-" + c.Display
		}
		if c.Port == 0 {
			c.Port = 110
		}
		return configureService(&c.Service, *b)
	})
}

func processRdpServices(box *Box, _ int) error {
	return processService(box, box.Rdp, "rdp", func(c *checks.Rdp, b *Box) error {
		if c.Display == "" {
			c.Display = "rdp"
		}
		if c.Name == "" {
			c.Name = b.Name + "-" + c.Display
		}
		if c.Port == 0 {
			c.Port = 3389
		}
		return configureService(&c.Service, *b)
	})
}

func processSmbServices(box *Box, _ int) error {
	return processService(box, box.Smb, "smb", func(c *checks.Smb, b *Box) error {
		if c.Display == "" {
			c.Display = "smb"
		}
		if c.Name == "" {
			c.Name = b.Name + "-" + c.Display
		}
		if c.Port == 0 {
			c.Port = 445
		}
		return configureService(&c.Service, *b)
	})
}

func processSmtpServices(box *Box, _ int) error {
	return processService(box, box.Smtp, "smtp", func(c *checks.Smtp, b *Box) error {
		if c.Display == "" {
			c.Display = "smtp"
		}
		if c.Name == "" {
			c.Name = b.Name + "-" + c.Display
		}
		if c.Port == 0 {
			c.Port = 25
		}
		return configureService(&c.Service, *b)
	})
}

func processSqlServices(box *Box, _ int) error {
	return processService(box, box.Sql, "sql", func(c *checks.Sql, b *Box) error {
		if c.Display == "" {
			c.Display = "sql"
		}
		if c.Name == "" {
			c.Name = b.Name + "-" + c.Display
		}
		if c.Kind == "" {
			c.Kind = "mysql"
		}
		if c.Port == 0 {
			c.Port = 3306
		}
		for _, q := range c.Query {
			if q.UseRegex {
				regexp.MustCompile(q.Output)
			}
			if q.UseRegex && q.Contains {
				return errors.New("cannot use both regex and contains")
			}
		}
		return configureService(&c.Service, *b)
	})
}

func processSshServices(box *Box, _ int) error {
	return processService(box, box.Ssh, "ssh", func(c *checks.Ssh, b *Box) error {
		if c.Display == "" {
			c.Display = "ssh"
		}
		if c.Name == "" {
			c.Name = b.Name + "-" + c.Display
		}
		if c.Port == 0 {
			c.Port = 22
		}
		if c.PrivKey != "" && c.BadAttempts != 0 {
			return errors.New("can not have bad attempts with pubkey for ssh")
		}
		for _, r := range c.Command {
			if r.UseRegex {
				regexp.MustCompile(r.Output)
			}
			if r.UseRegex && r.Contains {
				return errors.New("cannot use both regex and contains")
			}
		}
		if c.Anonymous {
			return errors.New("anonymous ssh not supported")
		}
		return configureService(&c.Service, *b)
	})
}

func processTcpServices(box *Box, _ int) error {
	return processService(box, box.Tcp, "tcp", func(c *checks.Tcp, b *Box) error {
		c.Anonymous = true
		if c.Display == "" {
			c.Display = "tcp"
		}
		if c.Name == "" {
			c.Name = b.Name + "-" + c.Display
		}
		if c.Port == 0 {
			return errors.New("tcp port required")
		}
		return configureService(&c.Service, *b)
	})
}

func processVncServices(box *Box, _ int) error {
	return processService(box, box.Vnc, "vnc", func(c *checks.Vnc, b *Box) error {
		if c.Display == "" {
			c.Display = "vnc"
		}
		if c.Name == "" {
			c.Name = b.Name + "-" + c.Display
		}
		if c.Port == 0 {
			c.Port = 5900
		}
		return configureService(&c.Service, *b)
	})
}

func processWebServices(box *Box, _ int) error {
	return processService(box, box.Web, "web", func(c *checks.Web, b *Box) error {
		if c.Display == "" {
			c.Display = "web"
		}
		if c.Name == "" {
			c.Name = b.Name + "-" + c.Display
		}
		if c.Port == 0 {
			if c.Scheme == "https" {
				c.Port = 443
			} else {
				c.Port = 80
			}
		}
		if len(c.Url) == 0 {
			return fmt.Errorf("no urls specified for web check %s", c.Name)
		}
		if len(c.CredLists) < 1 {
			c.Anonymous = true
		}
		if c.Scheme == "" {
			c.Scheme = "http"
		}
		for _, u := range c.Url {
			if u.Diff != 0 && u.CompareFile == "" {
				return errors.New("need compare file for diff in web")
			}
		}
		return configureService(&c.Service, *b)
	})
}

func processWinRMServices(box *Box, _ int) error {
	return processService(box, box.WinRM, "winrm", func(c *checks.WinRM, b *Box) error {
		if c.Display == "" {
			c.Display = "winrm"
		}
		if c.Name == "" {
			c.Name = b.Name + "-" + c.Display
		}
		if c.Port == 0 {
			if c.Encrypted {
				c.Port = 443
			} else {
				c.Port = 80
			}
		}
		if c.Anonymous {
			return errors.New("anonymous winrm not supported")
		}
		for _, r := range c.Command {
			if r.UseRegex {
				regexp.MustCompile(r.Output)
			}
			if r.UseRegex && r.Contains {
				return errors.New("cannot use both regex and contains")
			}
		}
		return configureService(&c.Service, *b)
	})
}

// configure general service attributes
func configureService(service *checks.Service, box Box) error {
	service.BoxName = box.Name
	service.BoxIP = box.IP
	service.BoxFQDN = box.FQDN

	if service.Points == 0 {
		service.Points = eventConf.Points
	}
	if service.Timeout == 0 {
		service.Timeout = eventConf.Timeout
	}
	if service.SlaPenalty == 0 {
		service.SlaPenalty = eventConf.SlaPenalty
	}
	if service.SlaThreshold == 0 {
		service.SlaThreshold = eventConf.SlaThreshold
	}
	if service.StopTime.IsZero() {
		service.StopTime = time.Now().AddDate(3, 0, 0) // 3 years ahead should be far enough
	}
	for _, list := range service.CredLists {
		if !strings.HasSuffix(list, ".credlist") {
			return errors.New("check " + service.Name + " has invalid credlist names")
		}
	}
	return nil
}
