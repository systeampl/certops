package main

type certopsConfig struct {
	Policy    configPolicy    `json:"policy" yaml:"policy"`
	CAs       []configCA      `json:"cas" yaml:"cas"`
	CRLs      []configCRL     `json:"crls" yaml:"crls"`
	Inventory configInventory `json:"inventory" yaml:"inventory"`
	Trust     configTrust     `json:"trust" yaml:"trust"`
	Services  []configService `json:"services" yaml:"services"`
}

type configPolicy struct {
	FailOn               string `json:"fail_on" yaml:"fail_on"`
	MinCADaysRemaining   int    `json:"min_ca_days_remaining" yaml:"min_ca_days_remaining"`
	MinLeafDaysRemaining int    `json:"min_leaf_days_remaining" yaml:"min_leaf_days_remaining"`
	MinCRLDaysRemaining  int    `json:"min_crl_days_remaining" yaml:"min_crl_days_remaining"`
	MaxCRLAgeDays        int    `json:"max_crl_age_days" yaml:"max_crl_age_days"`
	AllowUnmanagedRoots  bool   `json:"allow_unmanaged_roots" yaml:"allow_unmanaged_roots"`
}

type configCA struct {
	Name        string `json:"name" yaml:"name"`
	Provider    string `json:"provider" yaml:"provider"`
	URL         string `json:"url,omitempty" yaml:"url,omitempty"`
	CABundle    string `json:"ca_bundle,omitempty" yaml:"ca_bundle,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty" yaml:"fingerprint,omitempty"`
	Insecure    bool   `json:"insecure,omitempty" yaml:"insecure,omitempty"`
	Mount       string `json:"mount,omitempty" yaml:"mount,omitempty"`
	Issuer      string `json:"issuer,omitempty" yaml:"issuer,omitempty"`
	Label       string `json:"label,omitempty" yaml:"label,omitempty"`
	Profile     string `json:"profile,omitempty" yaml:"profile,omitempty"`
}

type configCRL struct {
	Name         string `json:"name" yaml:"name"`
	CA           string `json:"ca,omitempty" yaml:"ca,omitempty"`
	URL          string `json:"url,omitempty" yaml:"url,omitempty"`
	File         string `json:"file,omitempty" yaml:"file,omitempty"`
	WarnDays     int    `json:"warn_days,omitempty" yaml:"warn_days,omitempty"`
	CriticalDays int    `json:"critical_days,omitempty" yaml:"critical_days,omitempty"`
	MaxAgeDays   int    `json:"max_age_days,omitempty" yaml:"max_age_days,omitempty"`
	Insecure     bool   `json:"insecure,omitempty" yaml:"insecure,omitempty"`
}

type configInventory struct {
	Groups map[string]configGroup `json:"groups" yaml:"groups"`
}

type configGroup struct {
	Hosts map[string]configHost `json:"hosts" yaml:"hosts"`
}

type configHost struct {
	Address      string `json:"address" yaml:"address"`
	User         string `json:"user,omitempty" yaml:"user,omitempty"`
	Port         string `json:"port,omitempty" yaml:"port,omitempty"`
	IdentityFile string `json:"identity_file,omitempty" yaml:"identity_file,omitempty"`
	OS           string `json:"os,omitempty" yaml:"os,omitempty"`
}

type configTrust struct {
	Targets []configTrustTarget `json:"targets" yaml:"targets"`
}

type configTrustTarget struct {
	Group    string   `json:"group,omitempty" yaml:"group,omitempty"`
	Host     string   `json:"host,omitempty" yaml:"host,omitempty"`
	Required []string `json:"required" yaml:"required"`
}

type configService struct {
	Name             string   `json:"name" yaml:"name"`
	URL              string   `json:"url,omitempty" yaml:"url,omitempty"`
	Host             string   `json:"host,omitempty" yaml:"host,omitempty"`
	Port             string   `json:"port,omitempty" yaml:"port,omitempty"`
	ServerName       string   `json:"server_name,omitempty" yaml:"server_name,omitempty"`
	CA               string   `json:"ca,omitempty" yaml:"ca,omitempty"`
	ExpectedNames    []string `json:"expected_names,omitempty" yaml:"expected_names,omitempty"`
	AllowedIssuers   []string `json:"allowed_issuers,omitempty" yaml:"allowed_issuers,omitempty"`
	CRLs             []string `json:"crls,omitempty" yaml:"crls,omitempty"`
	AutoCRL          bool     `json:"auto_crl,omitempty" yaml:"auto_crl,omitempty"`
	MinDaysRemaining int      `json:"min_days_remaining,omitempty" yaml:"min_days_remaining,omitempty"`
	RequireTLS13     bool     `json:"require_tls13,omitempty" yaml:"require_tls13,omitempty"`
	RequireHSTS      bool     `json:"require_hsts,omitempty" yaml:"require_hsts,omitempty"`
	ForbidTLS10      bool     `json:"forbid_tls10,omitempty" yaml:"forbid_tls10,omitempty"`
	ForbidTLS11      bool     `json:"forbid_tls11,omitempty" yaml:"forbid_tls11,omitempty"`
}
