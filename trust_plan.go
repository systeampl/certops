package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func buildTrustPlan(name string) trustPlan {
	safeName := sanitizeTrustName(name)
	switch runtime.GOOS {
	case "darwin":
		path := "/Library/Keychains/System.keychain"
		return trustPlan{
			Name:     safeName,
			Store:    "macOS System.keychain",
			Commands: []string{fmt.Sprintf("security add-trusted-cert -d -r trustRoot -k %s <bundle.pem>", path)},
			Install: func(bundle []byte) error {
				tmp, err := writeTempBundle(safeName, bundle)
				if err != nil {
					return err
				}
				defer os.Remove(tmp)
				return exec.Command("security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", path, tmp).Run()
			},
		}
	case "linux":
		if _, err := os.Stat("/usr/local/share/ca-certificates"); err == nil {
			path := filepath.Join("/usr/local/share/ca-certificates", safeName+".crt")
			return trustPlan{
				Name:        safeName,
				Store:       "Debian/Ubuntu update-ca-certificates",
				InstallPath: path,
				Commands:    []string{"install -m 0644 <bundle.pem> " + path, "update-ca-certificates"},
				Install: func(bundle []byte) error {
					if err := writeFileAtomic(path, bundle, 0644); err != nil {
						return err
					}
					return exec.Command("update-ca-certificates").Run()
				},
			}
		}
		if _, err := os.Stat("/etc/pki/ca-trust/source/anchors"); err == nil {
			path := filepath.Join("/etc/pki/ca-trust/source/anchors", safeName+".crt")
			return trustPlan{
				Name:        safeName,
				Store:       "RHEL/Fedora update-ca-trust",
				InstallPath: path,
				Commands:    []string{"install -m 0644 <bundle.pem> " + path, "update-ca-trust extract"},
				Install: func(bundle []byte) error {
					if err := writeFileAtomic(path, bundle, 0644); err != nil {
						return err
					}
					return exec.Command("update-ca-trust", "extract").Run()
				},
			}
		}
	case "windows":
		return trustPlan{
			Name:     safeName,
			Store:    "Windows LocalMachine Root",
			Commands: []string{"certutil -addstore -f Root <bundle.pem>"},
			Install: func(bundle []byte) error {
				tmp, err := writeTempBundle(safeName, bundle)
				if err != nil {
					return err
				}
				defer os.Remove(tmp)
				return exec.Command("certutil", "-addstore", "-f", "Root", tmp).Run()
			},
		}
	}
	return trustPlan{Name: safeName, Store: "unsupported"}
}

func trustCertInstalled(plan trustPlan, raw []byte) (bool, string) {
	if strings.TrimSpace(plan.InstallPath) != "" {
		data, err := os.ReadFile(plan.InstallPath)
		if err == nil {
			found, note := rawCertInPEMBundle(data, raw)
			if found {
				return true, "fingerprint found at install path"
			}
			return false, note
		}
		found, note := findTrustCertInSystemDirs(raw)
		if found {
			return true, note
		}
		return false, "install path not found; " + note
	}
	return false, "direct OS trust-store lookup is not implemented"
}

func rawCertInPEMBundle(data, raw []byte) (bool, string) {
	_, rawCerts, err := parseTrustCerts(data)
	if err != nil {
		return false, "PEM bundle could not be parsed"
	}
	want := formatRawFingerprint(raw)
	for _, candidate := range rawCerts {
		if formatRawFingerprint(candidate) == want {
			return true, "fingerprint found"
		}
	}
	return false, "fingerprint was not found"
}

func findTrustCertInSystemDirs(raw []byte) (bool, string) {
	for _, dir := range []string{"/etc/ssl/certs", "/etc/pki/tls/certs"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			if found, _ := rawCertInPEMBundle(data, raw); found {
				return true, "fingerprint found in " + path
			}
		}
	}
	return false, "fingerprint not found in common system trust directories"
}

func writeTempBundle(name string, bundle []byte) (string, error) {
	file, err := os.CreateTemp("", sanitizeTrustName(name)+"-*.crt")
	if err != nil {
		return "", err
	}
	path := file.Name()
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0600); err != nil {
		return "", err
	}
	if _, err := file.Write(bundle); err != nil {
		return "", err
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	ok = true
	return path, nil
}
