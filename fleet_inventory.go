package main

import (
	"fmt"
	"sort"
	"strings"
)

type fleetHost struct {
	Name         string
	Group        string
	Address      string
	User         string
	Port         string
	IdentityFile string
	OS           string
}

func fleetHosts(cfg certopsConfig) map[string]fleetHost {
	out := map[string]fleetHost{}
	for groupName, group := range cfg.Inventory.Groups {
		for hostName, host := range group.Hosts {
			out[hostName] = fleetHost{
				Name:         hostName,
				Group:        groupName,
				Address:      host.Address,
				User:         host.User,
				Port:         host.Port,
				IdentityFile: host.IdentityFile,
				OS:           host.OS,
			}
		}
	}
	return out
}

func expandFleetTrustTargets(cfg certopsConfig, limit string) ([]fleetTrustTarget, []fleetTrustFailure) {
	hosts := fleetHosts(cfg)
	var targets []fleetTrustTarget
	var failures []fleetTrustFailure
	for _, target := range cfg.Trust.Targets {
		for _, host := range expandFleetTargetHosts(cfg, target) {
			if !fleetLimitMatches(host, limit) {
				continue
			}
			if strings.TrimSpace(host.Address) == "" {
				failures = append(failures, fleetTrustFailure{Host: host.Name, Error: "host address is empty"})
				continue
			}
			for _, caName := range target.Required {
				targets = append(targets, fleetTrustTarget{Host: host, CAName: caName})
			}
		}
		if strings.TrimSpace(target.Host) != "" {
			if _, ok := hosts[target.Host]; !ok {
				failures = append(failures, fleetTrustFailure{Host: target.Host, Error: "host not found in inventory"})
			}
		}
	}
	if len(targets) == 0 && len(failures) == 0 {
		failures = append(failures, fleetTrustFailure{Error: fmt.Sprintf("no trust targets matched limit %q", limit)})
	}
	return targets, failures
}

type fleetTrustTarget struct {
	Host   fleetHost
	CAName string
}

func expandFleetTargetHosts(cfg certopsConfig, target configTrustTarget) []fleetHost {
	all := fleetHosts(cfg)
	var hosts []fleetHost
	if strings.TrimSpace(target.Host) != "" {
		if host, ok := all[target.Host]; ok {
			hosts = append(hosts, host)
		}
		return hosts
	}
	if strings.TrimSpace(target.Group) != "" {
		group, ok := cfg.Inventory.Groups[target.Group]
		if !ok {
			return hosts
		}
		hostNames := make([]string, 0, len(group.Hosts))
		for hostName := range group.Hosts {
			hostNames = append(hostNames, hostName)
		}
		sort.Strings(hostNames)
		for _, hostName := range hostNames {
			host := group.Hosts[hostName]
			hosts = append(hosts, fleetHost{Name: hostName, Group: target.Group, Address: host.Address, User: host.User, Port: host.Port, IdentityFile: host.IdentityFile, OS: host.OS})
		}
	}
	return hosts
}

func fleetLimitMatches(host fleetHost, limit string) bool {
	limit = strings.TrimSpace(limit)
	return limit == "" || host.Name == limit || host.Group == limit
}

func caByName(cfg certopsConfig) map[string]configCA {
	out := map[string]configCA{}
	for _, ca := range cfg.CAs {
		out[ca.Name] = ca
	}
	return out
}

func hostEndpoint(address, port string) string {
	if strings.TrimSpace(port) == "" {
		return address
	}
	return address + ":" + port
}
