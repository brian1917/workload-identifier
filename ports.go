package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/brian1917/illumioapi"
)

func findPorts(traffic []illumioapi.TrafficAnalysis, coreServices []coreService, provider, incWL bool) []match {
	// Create a slice to hold the matches
	var matches []match

	var ft []illumioapi.TrafficAnalysis

	// Create the filter traffic slice by removing traffic that is talking to each other
	for _, entry := range traffic {
		if entry.Src.IP != entry.Dst.IP {
			ft = append(ft, entry)
		}
	}

	// For each traffic flow not going to a workload, see if it already exists in the ipAddrPorts map. If no, add it.
	ipPorts := make(map[string][]int)
	for _, flow := range ft {
		// Set the IP as destination or source
		ip := flow.Dst.IP
		if !provider {
			ip = flow.Src.IP
		}
		if ports, ok := ipPorts[ip]; ok {
			if !containsInt(ports, flow.ExpSrv.Port) {
				ipPorts[ip] = append(ports, flow.ExpSrv.Port)
			}
		} else {
			ipPorts[ip] = []int{flow.ExpSrv.Port}
		}
	}

	// Iterate through each machine seen in explorer
	for ipAddr, ports := range ipPorts {
		// Cycle through core services to look for matches
		for _, cs := range coreServices {
			// Only run when the the provider flag is the same for core service and passed into function
			portMatches := []string{}
			if provider == cs.provider {
				// Required Ports
				reqPortMatches := 0
				for _, csReqPort := range cs.requiredPorts {
					if containsInt(ports, csReqPort) {
						reqPortMatches++
						portMatches = append(portMatches, strconv.Itoa(csReqPort))
					}
				}
				// Optional Ports
				optPortMatches := 0
				for _, csOptPort := range cs.optionalPorts {
					if containsInt(ports, csOptPort) {
						optPortMatches++
						portMatches = append(portMatches, strconv.Itoa(csOptPort))
					}
				}
				// Optional Port Ranges
				optPortRangeMatches := 0
				for _, csOptPortRange := range cs.optionalPortRanges {
					for _, port := range ports {
						if csOptPortRange[0] <= port && csOptPortRange[1] >= port {
							optPortRangeMatches++
							portMatches = append(portMatches, fmt.Sprintf("%s-%s", strconv.Itoa(csOptPortRange[0]), strconv.Itoa(csOptPortRange[1])))
							break // Only want to count one match in each range (e.g., range: 40000-50000 and ports 40001 and 40002 are used, we only want to count that as one match.)
						}
					}
				}
				// Check if it should count
				if (len(cs.requiredPorts) == reqPortMatches && len(cs.requiredPorts) > 0 && cs.numOptionalPorts <= (optPortMatches+optPortRangeMatches)) ||
					(len(cs.requiredPorts) == 0 && cs.numOptionalPorts <= (optPortMatches+optPortRangeMatches)) {

					t := "provider"
					if !provider {
						t = "consumer"
					}
					s := "port"
					if len(portMatches) > 1 {
						s = "ports"
					}
					reason := fmt.Sprintf("%s is the %s on traffic over %s %s", ipAddr, t, s, strings.Join(portMatches, " "))

					matches = append(matches, match{csname: cs.name, ipAddress: ipAddr, app: cs.app, env: cs.env, loc: cs.loc, role: cs.role, reason: reason})
				}
			}
		}
	}

	return matches
}
