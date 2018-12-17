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

	// Get the traffic flow count for each machine on a port
	ipPortCount := make(map[string]int)

	for _, entry := range traffic {
		ip := entry.Dst.IP
		if !provider {
			ip = entry.Src.IP
		}
		ipPortCount[ip+"-"+strconv.Itoa(entry.ExpSrv.Port)] = ipPortCount[ip+"-"+strconv.Itoa(entry.ExpSrv.Port)] + entry.NumConnections

	}

	/** DEBUG
	for ipadd, count := range ipPortCount {
		if ipadd[:10] == "172.16.1.4" && len(ipadd) == 10 {
			fmt.Printf("%s - %d\n", ipadd, count)
		}

	}
	END DEBUG **/

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
		// Reset the flow counter
		flowCounter := 0
		// Cycle through core services to look for matches
		for _, cs := range coreServices {
			// Reset the portMatches slice
			portMatches := []string{}
			// Only run when the the provider flag is the same for core service and passed into function
			if provider == cs.provider {
				// Required Ports
				reqPortMatches := 0
				for _, csReqPort := range cs.requiredPorts {
					if containsInt(ports, csReqPort) {
						reqPortMatches++
						flowCounter = flowCounter + ipPortCount[ipAddr+"-"+strconv.Itoa(csReqPort)]
						portMatches = append(portMatches, strconv.Itoa(csReqPort))
					}
				}
				// Optional Ports
				optPortMatches := 0
				for _, csOptPort := range cs.optionalPorts {
					if containsInt(ports, csOptPort) {
						optPortMatches++
						flowCounter = flowCounter + ipPortCount[ipAddr+"-"+strconv.Itoa(csOptPort)]
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
				if (len(cs.requiredPorts) == reqPortMatches && len(cs.requiredPorts) > 0 && cs.numOptionalPorts <= (optPortMatches+optPortRangeMatches) && cs.numFlows <= flowCounter) ||
					(len(cs.requiredPorts) == 0 && cs.numOptionalPorts <= (optPortMatches+optPortRangeMatches) && cs.numFlows <= flowCounter) {

					t := "provider"
					if !provider {
						t = "consumer"
					}
					s := "port"
					if len(portMatches) > 1 {
						s = "ports"
					}
					reason := fmt.Sprintf("%s is the %s on traffic over %s %s. Required and optional non-ranges flow count is %d. ", ipAddr, t, s, strings.Join(portMatches, " "), flowCounter)

					matches = append(matches, match{csname: cs.name, ipAddress: ipAddr, app: cs.app, env: cs.env, loc: cs.loc, role: cs.role, reason: reason})
				}
			}
		}
	}

	return matches
}
