package main

import "github.com/brian1917/illumioapi"

func findProcesses(traffic []illumioapi.TrafficAnalysis, coreServices []coreService, incWL bool) []match {
	// Create a slice to hold the matches
	var matches []match

	// Drop all traffic coming from a workload - that means the consumer is known
	var unkConsTraffic []illumioapi.TrafficAnalysis
	for _, entry := range traffic {
		if (!incWL && entry.Src.Workload == nil) || (incWL && entry.Src.IP != entry.Dst.IP) {
			unkConsTraffic = append(unkConsTraffic, entry)
		}
	}

	// For each traffic flow going to an unknown consumer, check to see if we have the process already
	consIPAddressProcess := make(map[string][]string)
	for _, ct := range unkConsTraffic {
		if processes, ok := consIPAddressProcess[ct.Src.IP]; ok {
			if !containsStr(processes, ct.ExpSrv.Process) {
				consIPAddressProcess[ct.Src.IP] = append(processes, ct.ExpSrv.Process)
			}
		} else {
			consIPAddressProcess[ct.Src.IP] = []string{ct.ExpSrv.Process}
		}
	}

	// Cycle through each Source IP address from the explorer results
	for ipAddr, processes := range consIPAddressProcess {

		// Cycle through core services to look for matches
		for _, cs := range coreServices {
			processMatches := 0
			for _, csProcess := range cs.processes {
				if containsStr(processes, csProcess) {
					processMatches++
				}
			}

			// Check if it should count
			if cs.numProcessesReq <= processMatches && cs.numProcessesReq > 0 {
				if !cs.provider {
					matches = append(matches, match{csname: cs.name, ipAddress: ipAddr, app: cs.app, env: cs.env, loc: cs.loc, role: cs.role})
				}
			}
		}

	}

	return matches
}
