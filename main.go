package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/brian1917/illumioapi"
	"stash.ilabs.io/ct/goabsorption/tablewriter"
)

type match struct {
	csname    string
	ipAddress string
	hostname  string
	app       string
	env       string
	loc       string
	role      string
	reason    string
}

// Contains checks if an integer is in a slice
func containsInt(intSlice []int, searchInt int) bool {
	for _, value := range intSlice {
		if value == searchInt {
			return true
		}
	}
	return false
}

// ContainsStr hecks if an integer is in a slice
func containsStr(strSlice []string, searchStr string) bool {
	for _, value := range strSlice {
		if value == searchStr {
			return true
		}
	}
	return false
}

func main() {

	fqdn := flag.String("fqdn", "", "The fully qualified domain name of the PCE.")
	port := flag.Int("port", 8443, "The port for the PCE.")
	org := flag.Int("org", 1, "The org value for the PCE.")
	user := flag.String("user", "", "API user or email address.")
	pwd := flag.String("pwd", "", "API key if using API user or password if using email address.")
	csvFile := flag.String("input", "umwl_finder_default.csv", "CSV input file to be used to identify unmanaged workloads.")
	outputFile := flag.String("output", "umwl_output.csv", "File to write the unmanaged workloads to.")
	incWLs := flag.Bool("w", false, "Include IP addresses already assigned to workloads (managed or unmanaged). Can be used as a verification.")
	disableTLS := flag.Bool("x", false, "Disable TLS checking for communication to the PCE from the tool.")
	verbose := flag.Bool("v", false, "Verbose output provides an additional column in the output CSV to explain the match reason.")
	dupes := flag.Bool("d", false, "Allow same IP address to have several unmanaged workload recommendations. Default will use the order in the input CSV and match on the first one.")
	term := flag.Bool("t", false, "PrettyPrint the CSV to the terminal.")
	lookupTO := flag.Int("timeout", 5, "Timeout to lookup hostname in seconds.")

	// Parse flags
	flag.Parse()

	// Run some quick checks
	if len(*fqdn) == 0 || len(*user) == 0 || len(*pwd) == 0 {
		flag.PrintDefaults()
		log.Fatalf("ERROR - Required flags not included")
	}

	// If user is provided, we need to authenticate to the PCE
	userStr := *user
	if userStr[:4] != "api_" {
		auth, _, err := illumioapi.Authenticate(illumioapi.PCE{FQDN: *fqdn, Port: *port, Org: *org, DisableTLSChecking: *disableTLS}, *user, *pwd)
		if err != nil {
			log.Fatalf("Error - Authenticating to PCE - %s", err)
		}
		login, _, err := illumioapi.Login(illumioapi.PCE{FQDN: *fqdn, Port: *port, Org: *org, DisableTLSChecking: *disableTLS}, auth.AuthToken)
		if err != nil {
			log.Fatalf("Error - Logging in to PCE - %s", err)
		}
		user = &login.AuthUsername
		pwd = &login.SessionToken
	}

	// Create the PCE
	pce := illumioapi.PCE{
		FQDN:               *fqdn,
		Port:               *port,
		Org:                *org,
		User:               *user,
		Key:                *pwd,
		DisableTLSChecking: *disableTLS}

	// Parse the CSV
	coreServices := csvParser(*csvFile)

	// Create the query struct - don't need most fields
	traffic, err := illumioapi.GetTrafficAnalysis(pce, illumioapi.TrafficQuery{
		StartTime:      time.Date(2013, 1, 1, 0, 0, 0, 0, time.UTC),
		EndTime:        time.Date(2020, 12, 30, 0, 0, 0, 0, time.UTC),
		PolicyStatuses: []string{"allowed", "potentially_blocked", "blocked"},
		MaxFLows:       100000})

	if err != nil {
		log.Fatalf("ERROR - Making explorer API call - %s", err)
	}

	// Get Providers and Consumers and combine into one slice
	portProv := findPorts(traffic, coreServices, true, *incWLs)
	portCons := findPorts(traffic, coreServices, false, *incWLs)
	process := findProcesses(traffic, coreServices, *incWLs)

	matches := append(append(portProv, portCons...), process...)

	// Sort the Matches
	sMatches := []match{}
	for _, cs := range coreServices {
		for _, m := range matches {
			if m.csname == cs.name {
				sMatches = append(sMatches, m)
			}
		}
	}

	// Remove entries where the IP Address is assigned to a workload
	allIPs := make(map[string]int)
	wls, _, err := illumioapi.GetAllWorkloads(pce)
	if err != nil {
		log.Fatalf("ERROR - getting all workloads - %s", err)
	}
	for _, wl := range wls {
		for _, iface := range wl.Interfaces {
			allIPs[iface.Address] = 1
		}
	}
	sNonWlMatches := []match{}
	for _, sm := range sMatches {
		if _, ok := allIPs[sm.ipAddress]; !ok {
			sNonWlMatches = append(sNonWlMatches, sm)
		}
	}

	// Assign the final matches
	finalMatches := sNonWlMatches
	if *incWLs {
		finalMatches = sMatches
	}

	// Get the hostnames for the final matches
	var finalMatchesHost []match
	ctx, cancel := context.WithTimeout(context.TODO(), time.Duration(*lookupTO)*time.Second)
	defer cancel() // important to avoid a resource leak
	var r net.Resolver
	for _, fm := range finalMatches {
		names, _ := r.LookupAddr(ctx, fm.ipAddress)
		fm.hostname = strings.Join(names, ",")
		if fm.hostname == "" {
			fm.hostname = fmt.Sprintf("%s - %s", fm.ipAddress, fm.csname)
		}
		finalMatchesHost = append(finalMatchesHost, fm)
	}

	ipAddr := make(map[string]int)
	// Write out the CSV file
	if len(matches) > 0 {
		file, err := os.Create(*outputFile)
		if err != nil {
			log.Fatalf("ERROR - Creating file - %s\n", err)
		}
		defer file.Close()

		if *verbose {
			fmt.Fprintf(file, "ip_address,hostname,app,role,env,loc,match_reason\r\n")
			for _, fmh := range finalMatchesHost {
				if _, ok := ipAddr[fmh.ipAddress]; !ok || *dupes {
					ipAddr[fmh.ipAddress] = 1
					fmt.Fprintf(file, "%s,%s,%s,%s,%s,%s,%s\r\n", fmh.ipAddress, fmh.hostname, fmh.app, fmh.role, fmh.env, fmh.loc, fmh.reason)
				}

			}
		} else {
			fmt.Fprintf(file, "ip_address,hostname,app,role,env,loc\r\n")
			for _, fmh := range finalMatchesHost {
				if _, ok := ipAddr[fmh.ipAddress]; !ok || *dupes {
					ipAddr[fmh.ipAddress] = 1
					fmt.Fprintf(file, "%s,%s,%s,%s,%s,%s\r\n", fmh.ipAddress, fmh.hostname, fmh.app, fmh.role, fmh.env, fmh.loc)
				}
			}
		}
	}

	// Print to terminal if flagged
	if *term {
		table, err := tablewriter.NewCSV(os.Stdout, *outputFile, true)
		if err != nil {
			log.Printf("Error - printing csv to terminal - %s", err)
		}
		table.SetAlignment(tablewriter.ALIGN_LEFT)
		table.SetRowLine(true)
		table.SetRowSeparator("-")
		table.Render()
	}

}
