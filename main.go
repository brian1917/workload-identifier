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
	csname     string
	ipAddress  string
	hostname   string
	app        string
	env        string
	loc        string
	role       string
	reason     string
	wlhostname string
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
	gat := flag.Bool("gat", false, "Output CSV will be in the format GAT expects for creating unmanaged workloads from a csv. The -w and -d flags are auto set to false with GAT. The verbose (-v) flag will not change output.")
	ilo := flag.Bool("ilo", false, "Output will be two CSVs to run using two ILO-CLI commands: bulk_upload_csv and then label_sync_csv. The -w, -d, and -t flags are auto set to false with ILO. The verbose (-v) flag will not change output.")

	// Parse flags
	flag.Parse()

	// If the GAT flag is set, we want to over-ride a few user-supplied flags
	if *gat {
		*incWLs = false
		*dupes = false
		*ilo = false
		*term = false
	}

	// If the ILO flag is set, we want to over-ride a few user-supplied flags
	if *ilo {
		*incWLs = false
		*dupes = false
		*term = false
	}

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
	allIPs := make(map[string]string)
	wls, _, err := illumioapi.GetAllWorkloads(pce)
	if err != nil {
		log.Fatalf("ERROR - getting all workloads - %s", err)
	}
	for _, wl := range wls {

		for _, iface := range wl.Interfaces {
			name := wl.Name
			if net.ParseIP(wl.Hostname) == nil && len(wl.Hostname) > 0 {
				name = wl.Hostname
			}
			allIPs[iface.Address] = name
		}
	}
	sNonWlMatches := []match{}
	sMatchesWLName := []match{}
	for _, sm := range sMatches {
		sm.wlhostname = allIPs[sm.ipAddress]
		if _, ok := allIPs[sm.ipAddress]; !ok {
			sm.wlhostname = "IP ONLY - NO WORKLOAD"
			sNonWlMatches = append(sNonWlMatches, sm)
		}
		sMatchesWLName = append(sMatchesWLName, sm)
	}

	// Assign the final matches
	finalMatches := sNonWlMatches
	if *incWLs {
		finalMatches = sMatchesWLName
	}

	// Get the hostnames for the final matches
	var finalMatchesHost []match
	ctx, cancel := context.WithTimeout(context.TODO(), time.Duration(*lookupTO)*time.Second)
	defer cancel() // important to avoid a resource leak
	var r net.Resolver
	for _, fm := range finalMatches {
		if fm.wlhostname == "IP ONLY - NO WORKLOAD" {
			names, _ := r.LookupAddr(ctx, fm.ipAddress)
			if len(names) > 2 {
				fm.hostname = fmt.Sprintf("%s; %s; and %d more", names[0], names[1], len(names)-2)
			} else {
				fm.hostname = strings.Join(names, ";")
			}
			if fm.hostname == "" {
				fm.hostname = fmt.Sprintf("%s - %s", fm.ipAddress, fm.csname)
			}
		} else {
			fm.hostname = fm.wlhostname
		}
		finalMatchesHost = append(finalMatchesHost, fm)
	}

	ipAddr := make(map[string]int)
	// Write out the CSV file
	fileName := *outputFile
	if *ilo {
		fileName = fmt.Sprintf("%s%s", "bulk_upload_csv-", *outputFile)
	}
	if len(matches) > 0 {
		file, err := os.Create(fileName)
		if err != nil {
			log.Fatalf("ERROR - Creating file - %s\n", err)
		}
		defer file.Close()

		// Write the headers
		switch {
		case *gat:
			{
				// GAT does not use headers - do nothing
			}
		case *ilo:
			{
				fmt.Fprintf(file, "hostname,ips,os_type\r\n")
			}
		case *verbose:
			{
				fmt.Fprintf(file, "ip_address,hostname,app,role,env,loc,existing_workload,match_reason\r\n")
			}
		default:
			{
				fmt.Fprintf(file, "ip_address,hostname,app,role,env,loc\r\n")
			}
		}

		// Write the data
		for _, fmh := range finalMatchesHost {
			if _, ok := ipAddr[fmh.ipAddress]; !ok || *dupes {
				ipAddr[fmh.ipAddress] = 1
				wlCheck := "Yes"
				if fmh.wlhostname == "IP ONLY - NO WORKLOAD" {
					wlCheck = "No"
				}
				switch {
				case *gat:
					{
						fmt.Fprintf(file, "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,eth0:%s,%s,%s\r\n", fmh.hostname, "", fmh.role, fmh.app, fmh.env, fmh.loc, fmh.hostname, "", "", "", fmh.ipAddress, fmh.ipAddress, "", "")
					}
				case *ilo:
					{
						fmt.Fprintf(file, "%s,%s,%s\r\n", fmh.hostname, fmh.ipAddress, "")
					}
				case *verbose:
					{
						fmt.Fprintf(file, "%s,%s,%s,%s,%s,%s,%s,%s\r\n", fmh.ipAddress, fmh.hostname, fmh.app, fmh.role, fmh.env, fmh.loc, wlCheck, fmh.reason)
					}
				default:
					{
						fmt.Fprintf(file, "%s,%s,%s,%s,%s,%s\r\n", fmh.ipAddress, fmh.hostname, fmh.app, fmh.role, fmh.env, fmh.loc)
					}
				}

			}

		}

		// If ILO, we need to create a second CSV
		if *ilo {
			ipAddr := make(map[string]int)
			file, err := os.Create("label_sync_csv-" + *outputFile)
			if err != nil {
				log.Fatalf("ERROR - Creating file - %s\n", err)
			}
			defer file.Close()
			fmt.Fprintf(file, "role,app,env,loc,ips\r\n")
			for _, fmh := range finalMatchesHost {
				if _, ok := ipAddr[fmh.ipAddress]; !ok {
					ipAddr[fmh.ipAddress] = 1
					fmt.Fprintf(file, "%s,%s,%s,%s,%s\r\n", fmh.role, fmh.app, fmh.env, fmh.loc, fmh.ipAddress)
				}
			}

		}

		// Print to terminal if flagged
		if *term {
			table, err := tablewriter.NewCSV(os.Stdout, *outputFile, !*gat)
			if err != nil {
				log.Printf("Error - printing csv to terminal - %s", err)
			}
			table.SetAlignment(tablewriter.ALIGN_LEFT)
			table.SetRowLine(true)
			table.SetRowSeparator("-")
			table.Render()
		}
	} else {
		fmt.Println("NO MATCHES")
	}

}
