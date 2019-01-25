package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/brian1917/illumioapi"
)

type match struct {
	csname     string
	ipAddress  string
	rfc1918    bool
	hostname   string
	app        string
	env        string
	loc        string
	role       string
	reason     string
	wlhostname string
	eApp       string
	eEnv       string
	eLoc       string
	eRole      string
	wlHref     string
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

// RFC 1918 Check
func rfc1918(ipAddr string) bool {
	check := false
	rfc1918 := []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}
	// Iterate through the three RFC 1918 ranges
	for _, cidr := range rfc1918 {
		// Get the ipv4Net
		_, ipv4Net, _ := net.ParseCIDR(cidr)
		// Check if it is in the range
		check = ipv4Net.Contains(net.ParseIP(ipAddr))
		// If we get a true, append to the slice and stop checking the other ranges
		if check {
			break
		}
	}
	return check
}

// Hostname Lookup
func hostname(ipAddr string, t int) string {
	var hostname string
	ctx, cancel := context.WithTimeout(context.TODO(), time.Duration(t)*time.Millisecond)
	defer cancel()
	var r net.Resolver
	names, _ := r.LookupAddr(ctx, ipAddr)
	if len(names) > 2 {
		hostname = fmt.Sprintf("%s; %s; and %d more", names[0], names[1], len(names)-2)
	} else {
		hostname = strings.Join(names, ";")
	}
	return hostname

}

func main() {

	fqdn := flag.String("fqdn", "", "The fully qualified domain name of the PCE.")
	port := flag.Int("port", 8443, "The port for the PCE.")
	org := flag.Int("org", 1, "The org value for the PCE.")
	user := flag.String("user", "", "API user or email address.")
	pwd := flag.String("pwd", "", "API key if using API user or password if using email address.")
	app := flag.String("app", "", "App name. Explorer results focus on that app as provider or consumer. Default is all apps")
	csvFile := flag.String("in", "workload-identifier_default.csv", "CSV input file to be used to identify unmanaged workloads.")
	lookupTO := flag.Int("time", 1000, "Timeout to lookup hostname in ms.")
	consExcl := flag.String("excl", "", "Label to exclude as a consumer.")
	disableTLS := flag.Bool("x", false, "Disable TLS checking.")
	incWLs := flag.Bool("w", false, "Exclude IP addresses already assigned to workloads to suggest or verify labels.")
	privOnly := flag.Bool("p", false, "Limit suggested workloads to the RFC 1918 address space.")
	gat := flag.Bool("g", false, "Output CSV for GAT import. -w and -v are ignored with -g.")
	ilo := flag.Bool("i", false, "Output CSVs for ILO-CLI import to create UMWLs and label existing workloads.")

	// Go's alphabetical ordering is annoying so writing out our own help menu (will eventually use a cli package)
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		fmt.Println("-fqdn  string")
		fmt.Println("       The fully qualified domain name of the PCE. Required.")
		fmt.Println("-port  int")
		fmt.Println("       The port of the PCE. (default 8443)")
		fmt.Println("-org   int")
		fmt.Println("       The org value for the PCE. (default 1)")
		fmt.Println("-user  string")
		fmt.Println("       API user or email address. Required.")
		fmt.Println("-pwd   string")
		fmt.Println("       API key if using API user or password if using email address. Required.")
		fmt.Println("-app   string")
		fmt.Println("       App name. Explorer results focus on that app as provider or consumer. Default is all apps.")
		fmt.Println("-in    string")
		fmt.Println("       CSV input file to be used to identify unmanaged workloads. (default \"workload-identifier_default.csv\")")
		fmt.Println("-time  int")
		fmt.Println("       Timeout to lookup hostname in ms. (default 1000)")
		fmt.Println("-excl  string")
		fmt.Println("       Label to exclude as a consumer role")
		fmt.Println("-x     Disable TLS checking.")
		fmt.Println("-w     Exclude IP addresses already assigned to workloads to suggest or verify labels.")
		fmt.Println("-p     Limit suggested workloads to the RFC 1918 address space.")
		fmt.Println("-g     Output CSVs for GAT import to create UMWLs and label existing workloads.")
		fmt.Println("-i     Output CSVs for ILO-CLI import to create UMWLs and label existing workloads.")
	}

	// Parse flags
	flag.Parse()

	// Switched workload flag. -w is going to exclude workloads
	if !*incWLs {
		*incWLs = true
	} else {
		*incWLs = false
	}

	// If the GAT flag is set, we want to over-ride a few user-supplied flags
	if *gat {
		*incWLs = false
		*ilo = false
	}

	// If the ILO flag is set, we want to over-ride a few user-supplied flags
	if *ilo {
		*incWLs = false
	}

	// Run some quick checks on the required fields
	if len(*fqdn) == 0 || len(*user) == 0 || len(*pwd) == 0 {
		flag.Usage()
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

	// Get the label if we are going to do a consumer exclude
	var exclLabel illumioapi.Label
	if len(*consExcl) > 0 {
		exclLabel, _, err := illumioapi.GetLabel(pce, "role", *consExcl)
		if err != nil {
			log.Fatalf("ERROR - Getting label HREF - %s", err)
		}
		if exclLabel.Href == "" {
			log.Fatalf("ERROR- %s does not exist as an role label.", *consExcl)
		}
	}

	// Create the default query struct
	tq := illumioapi.TrafficQuery{
		StartTime:      time.Date(2013, 1, 1, 0, 0, 0, 0, time.UTC),
		EndTime:        time.Date(2020, 12, 30, 0, 0, 0, 0, time.UTC),
		PolicyStatuses: []string{"allowed", "potentially_blocked", "blocked"},
		SourcesExclude: []string{exclLabel.Href},
		MaxFLows:       100000}

	// If an app is provided, we want to run with that app as the consumer.
	if *app != "" {
		label, _, err := illumioapi.GetLabel(pce, "app", *app)
		if err != nil {
			log.Fatalf("ERROR - Getting label HREF - %s", err)
		}
		if label.Href == "" {
			log.Fatalf("ERROR- %s does not exist as an app label.", *app)
		}
		tq.SourcesInclude = []string{label.Href}
	}

	traffic, err := illumioapi.GetTrafficAnalysis(pce, tq)
	if err != nil {
		log.Fatalf("ERROR - Making explorer API call - %s", err)
	}

	// Switch to the destination include, clear the sources include, run query again, append to previous result
	if *app != "" {
		tq.DestinationsInclude = tq.SourcesInclude
		tq.SourcesInclude = []string{}

		traffic2, err := illumioapi.GetTrafficAnalysis(pce, tq)
		if err != nil {
			log.Fatalf("ERROR - Making second explorer API call - %s", err)
		}
		traffic = append(traffic, traffic2...)
	}

	// Get Providers and Consumers and combine into one slice
	portProv := findPorts(traffic, coreServices, true, *incWLs)
	portCons := findPorts(traffic, coreServices, false, *incWLs)
	process := findProcesses(traffic, coreServices, *incWLs)

	matches := append(append(portProv, portCons...), process...)

	// Sort the Matches by entries in the input CSV.
	// When we write the data to the output CSV, we only write the first match.
	sMatches := []match{}
	for _, cs := range coreServices {
		for _, m := range matches {
			if m.csname == cs.name {
				sMatches = append(sMatches, m)
			}
		}
	}

	// Get all workloads and create workload map
	allIPWLs := make(map[string]illumioapi.Workload)
	wls, _, err := illumioapi.GetAllWorkloads(pce)
	if err != nil {
		log.Fatalf("ERROR - getting all workloads - %s", err)
	}
	for _, wl := range wls {
		for _, iface := range wl.Interfaces {
			// We are going to use the workloads name field. If hostname is populated and not an IP address, we put that value in workload name to use the hostname
			if net.ParseIP(wl.Hostname) == nil && len(wl.Hostname) > 0 {
				wl.Name = wl.Hostname
			}
			allIPWLs[iface.Address] = wl
		}
	}

	// Get all labels and create label map
	labels, _, err := illumioapi.GetAllLabels(pce)
	if err != nil {
		log.Fatalf("ERROR - getting all workloads - %s", err)
	}
	allLabels := make(map[string]illumioapi.Label)
	for _, l := range labels {
		allLabels[l.Href] = l
	}

	// Process the match slice
	finalMatches := []match{}
	for _, sm := range sMatches {
		// Adjust the naming information
		sm.wlhostname = allIPWLs[sm.ipAddress].Name
		sm.wlHref = allIPWLs[sm.ipAddress].Href

		// If it's just an IP address, we are going to put "IP-ONLY - NO WORKLOAD" AS THE HOSTNAME
		if _, ok := allIPWLs[sm.ipAddress]; !ok {
			// Set the workload hostname if it's not a workload
			sm.wlhostname = "IP ONLY - NO WORKLOAD"
			if *lookupTO > 0 {
				sm.hostname = hostname(sm.ipAddress, *lookupTO)
				// If there's no match, use "IP - CSNAME"
				if sm.hostname == "" {
					sm.hostname = fmt.Sprintf("%s - %s", sm.ipAddress, sm.csname)
				}
				// If we aren't doing a lookup, use the "IP - CSNAME"
			} else {
				sm.hostname = fmt.Sprintf("%s - %s", sm.ipAddress, sm.csname)
			}
			// If the workload is in the map, get the hostname that we previously populated
		} else {
			sm.hostname = sm.wlhostname
		}

		// Check for RFC 1918
		sm.rfc1918 = rfc1918(sm.ipAddress)

		// Populate existing label information
		for _, l := range allIPWLs[sm.ipAddress].Labels {
			switch {
			case allLabels[l.Href].Key == "app":
				{
					sm.eApp = allLabels[l.Href].Value
				}
			case allLabels[l.Href].Key == "role":
				{
					sm.eRole = allLabels[l.Href].Value
				}
			case allLabels[l.Href].Key == "env":
				{
					sm.eEnv = allLabels[l.Href].Value
				}
			case allLabels[l.Href].Key == "loc":
				{
					sm.eLoc = allLabels[l.Href].Value
				}
			}
		}

		// Append results to a new array, taking into account the private IP address flag
		if sm.rfc1918 && *privOnly || !*privOnly {
			finalMatches = append(finalMatches, sm)
		}
	}

	// Create the output csv file and add headers if needed (no headers for GAT)
	var file1, file2 *os.File
	defaultOut := "identified-workloads.csv"
	gatUMWLOut := "gat-create-umwls.csv"
	gatLabelOut := "gat-update-labels.csv"
	iloWLOut := "ilo-create-umwls.csv"
	iloLabelOut := "ilo-update-labels.csv"

	if len(matches) > 0 {
		switch {
		case *gat:
			{
				file1, err = os.Create(gatUMWLOut)
				if err != nil {
					log.Fatalf("ERROR - Creating file - %s\n", err)
				}
				defer file1.Close()
				file2, err = os.Create(gatLabelOut)
				if err != nil {
					log.Fatalf("ERROR - Creating file - %s\n", err)
				}
				defer file2.Close()
			}
		case *ilo:
			{
				file1, err = os.Create(iloWLOut)
				if err != nil {
					log.Fatalf("ERROR - Creating file - %s\n", err)
				}
				defer file1.Close()
				file2, err = os.Create(iloLabelOut)
				if err != nil {
					log.Fatalf("ERROR - Creating file - %s\n", err)
				}
				defer file2.Close()
				fmt.Fprintf(file1, "hostname,ips,os_type\r\n")
				fmt.Fprintf(file2, "role,app,env,loc,ips\r\n")
			}
		default:
			{
				file1, err = os.Create(defaultOut)
				if err != nil {
					log.Fatalf("ERROR - Creating file - %s\n", err)
				}
				defer file1.Close()
				fmt.Fprintf(file1, "ip_address,name,existing_workload,current_role,current_app,current_env,current_loc,suggested_role,suggested_app,suggested_env,suggested_loc,match_reason\r\n")
			}
		}

		// Write the data
		ipAddr := make(map[string]int)
		ref := 122
		for _, fm := range finalMatches {
			if _, ok := ipAddr[fm.ipAddress]; !ok {
				ipAddr[fm.ipAddress] = 1
				wlCheck := "Yes"
				if fm.wlhostname == "IP ONLY - NO WORKLOAD" {
					wlCheck = "No"
				}
				switch {
				case *gat:
					{
						// Write the UMWLs
						if wlCheck == "No" {
							fmt.Fprintf(file1, "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\r\n", fm.hostname, "", fm.role, fm.app, fm.env, fm.loc, fm.hostname, "", "", "", fm.ipAddress, "eth0:"+fm.ipAddress, "set123", "ref-"+strconv.Itoa(ref+1))
							// Write the update labels
						} else {
							fmt.Fprintf(file2, "%s,%s,%s,%s,%s,%s\r\n", fm.ipAddress, fm.role, fm.app, fm.env, fm.loc, fm.wlHref)
						}
					}
				case *ilo:
					{
						// Write the UMWLs
						if wlCheck == "No" {
							fmt.Fprintf(file1, "%s,%s,%s\r\n", fm.hostname, fm.ipAddress, "")
							// Write the update labels
						} else {
							fmt.Fprintf(file2, "%s,%s,%s,%s,%s\r\n", fm.role, fm.app, fm.env, fm.loc, fm.ipAddress)
						}
					}
				default:
					{
						fmt.Fprintf(file1, "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\r\n", fm.ipAddress, fm.hostname, wlCheck, fm.eRole, fm.eApp, fm.eEnv, fm.eLoc, fm.role, fm.app, fm.env, fm.loc, fm.reason)
					}
				}

			}

		}

	}
}
