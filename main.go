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
)

type result struct {
	csname      string
	ipAddress   string
	hostname    string
	app         string
	env         string
	loc         string
	role        string
	reason      string
	wlhostname  string
	eApp        string
	eEnv        string
	eLoc        string
	eRole       string
	wlHref      string
	matchStatus int // 0 = Existing Workload Match; 1 = UMWL Match; 2 = Existing Workload No Match
}

func (m *result) subnetRelabeler(n2l []subnetLabel) {

	//cycle through all the subnets to see if workload IP is within a subnet...
	for _, nets := range n2l {
		if nets.network.Contains(net.ParseIP(m.ipAddress)) {

			//If in the subnet then get loc and env labels associated with subnet unless empty string
			if nets.locLabel != "" {
				m.loc = nets.locLabel
			}
			if nets.envLabel != "" {
				m.env = nets.envLabel
			}
		}
	}
}

// Workload Labels
func (m *result) existingLabels(workloads map[string]illumioapi.Workload, labels map[string]illumioapi.Label) {
	for _, l := range workloads[m.ipAddress].Labels {
		switch {
		case labels[l.Href].Key == "app":
			{
				m.eApp = labels[l.Href].Value
			}
		case labels[l.Href].Key == "role":
			{
				m.eRole = labels[l.Href].Value
			}
		case labels[l.Href].Key == "env":
			{
				m.eEnv = labels[l.Href].Value
			}
		case labels[l.Href].Key == "loc":
			{
				m.eLoc = labels[l.Href].Value
			}
		}
	}
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
	exclWLs := flag.Bool("w", false, "Exclude IP addresses already assigned to workloads to suggest or verify labels.")
	privOnly := flag.Bool("p", false, "Exclude public IP addresses and limit suggested workloads to the RFC 1918 address space.")
	gat := flag.Bool("g", false, "Output CSV for GAT import. -w and -v are ignored with -g.")
	ilo := flag.Bool("i", false, "Output CSVs for ILO-CLI import to create UMWLs and label existing workloads.")
	nonMatchIncl := flag.Bool("n", false, "Include information (ports and hostname lookups) for workloads and IP Addresses that do not match a service.")
	snet := flag.String("snet", "", "Subnet to location CSV file name. Overides csvFile entries")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		fmt.Println("-fqdn  string")
		fmt.Println("       The fully qualified domain name of the PCE. Required.")
		fmt.Println("-port  int")
		fmt.Println("       The port of the PCE. (default 8443)")
		fmt.Println("-user  string")
		fmt.Println("       API user or email address. Required.")
		fmt.Println("-pwd   string")
		fmt.Println("       API key if using API user or password if using email address. Required.")
		fmt.Println("-org   int")
		fmt.Println("       The org value for the PCE. Only needed if SaaS PCE while using API ID/Key.")
		fmt.Println("-in    string")
		fmt.Println("       CSV input file to be used to identify workloads. (default \"workload-identifier_default.csv\")")
		fmt.Println("-time  int")
		fmt.Println("       Timeout to lookup hostname in ms. 0 will skip hostname lookups. (default 1000)")
		fmt.Println("-app   string")
		fmt.Println("       App name to limit Explorer results to flows with that app as a provider or consumer. Default is all apps.")
		fmt.Println("-excl  string")
		fmt.Println("       Label to exclude as a consumer role")
		fmt.Println("-snet  string")
		fmt.Println("       CSV input file to identify location based on IP address. *Ignore if left out")
		fmt.Println("-x     Disable TLS checking.")
		fmt.Println("-p     Exclude public IP addresses and limit suggested workloads to the RFC 1918 address space.")
		fmt.Println("-w     Exclude IP addresses already assigned to workloads to suggest or verify labels.")
		fmt.Println("-n     Include workloads (ports in use and hostnames) that do not match a service in the output.")
		fmt.Println("-g     Output CSVs for GAT import to create UMWLs and label existing workloads.")
		fmt.Println("-i     Output CSVs for ILO-CLI import to create UMWLs and label existing workloads.")
	}

	// Parse flags
	flag.Parse()

	// Run some checks on the required fields
	if len(*fqdn) == 0 || len(*user) == 0 || len(*pwd) == 0 {
		log.Fatalf("ERROR - Required arguments not included. Run -h for usgae.")
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
		org = &login.Orgs[0].ID
	}

	// Create the PCE
	pce := illumioapi.PCE{
		FQDN:               *fqdn,
		Port:               *port,
		Org:                *org,
		User:               *user,
		Key:                *pwd,
		DisableTLSChecking: *disableTLS}

	// Parse the iunput CSVs
	var subnetLabels []subnetLabel
	if *snet != "" {
		subnetLabels = locParser(*snet)
	}
	coreServices := csvParser(*csvFile)

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

	// If an app is provided, adjust query to include it
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

	// Run traffic query
	traffic, err := illumioapi.GetTrafficAnalysis(pce, tq)
	if err != nil {
		log.Fatalf("ERROR - Making explorer API call - %s", err)
	}

	// If app is provided, switch to the destination include, clear the sources include, run query again, append to previous result
	if *app != "" {
		tq.DestinationsInclude = tq.SourcesInclude
		tq.SourcesInclude = []string{}

		traffic2, err := illumioapi.GetTrafficAnalysis(pce, tq)
		if err != nil {
			log.Fatalf("ERROR - Making second explorer API call - %s", err)
		}
		traffic = append(traffic, traffic2...)
	}

	// Get matches for provider ports (including non-match existing workloads), consumer ports, and processes
	portProv, nonMatches := findPorts(traffic, coreServices, true)
	portCons, _ := findPorts(traffic, coreServices, false)
	process := findProcesses(traffic, coreServices)

	// Make one slice from port port results (prov and cons), processes, and nonmatches
	var results []result
	if *nonMatchIncl {
		results = append(append(append(portProv, portCons...), process...), nonMatches...)
	} else {
		results = append(append(portProv, portCons...), process...)
	}

	// Create the final matches array
	finalMatches := []result{}

	// Create a map to keep track of when we write a match.
	ipAddr := make(map[string]int)

	// For each input core service, process its matches to preserve input service order.
	i := 0
	for _, cs := range coreServices {
		i++
		// Iterate each match for each core services.
		for _, r := range results {
			// Only process those that have not been matched
			if _, ok := ipAddr[r.ipAddress]; !ok {
				// Process entries if it matches a core service OR is an existing workload with no matches and done processing all core services
				if r.csname == cs.name || (r.matchStatus == 2 && allIPWLs[r.ipAddress].Href != "" && i == len(coreServices)) {
					// Set hostnames and HREF for existing workloads
					r.hostname = allIPWLs[r.ipAddress].Name
					r.wlHref = allIPWLs[r.ipAddress].Href
					// Set hostname for non-existing workloads
					if _, ok := allIPWLs[r.ipAddress]; !ok {
						r.matchStatus = 1 // UMWL status code
						// Default hostname is IP - CSNAME. Lookup will override.
						r.hostname = fmt.Sprintf("%s - %s", r.ipAddress, r.csname)
						if *lookupTO > 0 {
							h := hostname(r.ipAddress, *lookupTO)
							if h != "" {
								r.hostname = h
							}
						}
					}
					// Populate existing label information
					r.existingLabels(allIPWLs, allLabels)
					//If snet set check for label based on Subnet
					if *snet != "" {
						r.subnetRelabeler(subnetLabels)
					}
					// Append results to a new array, if RFC 1918 and that's all we want OR we don't care about RFC 1918.
					if rfc1918(r.ipAddress) && *privOnly || !*privOnly {
						finalMatches = append(finalMatches, r)
						ipAddr[r.ipAddress] = 1
					}
				}
			}
		}
	}

	// If we have data, send to writing CSV
	if len(results) > 0 {
		csvWriter(finalMatches, *ilo, *gat, *exclWLs, *nonMatchIncl)
	}
}
