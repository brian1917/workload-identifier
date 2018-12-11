package main

import (
	"bufio"
	"encoding/csv"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
)

type coreService struct {
	name               string
	provider           bool
	requiredPorts      []int
	optionalPorts      []int
	optionalPortRanges [][]int
	numOptionalPorts   int
	processes          []string
	numProcessesReq    int
	app                string
	env                string
	loc                string
	role               string
}

func csvParser(filename string) []coreService {

	/**
	CSV Fields:
	0 - name
	1 - provider
	2 - required_ports
	3 - optional_ports
	4 - num_optional_ports_required
	5 - processes
	6 - process_required
	7 - role
	8 - app
	9 - env
	10 - loc
	**/

	var coreServices []coreService

	// Open CSV File
	csvFile, _ := os.Open(filename)
	reader := csv.NewReader(bufio.NewReader(csvFile))

	// Start the counters
	i := 0

	for {
		// Reset variables
		reqPortsInt := []int{}
		optPortsInt := []int{}
		optPortRangesInt := [][]int{}
		numOptPorts := 0
		numProcessesReq := 0

		// Increment the counter
		i++

		// Read the CSV
		line, err := reader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Fatalf("Error - Reading CSV File - %s", err)
		}

		// Skip the header row
		if i != 1 {

			// Set provider
			provider := true
			if line[1] == "0" {
				provider = false
			}
			// Set the required ports slice if there is any text in the field
			if len(line[2]) > 0 {
				requiredPortsStr := strings.Split(line[2], " ")
				for _, strPort := range requiredPortsStr {
					intPort, err := strconv.Atoi(strPort)
					if err != nil {
						log.Fatalf("ERROR - Converting required port to int on line %d - %s", i, err)
					}
					reqPortsInt = append(reqPortsInt, intPort)
				}
			}

			// Set the optional ports slice if there is any text in the field
			if len(line[3]) > 0 {

				// Split based on spaces
				optPortsStr := strings.Split(line[3], " ")

				for _, strPort := range optPortsStr {
					rangePortInt := []int{}

					// Process the entry if it a range
					rangePortStr := strings.Split(strPort, "-")
					if len(rangePortStr) > 1 {
						for _, rangeValue := range rangePortStr {
							value, err := strconv.Atoi(rangeValue)
							if err != nil {
								log.Fatalf("ERROR - Converting port range values to int on line %d - %s", i, err)
							}
							rangePortInt = append(rangePortInt, value)
						}
						optPortRangesInt = append(optPortRangesInt, rangePortInt)
					}

					// Process the entry if it is a single port
					if len(rangePortInt) == 0 {
						intPort, err := strconv.Atoi(strPort)
						if err != nil {
							log.Fatalf("ERROR - Converting optional port to int on line %d - %s", i, err)
						}
						optPortsInt = append(optPortsInt, intPort)
					}
				}
			}

			// Convert the number of optional ports to int if there is any text in the field
			if len(line[4]) > 0 {
				numOptPorts, err = strconv.Atoi(line[4])
				if err != nil {
					log.Fatalf("ERROR - Converting number of required ports to int on line %d - %s", i, err)
				}
			}

			// Convert the number of processes to int if there is any text in the field
			if len(line[6]) > 0 {
				numProcessesReq, err = strconv.Atoi(line[6])
				if err != nil {
					log.Fatalf("ERROR - Converting number of required consumer services to int on line %d - %s", i, err)
				}
			}

			// Append to the coreServices slice
			coreServices = append(coreServices, coreService{
				name:               line[0],
				provider:           provider,
				requiredPorts:      reqPortsInt,
				optionalPorts:      optPortsInt,
				optionalPortRanges: optPortRangesInt,
				numOptionalPorts:   numOptPorts,
				processes:          strings.Split(line[5], " "),
				numProcessesReq:    numProcessesReq,
				app:                line[8],
				env:                line[9],
				loc:                line[10],
				role:               line[7]})

		}
	}

	return coreServices

}
