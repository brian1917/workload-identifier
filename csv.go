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
	numFlows           int
	processes          []string
	numProcessesReq    int
	app                string
	env                string
	loc                string
	role               string
}

func csvParser(filename string) []coreService {

	// Set CSV columns here to avoid changing multiple locations
	csvName := 0
	csvProvider := 1
	csvReqPorts := 2
	csvOptPorts := 3
	csvNumOptPorts := 4
	csvNumFlows := 5
	csvProcesses := 6
	csvNumProcess := 7
	csvRole := 8
	csvApp := 9
	csvEnv := 10
	csvLoc := 11

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
		numFlows := 0

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
			if line[csvProvider] == "0" {
				provider = false
			}
			// Set the required ports slice if there is any text in the field
			if len(line[csvReqPorts]) > 0 {
				requiredPortsStr := strings.Split(line[csvReqPorts], " ")
				for _, strPort := range requiredPortsStr {
					intPort, err := strconv.Atoi(strPort)
					if err != nil {
						log.Fatalf("ERROR - Converting required port to int on line %d - %s", i, err)
					}
					reqPortsInt = append(reqPortsInt, intPort)
				}
			}

			// Set the optional ports slice if there is any text in the field
			if len(line[csvOptPorts]) > 0 {

				// Split based on spaces
				optPortsStr := strings.Split(line[csvOptPorts], " ")

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
			if len(line[csvNumOptPorts]) > 0 {
				numOptPorts, err = strconv.Atoi(line[csvNumOptPorts])
				if err != nil {
					log.Fatalf("ERROR - Converting number of required ports to int on line %d - %s", i, err)
				}
			}

			// Convert the number of flows to int
			if len(line[csvNumFlows]) > 0 {
				numFlows, err = strconv.Atoi(line[csvNumFlows])
				if err != nil {
					log.Fatalf("ERROR - Converting number of flows to int on line %d - %s", i, err)
				}
			}

			// Convert the number of processes to int if there is any text in the field
			if len(line[6]) > 0 {
				numProcessesReq, err = strconv.Atoi(line[csvNumProcess])
				if err != nil {
					log.Fatalf("ERROR - Converting number of required consumer services to int on line %d - %s", i, err)
				}
			}

			// Append to the coreServices slice
			coreServices = append(coreServices, coreService{
				name:               line[csvName],
				provider:           provider,
				requiredPorts:      reqPortsInt,
				optionalPorts:      optPortsInt,
				optionalPortRanges: optPortRangesInt,
				numFlows:           numFlows,
				numOptionalPorts:   numOptPorts,
				processes:          strings.Split(line[csvProcesses], " "),
				numProcessesReq:    numProcessesReq,
				app:                line[csvApp],
				env:                line[csvEnv],
				loc:                line[csvLoc],
				role:               line[csvRole]})

		}
	}

	return coreServices

}
