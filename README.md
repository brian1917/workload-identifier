# Unmanaged Maker

## Description
CLI tool that suggets unmanaged workloads for the Illumio PCE from observed traffic in Explorer.

## Input CSV File
The tool requires an input CSV. The repository includes a default CSV that is suggested to be used as a starting point. Add to it as needed. The CSV columns are explained below:
* *name* - name of the service being identified (e.g., domain controller, LDAP, etc.)
* *provider* - 1 if the workload is a provider or 0 if it is a consumer. For example, Domain Controllers will the providers on the matching traffic. McAfee * workloads will be consumers on their identified traffic over port 8081.
* *require_ports* - list of ports that _must_ be observed to be considered a match. Separate ports by a space. Ranges are not allowed.
* *optional_ports* - list of ports that some must be observed to be considered a match. Separate ports by a space. Ranges should be written at 49152-65535 (no spaces). A match in a range only counts once. For example, if a range is given as 100-200 and traffic is observed on 101 and 102, it counted as 1 optional match. This is to avoid situations like a server matching as a domain controller because several high end ports were identified.
* *processes* - list of optional provider processes (e.g., test.exe) used to identify the workload.
* *num_processes_required* - number of optional proccesses to be identified to be considered a match.
* *role* - Illumio role label to be assigned
* *app* - Illumio app label to be assigned
* *env* - Illumio environment label be assigned
* *loc* - Illumio location label to be assigned.

## Usage
```
Usage of unmanaged-maker:
  -d    Allow same IP address to have several unmanaged workloda recommendations. Default will use the order in the input CSV.
  -fqdn string
        The fully qualified domain name of the PCE.
  -input string
        CSV File to be used to identify unmanaged workloads. (default "umwl_finder_default.csv")
  -org int
        The org value for the PCE. (default 1)
  -output string
        File to write the unmanaged workloads to. (default "umwl_output.csv")
  -port int
        The port for the PCE. (default 8443)
  -pwd string
        API Key if using API user or password if using email address.
  -t    Print the CSV to the terminal
  -timeout int
        Timeout to lookup hostname in seconds. (default 5)
  -user string
        API User or email address.
  -v    Verbose output produces a log file and adds an additional column in the output CSV for match reason.
  -w    Include IP addresses already assigned to workloads (typically used in testing only).
  -x    Disable TLS checking
  ```