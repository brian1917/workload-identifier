# Unmanaged Maker

## Description
CLI tool that suggests unmanaged workloads for the Illumio PCE from observed traffic in Explorer.

## Input CSV File
The tool requires an input CSV with information on how to match unmanaged workloads to observed traffic. The repository includes a default CSV that is suggested to be used as a starting point. Add to it as needed. The CSV columns are explained below:
* *name* - name of the service being identified (e.g., domain controller, LDAP, etc.)
* *provider* - 1 if the workload is a provider or 0 if it is a consumer. For example, a Domain Controllers will be on the provider of observed traffic. McAfee workloads will be the consumer on traffic over port 8081.
* *required_ports* - list of ports that _must_ be observed to be considered a match. Separate ports by a space. *_Ranges are not allowed_*.
* *optional_ports* - list of ports that some must be observed to be considered a match. Separate ports by a space. Ranges are allowed and should be written as 49152-65535 with no spaces. *_A match in a range only counts once_*. For example, if a range is given as 100-200 and traffic is observed on 101 and 102, it counted as 1 optional match. This avoids situations like a server matching as a domain controller because several high end ports were identified.
* *processes* - list of optional provider processes (e.g., macmnsvc.exe) used to identify the workload.
* *num_processes_required* - number of optional proccesses to be identified to be considered a match.
* *role* - Illumio role label to be assigned.
* *app* - Illumio app label to be assigned.
* *env* - Illumio environment label be assigned.
* *loc* - Illumio location label to be assigned.

## Usage
```
Usage of unmanaged-maker:
  -d    Allow same IP address to have several unmanaged workload recommendations. Default will use the order in the input CSV and match on the first one.
  -fqdn string
        The fully qualified domain name of the PCE.
  -gat
        Output CSV will be in the format GAT expects for creating unmanaged workloads from a csv. The -w and -d flags are auto set to false with GAT. The verbose (-v) flag will not change output.
  -ilo
        Output will be two CSVs to run using two ILO-CLI commands: bulk_upload_csv and then label_sync_csv. The -w, -d, and -t flags are auto set to false with ILO. The verbose (-v) flag will not change output.
  -input string
        CSV input file to be used to identify unmanaged workloads. (default "umwl_finder_default.csv")
  -org int
        The org value for the PCE. (default 1)
  -output string
        File to write the unmanaged workloads to. (default "umwl_output.csv")
  -port int
        The port for the PCE. (default 8443)
  -pwd string
        API key if using API user or password if using email address.
  -t    PrettyPrint the CSV to the terminal.
  -timeout int
        Timeout to lookup hostname in seconds. (default 5)
  -user string
        API user or email address.
  -v    Verbose output provides an additional column in the output CSV to explain the match reason.
  -w    Include IP addresses already assigned to workloads (managed or unmanaged). Can be used as a verification.
  -x    Disable TLS checking for communication to the PCE from the tool.
  ```

  ## Hostname Resolution
  When an unmanaged workload is identified, the tool will attempt to resolve its hostname. The default allows for 5 second to resolve the hostname. It can be changed via the `-timeout` flag. If the hostname cannot be found, the output will use the name from the input file and the IP address. For example, `ldap - 10.0.80.3`