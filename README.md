# Unmanaged Maker

## Description
CLI tool that suggests unmanaged workloads for the Illumio PCE from observed traffic in Explorer. The output of the tool should be reviewed and then used to import into the PCE to create and label the workloads. The default output is the easiest to consume. When you are ready to import, you can run the tool with either the `-g` flag to create a CSV to be used with GAT to import the workloads and labels or the `-i` flag to create two CSVs (one for workloads and one for labels) to be used with the ILO-CLI tool.

## Input CSV File
The tool requires an input CSV with information on how to match IP addresses from observed traffic to unmanaged workloads. The repository includes a default CSV that is suggested to be used as a starting point. Add to it as needed.
* **name** - name of the service being identified (e.g., domain controller, LDAP, etc.)
* **provider** - 1 if the workload is a provider or 0 if it is a consumer. For example, a Domain Controllers will be on the provider of observed traffic. McAfee workloads will be the consumer on traffic over port 8081.
* **required_ports** - list of ports that _must_ be observed to be considered a match. Separate ports by a space. *_Ranges are not allowed_*.
* **optional_ports** - list of ports that some must be observed to be considered a match. Separate ports by a space. Ranges are allowed and should be written as 49152-65535 with no spaces. *_A match in a range only counts once_*. For example, if a range is given as 100-200 and traffic is observed on 101 and 102, it counted as 1 optional match. This avoids situations like a server matching as a domain controller because several high end ports were identified.
* **num_optional_ports** - number of optional ports that must be matched.
* **num_flows** - number of flows that must be observed on required ports and optional ports. Flows observed in port ranges do not count toward this requirement.
* **processes** - list of optional provider processes (e.g., macmnsvc.exe) used to identify the workload.
* **num_processes_required** - number of optional proccesses to be identified to be considered a match.
* **role** - Illumio role label to be assigned.
* **app** - Illumio app label to be assigned.
* **env** - Illumio environment label be assigned.
* **loc** - Illumio location label to be assigned.

## Usage
`unmanaged-maker -h`
```
Usage of unmanaged-maker:
-fqdn  string
       The fully qualified domain name of the PCE. Required.
-port  int
       The port of the PCE. (default 8443)
-org   int
       The org value for the PCE. (default 1)
-user  string
       API user or email address. Required.
-pwd   string
       API key if using API user or password if using email address. Required.
-app   string
       App name. Explorer results focus on that app as provider or consumer. Default is all apps.
-in    string
       CSV input file to be used to identify unmanaged workloads. (default "umwl_finder_default.cs")
-out   string
       File to write the unmanaged workloads to. (default "umwl_output.csv")
-time  int
       Timeout to lookup hostname in seconds. (default 5)
-x     Disable TLS checking.
-t     PrettyPrint the CSV to the terminal.
-v     Verbose output provides additional columns in output to explain the match reason.
-w     Include IP addresses already assigned to workloads to suggest or verify labels.
-p     Limit suggested workloads to the RFC 1918 address space.
-g     Output CSV for GAT import. -w and -v are ignored with -g.
-i     Output two CSVs (workloads and labels) to import via ILO-CLI. -w and -v are ignored with -i.
  ```

  ## Hostname Resolution
  When an unmanaged workload is identified, the tool will attempt to resolve its hostname. The default allows for 5 second to resolve the hostname. It can be changed via the `-timeout` flag. If the hostname cannot be found, the output will use the name from the input file and the IP address. For example, `ldap - 10.0.80.3`