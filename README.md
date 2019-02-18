# Workload Identifier

Binaries for Mac, Linux, and Windows are in the `bin` folder of this repository.

## Description
CLI tool that analyzes traffic from explorer to do the following: 
1. Identify and label potential unmanaged workloads.
2. Verify or recommend labels for existing managed and unmanaged workloads.

## Usage
`workload-identifier -h`
```
Usage of workload-identifier:
-fqdn  string
       The fully qualified domain name of the PCE. Required.
-port  int
       The port of the PCE. (default 8443)
-user  string
       API user or email address. Required.
-pwd   string
       API key if using API user or password if using email address. Required.
-in    string
       CSV input file to be used to identify workloads. (default "workload-identifier-default.csv")
-time  int
       Timeout to lookup hostname in ms. 0 will skip hostname lookups. (default 1000)
-app   string
       App name to limit Explorer results to flows with that app as a provider or consumer. Default is all apps.
-excl  string
       Label to exclude as a consumer role
-snet  string
       Optional CSV input file to identify location based on IP address.
-x     Disable TLS checking.
-p     Exclude public IP addresses and limit suggested workloads to the RFC 1918 address space.
-w     Exclude IP addresses already assigned to workloads to suggest or verify labels.
-n     Include workloads (ports in use and hostnames) that do not match a service in the output.
-g     Output CSVs for GAT import to create UMWLs and label existing workloads.
-i     Output CSVs for ILO-CLI import to create UMWLs and label existing workloads.
```

## Input CSV File
The tool requires an input CSV with information on how to match IP addresses from observed traffic to unmanaged workloads. The repository includes a default CSV (`workload-identifier-default.csv`) that is suggested to be used as a starting point. Add to it as needed.
* **name** - name of the service being identified (e.g., domain controller, LDAP, etc.)
* **provider** - 1 if the workload to be identified will be on the provider side of traffic and 0 if it will be consumer. For example, a Domain Controllers will be the provider of observed traffic. McAfee will be the consumer on traffic over port 8081.
* **required_ports** - list of ports that _must_ be observed to be considered a match. Separate ports by a space. *_Ranges are not allowed_*.
* **optional_ports** - list of ports that some must be observed to be considered a match. Separate ports by a space. Ranges are allowed and should be written as 49152-65535 with no spaces. *_A match in a range only counts once_*. For example, if a range is given as 100-200 and traffic is observed on 101 and 102, it is counted as 1 optional match. This avoids situations like a server matching as a domain controller because several high end ports were identified.
* **num_optional_ports** - number of optional ports that must be matched.
* **num_flows** - number of flows that must be observed on required ports and optional ports. Flows observed in port ranges do not count toward this requirement.
* **processes** - list of optional provider processes (e.g., macmnsvc.exe) used to identify the workload.
* **num_processes_required** - number of optional proccesses to be identified to be considered a match.
* **role** - Illumio role label to be assigned.
* **app** - Illumio app label to be assigned.
* **env** - Illumio environment label be assigned.
* **loc** - Illumio location label to be assigned.

## Optional Input CSV for Location and Environment Identification based on Subnet
You can use the `-snet` parameter to specific a CSV file with the following columns:
* Network (CIDR notation)
* Location Label
* Environment Label
If used, Environment and Location labels are pulled from here based on IP address being in the subnet.

## Name Resolution
When an unmanaged workload is identified, the tool will attempt to resolve its hostname. The default allows for 1000 ms to resolve the hostname. It can be changed via the `-time` flag. If the hostname cannot be found, the output will use the name from the input file and the IP address. For example, `ldap - 10.0.80.3`