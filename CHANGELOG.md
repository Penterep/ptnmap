## Version History

## Version 0.0.16

- Changed `-sV` scans with one target and one explicit port to return properties of the current node with no new nodes, including when combined with `-sT`, `-sS` or `-sU`. Known services return `serviceType`; unmapped services return `name` instead. Multiple-target, multiple-port and default-port scans still return nodes.
- Added 16 service name and type mappings in [`ptnmap/modules/service_mapping.json`](ptnmap/modules/service_mapping.json). Entries use the nmap service name as the key and define `name` and `serviceType`, for example `"http": {"name": "HTTP", "serviceType": "serviceTypeHttps"}`. Edit or add entries to extend the mapping without changing the parser.
- Changed service node names to the format `80 (HTTP)`, preserving mapped capitalization such as `1900 (UPnP)`.
- Unmapped services use the uppercase nmap name, for example `1234 (CUSTOM-SERVICE)`, and omit `serviceType` entirely. If nmap supplies no service name, service nodes use the port number as their name.
- Included the service mapping JSON in installation packages through `package_data`.

## Version 0.0.8

- Added device nodes as parents for services in port scan results against multiple targets.
- Preserved top-level service output for single-target port scans.

## Version 0.0.6

- Added `-PE`/`--ping-echo` and `-PS`/`--ping-syn` discovery options.
- Made `-sV`/`--scan-service` combinable with port scan options.

## Version 0.0.5

- Fixed XML parser to ignore closed ports in UDP scans (-sU).
- Removed incorrect root access requirement for UDP scans from help output.

## Version 0.0.4

- Added UDP support.
- Fixed `UnboundLocalError` in `xml_parser`.

## Version 0.0.3

- Fixed OS scan JSON error
- Added `--socket-address` `--socket-port` `--process-ident` arguments for ptmanager communication.

## Version 0.0.2

- Fixed error msg disrupting JSON output.

## Version 0.0.1

- Initial release.
