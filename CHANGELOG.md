## Version History

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
