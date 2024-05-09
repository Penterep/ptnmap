[![penterepTools](https://www.penterep.com/external/penterepToolsLogo.png)](https://www.penterep.com/)


## PTNMAP

## Installation
```
pip install ptnmap
```

## Adding to PATH
If you're unable to invoke the script from your terminal, it's likely because it's not included in your PATH. You can resolve this issue by executing the following commands, depending on the shell you're using:

For Bash Users
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.bashrc
source ~/.bashrc
```

For ZSH Users
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.zshrc
source ~/.zshrc
```

## Usage examples
```
ptnmap -sn -t 192.168.0.0/24
ptnmap -sT -t 192.168.0.1 -p 1-1000
ptnmap -sT -t 192.168.0.1 -sV
```

## Options
```
Scan options:
   -sn  --scan-live            Do live device scan / portsweep / no service detection
   -sV  --scan-service         Do service scan / service banner grabber
   -O   --scan-os              Do OS scan / detect target's OS,  root access required
   -sT  --scan-port-connect    Do port scan (TCP Connect)
   -sS  --scan-port-syn        Do port scan (TCP Syn / Stealth), root access required

Options:
   -t  --target   <target>  Set target
   -p  --port     <port>    Set port(s)
   -v  --version            Show script version and exit
   -h  --help               Show this help message and exit
   -j  --json               Output in JSON format
```

## Dependencies
```
ptlibs
defusedxml
```

## License

Copyright (c) 2024 Penterep Security s.r.o.

ptnmap is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

ptnmap is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with ptnmap. If not, see https://www.gnu.org/licenses/.

## Warning

You are only allowed to run the tool against the websites which
you have been given permission to pentest. We do not accept any
responsibility for any damage/harm that this application causes to your
computer, or your network. Penterep is not responsible for any illegal
or malicious use of this code. Be Ethical!