[![penterepTools](https://www.penterep.com/external/penterepToolsLogo.png)](https://www.penterep.com/)


# PTNMAP
> Nmap wrapper

## Installation
```
pip install ptnmap
```

## Add to PATH
If you cannot invoke the script in your terminal, its probably because its not in your PATH. Fix it by running commands below.

> Add to PATH for Bash
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.bashrc
source ~/.bashrc
```

> Add to PATH for ZSH
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
-sn  --scan-live            Do live device scan / portsweep / no service detection
-sV  --scan-service         Do service scan / service banner grabber
-O   --scan-os              Do OS scan / detect target's OS,  root access required
-sT  --scan-port-connect    Do port scan (TCP Connect)
-sS  --scan-port-syn        Do port scan (TCP Syn / Stealth), root access required
-t  --target   <target>     Set target
-p  --port     <port>       Set port(s)
-v  --version               Show script version and exit
-h  --help                  Show this help message and exit
-j  --json                  Output in JSON format
```


## Dependencies

```
ptlibs
```


## Version History
```
1.0.0
    - Initial release
```

## License

Copyright (c) 2023 Penterep Security s.r.o.

ptnmap is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

ptnmap is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with ptnmap.  If not, see <https://www.gnu.org/licenses/>.

## Warning

You are only allowed to run the tool against the websites which
you have been given permission to pentest. We do not accept any
responsibility for any damage/harm that this application causes to your
computer, or your network. Penterep is not responsible for any illegal
or malicious use of this code. Be Ethical!
