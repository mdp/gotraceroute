# gotraceroute

_Demo codebase for a talk at Yahoo SF's Tech and Beer Talk_

[See the presentation here](https://slides.com/mdp/gotraceroute)

## Run and install

```
# Needs libpcap on linux
go get
go build gotraceroute.go
sudo ./gotraceroute -ttl 5 www.yahoo.com
```
