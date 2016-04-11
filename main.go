package main

import "certificate-transparency/transparency"

func main() {
	for i:= range transparency.LogServers {
		url := transparency.LogServers[i]
		logServerConnection := transparency.New(url, 1000)
		if logServerConnection == nil{
			continue
		}

		logServerConnection.GetAllLogEntries()
	}
}