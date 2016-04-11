package main

import "github.com/eacha/ct-downloader/transparency"

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