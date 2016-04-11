package transparency

import (
	"fmt"
	"errors"
	"encoding/json"

	"github.com/zmap/zgrab/ztools/x509"
	"github.com/google/certificate-transparency/go"
	"github.com/google/certificate-transparency/go/client"
)

var (
	TreeHeadError = errors.New("Error to get tree head")
	LogEntriesError = errors.New("Error ...")
	CertificateNotFoundError = errors.New("Error certificate not found")
)

type LogServerConnection struct {
	logClient	*client.LogClient
	treeSize	int64
	bucketSize	int64
	start 		int64
	end 		int64
}

func merkleTreeSize(logClient *client.LogClient) (uint64, error) {
	treeHead, err := logClient.GetSTH()

	if err != nil {
		return 0, TreeHeadError
	}

	return treeHead.TreeSize, nil
}

func leafCertificate(logEntry ct.LogEntry) (ct.ASN1Cert, error) {
	if logEntry.Leaf.LeafType != ct.TimestampedEntryLeafType {
		return nil, CertificateNotFoundError
	}

	if logEntry.Leaf.TimestampedEntry.EntryType != ct.X509LogEntryType {
		return nil, CertificateNotFoundError
	}

	return logEntry.Leaf.TimestampedEntry.X509Entry, nil
}

func ASN1CertToJson(certificate ct.ASN1Cert) ([]byte) {
	cert, err := x509.ParseCertificate(certificate)

	if err != nil {
		return nil
	}

	json_cert, err := json.Marshal(cert)

	if err != nil {
		return nil
	}

	return json_cert
}

func New(uri string, bucketSize int64) *LogServerConnection {
	var c LogServerConnection

	c.logClient = client.New(uri)

	treeSize, err := merkleTreeSize(c.logClient)
	if err != nil {
		return nil
	}
	c.treeSize = int64(treeSize)

	if bucketSize >= c.treeSize{
		c.bucketSize = c.treeSize / 2
	} else {
		c.bucketSize = bucketSize
	}

	c.start = 0
	c.end = c.bucketSize

	return &c
}

func (c *LogServerConnection) slideBucket() {
	if c.start == 0 {
		c.start = 1
	}

	c.start += c.bucketSize
	c.end += c.bucketSize
}

func (c *LogServerConnection) GetLogEntries() ([]ct.LogEntry, error) {
	if c.end >= c.treeSize {
		c.treeSize -= 1
		c.end = c.treeSize
	}

	entries, err := c.logClient.GetEntries(c.start, c.end)

	if err != nil {
		return nil, LogEntriesError
	}

	if len(entries) < int(c.bucketSize) && c.end != c.treeSize {
		c.end -= c.bucketSize
		c.bucketSize = int64(len(entries)) - 1
		c.end += c.bucketSize
	 }

	return entries, nil
}

func (c *LogServerConnection) GetAllLogEntries() {
	for {
		entries, err := c.GetLogEntries()

		if err != nil {
			continue
		}

		for i := range entries {
			certificate, err := leafCertificate(entries[i])

			if err != nil {
				continue
			}


			if jsonCert := ASN1CertToJson(certificate); jsonCert != nil {
				fmt.Println(string(jsonCert))
			}
		}

		if c.end >= c.treeSize {
			break
		}

		c.slideBucket()
	}
}