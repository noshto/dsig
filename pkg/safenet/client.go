package safenet

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

// NewClient creates new http.Client with TLS config with X.509 certificate
func (t *SafeNet) NewClient() (*http.Client, error) {
	if !t.isLoggedIn() {
		return nil,
			fmt.Errorf("NewClient is called before SafeNet being initialized")
	}

	cert, err := t.GetCertificate()
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{
					{Certificate: [][]byte{cert.Raw}},
				},
				InsecureSkipVerify: true,
			},
		},
		Timeout: time.Second * 60,
	}, nil
}
