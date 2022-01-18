package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"net"
	"time"
)


func LoadRootCertificate(pubFileName, privFileName string) (*x509.Certificate, *rsa.PrivateKey, error) {
	cf, err := ioutil.ReadFile(pubFileName)
    if err != nil {
        return nil, nil, err
    }
	kf, err := ioutil.ReadFile(privFileName)
    if err != nil {
        return nil, nil, err
    }

    cpb, _ := pem.Decode(cf)
	kpb, _ := pem.Decode(kf)
    crt, err := x509.ParseCertificate(cpb.Bytes)

    if err != nil {
        return nil, nil, err
    }
	key, err := x509.ParsePKCS8PrivateKey(kpb.Bytes)
    if err != nil {
		return nil, nil, err
	}

	return crt, key.(*rsa.PrivateKey), nil
}

func GenerateCert(commonName string, rootCertificate *x509.Certificate, key *rsa.PrivateKey) (*tls.Certificate, error) {
	dummyKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() / 100000),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"onethinglab"},
		},
		NotBefore:          time.Now().Add(-time.Hour * 48),
		NotAfter:           time.Now().Add(time.Hour * 24 * 365),
		SignatureAlgorithm: x509.SHA256WithRSA,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	ip := net.ParseIP(commonName)
	if ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{commonName}
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, rootCertificate, dummyKey.Public(), key)
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  dummyKey,
	}

	return cert, nil
}