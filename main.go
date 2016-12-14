package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/fullsailor/pkcs7"
)

var CertificateBundle []*x509.Certificate
var Certificate *x509.Certificate
var PrivateKey *rsa.PrivateKey
var SignInfoConfig pkcs7.SignerInfoConfig
var RootCA *x509.Certificate
var RootFingerprint [20]byte

var requests, succ int64 = 0, 0

const MAX_COUNT = 10000000000

func handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(fmt.Sprintf("%v\t%v", requests, succ)))
	w.Write([]byte("\r\n"))
}

func handleSign(w http.ResponseWriter, r *http.Request) {
	requests = requests%MAX_COUNT + 1

	if r.Method != "POST" || r.Body == nil {
		http.Error(w, "Bad request", 400)
		return
	}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	signedData, err := pkcs7.NewSignedData(body)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	signedData.AddSigner(Certificate, PrivateKey, SignInfoConfig)
	for _, cert := range CertificateBundle {
		signedData.AddCertificate(cert)
	}
	data, err := signedData.Finish()
	if err != nil {
		http.Error(w, fmt.Sprintf("Not AppleRootCA: %s", err.Error()), 500)
		return
	}
	w.Write(data)
	succ = succ%MAX_COUNT + 1
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
	requests = requests%MAX_COUNT + 1

	if r.Method != "POST" || r.Body == nil {
		http.Error(w, "Bad request", 400)
		return
	}

	verbose := false
	verify := true
	qs := r.URL.Query()
	if _, ok := qs["verbose"]; ok {
		verbose = true
	}
	if value, ok := qs["verify"]; ok {
		v := strings.ToLower(value[0])
		verify = (v == "1" || v == "true" || v == "yes")
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	p7, err := pkcs7.Parse(body)
	if err != nil {
		body, err = workaround_pkcs7(body)
		if err != nil {
			log.Fatal(err)
			return
		}
		p7, err = pkcs7.Parse(body)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
	}
	if verify {
		err = p7.Verify()
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		err = verifyCertificateChain(p7.Certificates)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
	}

	if verbose {
		w.Write(p7.Content)
	}
	succ = succ%MAX_COUNT + 1
}

func workaround_pkcs7(body []byte) ([]byte, error) {
	cmd := exec.Command("openssl", "pkcs7", "-inform", "der", "-outform", "der")
	cmd.Stdin = bytes.NewReader(body)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil

}

func verifyCertificateChain(certs []*x509.Certificate) error {
	lenOfCerts := len(certs)
	if lenOfCerts <= 0 {
		return fmt.Errorf("No certificate?")
	}
	cert := certs[0]
	for _, parentCert := range certs[1:] {
		err := cert.CheckSignatureFrom(parentCert)
		if err != nil {
			break
		}
		cert = parentCert
	}

	if cert == nil {
		return fmt.Errorf("Nil certificate?")
	}

	fingerprint := sha1.Sum(cert.Raw)
	if bytes.Compare(RootFingerprint[:], fingerprint[:]) != 0 {
		err := cert.CheckSignatureFrom(RootCA)
		if err != nil {
			return err
		}
	}

	return nil
}

func prepareCertificateBundle(filename string) {
	log.Printf("Loading CertificateBundle: %s", filename)
	CertificateBundle = make([]*x509.Certificate, 0, 10)
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Bundle: %s", cert.Subject.CommonName)
		CertificateBundle = append(CertificateBundle, cert)
		data = rest
	}
}

func prepareCertificate(filename string) {
	log.Printf("Loading Certificate: %s", filename)
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		log.Fatal("Certificate error")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Certificate: %s", cert.Subject.CommonName)
	Certificate = cert
}

func preparePrivateKey(filename string) {
	log.Printf("Loading PrivateKey: %s", filename)
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		log.Fatal("PrivateKey error")
	}
	pkey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	PrivateKey = pkey
}

func prepareRootCA(filename string) {
	log.Printf("Loading RootCA: %s", filename)
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		log.Fatal("RootCA error")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("RootCA: %s", cert.Subject.CommonName)
	RootCA = cert
	RootFingerprint = sha1.Sum(cert.Raw)
}

func main() {
	if len(os.Args) < 6 {
		fmt.Printf(
			"Usage: %s <Listen> <Certificate> <PrivateKey> <CertificatesBundle> <RootCA>",
			os.Args[0],
		)
		fmt.Println()
		os.Exit(1)
	}
	prepareCertificate(os.Args[2])
	preparePrivateKey(os.Args[3])
	prepareCertificateBundle(os.Args[4])
	prepareRootCA(os.Args[5])

	http.HandleFunc("/status", handleStatus)
	http.HandleFunc("/sign", handleSign)
	http.HandleFunc("/verify", handleVerify)

	log.Println()
	log.Println("HTTP Serve on", os.Args[1])
	log.Println("GOMAXPROCS: ", runtime.GOMAXPROCS(0))
	http.ListenAndServe(os.Args[1], nil)
}
