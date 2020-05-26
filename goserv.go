package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

var hostDir string
var hostHddrs bool

func genCert() {
	if _, err := os.Stat(fmt.Sprintf("%s/cert.pem", hostDir)); err == nil {
		if _, er := os.Stat(fmt.Sprintf("%s/key.pem", hostDir)); er == nil {
			fmt.Println("[*] Found certificate files in directory. Using these.")
			return
		}
	}
	fmt.Println("[*] No certificate files found in directory. Generating new...")
	s, _ := rand.Prime(rand.Reader, 2048)
	ca := &x509.Certificate{
		SerialNumber: s,
		Subject: pkix.Name{
			Country:      []string{"UK"},
			Organization: []string{"Org"},
			CommonName:   "*.changeme.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		SubjectKeyId:          []byte{1, 2, 3, 4, 6},
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &priv.PublicKey
	cab, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)
	if err != nil {
		fmt.Println("create ca failed", err)
	}

	kpemfile, err := os.Create("key.pem")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	cpemfile, err := os.Create("cert.pem")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var pemkey = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv)}
	err = pem.Encode(kpemfile, pemkey)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	kpemfile.Close()
	pem.Encode(cpemfile, &pem.Block{Type: "CERTIFICATE", Bytes: cab})
	cpemfile.Close()

	fmt.Println("[*] Certificate files generated")
}

func redirRequest(w http.ResponseWriter, req *http.Request) {
	dst := req.URL.Query().Get("r")
	fmt.Printf("[%s][Accepted -  %s][From: %s][Redirect: %s]\n", time.Now(), req.URL, req.RemoteAddr, dst)
	http.Redirect(w, req, dst, 302)
}

func redir2Request(w http.ResponseWriter, req *http.Request) {
	dst := req.URL.Query().Get("r")
	fmt.Printf("[%s][Accepted -  %s][From: %s][Redirect: %s]\n", time.Now(), req.URL, req.RemoteAddr, dst)
	//http.Redirect(w,req,dst,302)
	w.Header().Add("Location", "`curl `")
	w.WriteHeader(302)

	fmt.Fprintf(w, "ok")
	return

}

func logRequest(w http.ResponseWriter, req *http.Request) {
	t := time.Now().Format(time.UnixDate)
	fmt.Printf("[%s][Accepted -  %s][From: %s]\n", t, req.URL, req.RemoteAddr)

	if hostHddrs == true {
		fmt.Println("---Headers---")
		for k, v := range req.Header {
			fmt.Printf("%s : %s\n", k, v)
		}
		fmt.Println("----------")
	}
	if req.Method == "POST" {
		req.ParseForm()

		if len(req.PostForm) > 0 {
			fmt.Println("-----Form POST-----")
			for k, v := range req.PostForm {
				fmt.Printf("%s = %s\n", k, v)
			}
		} else {
			buf := make([]byte, req.ContentLength)
			_, err := req.Body.Read(buf)
			if err != nil && err != io.EOF {
				fmt.Println(buf, err)
			} else {
				fmt.Println("-----POST-----")
				fmt.Printf("\n%s\n", buf)
			}
		}
		fmt.Fprintf(w, "")
		return
	}
	if _, err := os.Stat(fmt.Sprintf("%s/%s", hostDir, req.URL)); err != nil {
		fmt.Printf("[%s][404] %s\n", req.RemoteAddr, req.URL)
		w.WriteHeader(200)
		fmt.Fprintf(w, "")
	} else if req.URL.Path == "/key.pem" || req.URL.Path == "/cert.pem" {
		fmt.Printf("[%s][403] %s\n", req.RemoteAddr, req.URL)
		w.WriteHeader(403)
		fmt.Fprintf(w, "Nop, sorry...")
	} else {
		fmt.Printf("[%s][200] %s\n", req.RemoteAddr, req.URL)
		if req.URL.Path == "/" {
			http.ServeFile(w, req, fmt.Sprintf("%s/", hostDir))
		} else if req.URL.Path[len(req.URL.Path)-1:] == "/" {
			//http.ServeFile(w,req,fmt.Sprintf("%s/%s",hostDir,req.URL[:len(req.URL)-1]))
			http.ServeFile(w, req, fmt.Sprintf("%s/%s", hostDir, req.URL))
		} else {
			http.ServeFile(w, req, fmt.Sprintf("%s/%s", hostDir, req.URL))
		}
	}
}

func uploadRequest(w http.ResponseWriter, req *http.Request) {
	t := time.Now().Format(time.UnixDate)
	fmt.Printf("[%s][Accepted -  %s][From: %s]\n", t, req.URL, req.RemoteAddr)

	if req.Method == "GET" {
		w.WriteHeader(200)
		fmt.Fprintf(w, "ok")
		return
	} else {
		file, _, err := req.FormFile("data")
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(500)
			fmt.Fprintf(w, "ok")
			return
		}
		defer file.Close()

		// copy example
		f, err := os.OpenFile(fmt.Sprintf("./upload_%d", time.Now().Unix()), os.O_WRONLY|os.O_CREATE, 0666)
		defer f.Close()
		io.Copy(f, file)
	}
	w.WriteHeader(200)
	fmt.Fprintf(w, "ok")
}

func main() {
	portPtr := flag.Int("p", 8080, "Port to use")
	dirPtr := flag.String("d", "./", "The directory to share")
	tlsPtr := flag.Bool("s", false, "Share using HTTPS (default=false)")
	hdrsPtr := flag.Bool("headers", false, "Print incomming headers")
	mTLSPtr := flag.String("m", "", "client certificate to use for mtls")
	flag.Parse()

	var err error

	hostDir = *dirPtr
	hostHddrs = *hdrsPtr
	if _, err := os.Stat(hostDir); err != nil {
		fmt.Println("[-] The selected directory does not exist!")
		os.Exit(1)
	}

	if hostDir == "./" {
		fmt.Printf("[*] Serving current directory on %d\n", *portPtr)
	} else {
		fmt.Printf("[*] Serving [%s] on %d\n", hostDir, *portPtr)
	}

	http.HandleFunc("/", logRequest)
	http.HandleFunc("/redir/", redirRequest)
	http.HandleFunc("/redir2/", redir2Request)
	http.HandleFunc("/upload/", uploadRequest)

	if *tlsPtr == true {
		genCert()

		tlsConfig := &tls.Config{InsecureSkipVerify: true}
		if *mTLSPtr != "" {
			caCert, err := ioutil.ReadFile(*mTLSPtr)
			if err != nil {
				log.Fatal(err)
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			tlsConfig.ClientCAs = caCertPool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}

		server := &http.Server{
			Addr:      fmt.Sprintf(":%d", *portPtr),
			TLSConfig: tlsConfig,
		}

		err = server.ListenAndServeTLS("cert.pem", "key.pem")
	} else {
		err = http.ListenAndServe(fmt.Sprintf(":%d", *portPtr), nil)
	}

	if err != nil {
		fmt.Printf("[-] Couldn't start server: %s\n", err)
		os.Exit(1)
	}
}
