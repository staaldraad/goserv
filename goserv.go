package main

import (
    "net/http"
    "fmt"
    "flag"
    "os"
    "encoding/pem"
    "crypto/x509"
    "crypto/x509/pkix"
    "crypto/rand"
    "crypto/rsa"
    "time"
)

var hostDir string

func genCert() {
    if _, err := os.Stat(fmt.Sprintf("%s/cert.pem",hostDir)); err == nil {
        if _, er := os.Stat(fmt.Sprintf("%s/key.pem",hostDir)); er == nil {
            fmt.Println("[*] Found certificate files in directory. Using these.")
            return
        }
    }
    fmt.Println("[*] No certificate files found in directory. Generating new...")
    s,_ := rand.Prime(rand.Reader,1024)
    ca := &x509.Certificate{
        SerialNumber: s,
        Subject: pkix.Name{
            Country: []string{"ZA"},
            Organization: []string{"SensePost"},
            CommonName: "*.sensepost.com",
        },
        NotBefore: time.Now(),
        NotAfter: time.Now().AddDate(10,0,0),
        SubjectKeyId: []byte{1,2,3,4,6},
        BasicConstraintsValid: true,
        IsCA: true,
        ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
        KeyUsage: x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign,
    }

    priv, _ := rsa.GenerateKey(rand.Reader, 1024)
    pub := &priv.PublicKey
    ca_b, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)
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
                Type : "RSA PRIVATE KEY",
                Bytes : x509.MarshalPKCS1PrivateKey(priv)}
    err = pem.Encode(kpemfile, pemkey)
    if err != nil {
       fmt.Println(err)
       os.Exit(1)
    }

    kpemfile.Close()
    pem.Encode(cpemfile, &pem.Block{Type: "CERTIFICATE", Bytes: ca_b})
    cpemfile.Close()

    fmt.Println("[*] Certificate files generated")
}

func logRequest(w http.ResponseWriter, req *http.Request){
    if _, err := os.Stat(fmt.Sprintf("%s/%s",hostDir,req.URL.Path)); err != nil {
        fmt.Printf("[%s][404] %s\n",req.RemoteAddr,req.URL)
        fmt.Fprintf(w,"Not Found")
    } else if req.URL.Path == "/key.pem" || req.URL.Path == "/cert.pem" {
        fmt.Printf("[%s][403] %s\n",req.RemoteAddr,req.URL)
        fmt.Fprintf(w,"Nop, sorry...")
    } else {
        fmt.Printf("[%s][200] %s\n",req.RemoteAddr,req.URL)
        if req.URL.Path == "/" {
            http.ServeFile(w,req,fmt.Sprintf("%s/",hostDir))
        } else if req.URL.Path[len(req.URL.Path)-1:] == "/" {
            http.ServeFile(w,req,fmt.Sprintf("%s/%s",hostDir,req.URL.Path[:len(req.URL.Path)-1]))
        } else {
            http.ServeFile(w,req,fmt.Sprintf("%s/%s",hostDir,req.URL.Path))
        }
    }
}

func main(){
    portPtr := flag.Int("p", 8080, "Port to use")
    dirPtr := flag.String("d", "./", "The directory to share")
    tlsPtr := flag.Bool("s", false, "Share using HTTPS (default=false)")
    flag.Parse()

    var err error

    hostDir = *dirPtr

    if _, err := os.Stat(hostDir); err != nil {
        fmt.Println("[-] The selected directory does not exist!")
        os.Exit(1)
    }

    if hostDir == "./" {
        fmt.Printf("[*] Serving current directory on %d\n",*portPtr)
    } else {
        fmt.Printf("[*] Serving [%s] on %d\n",hostDir,*portPtr)
    }

    http.HandleFunc("/",logRequest)

    if *tlsPtr == true {
        genCert()
        err = http.ListenAndServeTLS(fmt.Sprintf(":%d",*portPtr),"cert.pem","key.pem",nil)
    } else {
        err = http.ListenAndServe(fmt.Sprintf(":%d",*portPtr),nil)
    }

    if err != nil {
        fmt.Printf("[-] Couldn't start server: %s\n",err)
        os.Exit(1)
    }
}
