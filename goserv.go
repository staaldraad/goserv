package main

import (
    "net/http"
    "fmt"
    "flag"
    "os"
)

var hostDir string

func logRequest(w http.ResponseWriter, req *http.Request){
    if _, err := os.Stat(fmt.Sprintf("%s/%s",hostDir,req.URL.Path)); err != nil {
        fmt.Printf("[%s][404] %s\n",req.RemoteAddr,req.URL)
        fmt.Fprintf(w,"Not Found")
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
    flag.Parse()
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
    err := http.ListenAndServe(fmt.Sprintf(":%d",*portPtr),nil)

    if err != nil {
        fmt.Printf("[-] Couldn't start server: %s\n",err)
        os.Exit(1)
    }
}
