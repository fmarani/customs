package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
)

func hostAndPortIfNot80(host string, port int) string {
	if port != 80 {
		return fmt.Sprintf("%s:%d", host, port)
	} else {
		return host
	}
}

func BasicAuthPassThroughHandler(username string, password string, innerHandler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := strings.SplitN(r.Header.Get("Authorization"), " ", 2)

		if len(auth) != 2 || auth[0] != "Basic" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Customs"`)
			http.Error(w, "authorization failed", http.StatusUnauthorized)
			log.Printf("Received unauthenticated request")
			return
		}

		payload, _ := base64.StdEncoding.DecodeString(auth[1])
		pair := strings.SplitN(string(payload), ":", 2)

		if len(pair) != 2 || !AuthValidate(username, password, pair[0], pair[1]) {
			http.Error(w, "authorization failed", http.StatusUnauthorized)
			return
		}

		r.Header.Del("Authorization")
		innerHandler.ServeHTTP(w, r)
	}
}

func AuthValidate(refUsername, refPassword, username, password string) bool {
	if username == refUsername {
		if strings.HasPrefix(refPassword, "$2") && (bcrypt.CompareHashAndPassword([]byte(refPassword), []byte(password)) == nil) {
			return true
		}
		if password == refPassword {
			return true
		}
	}
	return false
}

func ProxyDirector(scheme string, host string, port int) func(*http.Request) {
	return func(r *http.Request) {
		r.URL.Scheme = scheme
		r.URL.Host = hostAndPortIfNot80(host, port)

		log.Print("Proxy-ed URL: " + r.URL.Path)
	}
}

func main() {
	var dhost = flag.String("destination-host", "127.0.0.1", "Host to reverse proxy to")
	var dport = flag.Int("destination-port", 80, "Port to reverse proxy to")
	var sportHttp = flag.Int("source-http", 8010, "Port for incoming connections on HTTP, 0 to disable")
	var sportHttps = flag.Int("source-https", 0, "Port for incoming connections on HTTPS, 0 to disable")
	var httpsPrivKey = flag.String("https-priv-key", "", "Private key file path")
	var httpsCert = flag.String("https-cert", "", "Certificate file path")
	var username = flag.String("username", "customs", "User to get through")
	var password = flag.String("password", "", "Password in clear-text or bcrypt format")
	var generateBcrypt = flag.Bool("generate-pw", false, "Generate bcrypt password to use later")
	flag.Parse()

	if *generateBcrypt {
		fmt.Println("Enter password to encrypt")
		reader := bufio.NewReader(os.Stdin)
		line, _ := reader.ReadString('\n')
		line = strings.TrimRight(line, "\n")
		fmt.Printf("Entered password is: %s\n", line)
		hash, _ := bcrypt.GenerateFromPassword([]byte(line), 10)
		fmt.Printf("The resulting hash is: %s\n", string(hash))
		return
	}

	if len(*password) == 0 {
		fmt.Println("Please define a password")
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "http", Host: hostAndPortIfNot80(*dhost, *dport)})
	proxy.Director = ProxyDirector("http", *dhost, *dport)
	http.Handle("/", BasicAuthPassThroughHandler(*username, *password, proxy))

	wg := &sync.WaitGroup{}
	if *sportHttp > 0 {
		listenAddrHttp := fmt.Sprintf(":%d", *sportHttp)
		log.Printf("Listening for HTTP traffic on %s", listenAddrHttp)
		wg.Add(1)
		go func() {
			error := http.ListenAndServe(listenAddrHttp, nil)
			if error != nil {
				log.Fatal(error)
			}
			wg.Done()
		}()
	}
	if *sportHttps > 0 {
		listenAddrHttps := fmt.Sprintf(":%d", *sportHttps)
		log.Printf("Listening for HTTPS traffic on %s", listenAddrHttps)
		wg.Add(1)
		go func() {
			error := http.ListenAndServeTLS(listenAddrHttps, *httpsCert, *httpsPrivKey, nil)
			if error != nil {
				log.Fatal(error)
			}
			wg.Done()
		}()
	}
	wg.Wait()
}
