CUSTOMS
===

Very simple HTTP(S) Reverse Proxy with Basic Authentication, ideal to put in front of HTTP interfaces without any special security in place, like Database Web interfaces or Development servers. It is written in Go and very easy to deploy as it is only one binary file.

Basic Authentication cannot be disabled. You always need to define a password.


Right now, it doesn't:

- Transform any HTTP headers (e.g. Host header)
- Set up X-Forwarded headers
- Let HTTP Auth header go through
- Produce any CLF type logs
- Do HTTPS Client authentication
- IP Whitelisting/Blacklisting

Contributions on these, or others, are Welcome!

QUICKSTART
---

- git clone this repo
- run `./compile.sh`
- run `bin/customs`

OPTIONS
---

```
Usage of bin/customs:
  -destination-host="127.0.0.1": Host to reverse proxy to
  -destination-port=80: Port to reverse proxy to
  -generate-pw=false: Generate bcrypt password to use later
  -https-cert="": Certificate file path
  -https-priv-key="": Private key file path
  -password="": Password in clear-text or bcrypt format
  -source-http=8010: Port for incoming connections on HTTP, 0 to disable
  -source-https=0: Port for incoming connections on HTTPS, 0 to disable
  -username="customs": User to get through
```

EXAMPLE USAGE
===

Generate hashed passwords
---

bin/customs -generate-pw


HTTP
---

bin/customs -destination-port=8080 -username="alpha" -password='bravo' 


HTTP
---

bin/customs -destination-port=8080 -username="alpha" -password='$2a$10$pQl5ow/s6wTMpy2bqTvsJuE51cVMhAZcBkucrrGMX016iVzwINd9C' 


HTTPS
---

openssl genrsa -out private_key 2048  # generate private key for first run
openssl req -new -x509 -key private_key -out public_key -days 365  # and public certificate

bin/customs -destination-port=8080 -username="alpha" -password='$2a$10$pQl5ow/s6wTMpy2bqTvsJuE51cVMhAZcBkucrrGMX016iVzwINd9C' -source-https=8011 -https-cert=public_key -https-priv-key=private_key
