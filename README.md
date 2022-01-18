# HTTP Monitor

HTTP Monitor is POC to monitor HTTP/HTTPS (man-in-the-middle) traffic and export to [HAR](https://en.wikipedia.org/wiki/HAR_(file_format)) format.
Root cetificate must be generated and added to local CA and public/private keys file path must be passed to `LoadRootCertificate` function.

## Usage
After the proxy server is started on port 8080, it can be used as follows: `curl -v -x http://localhost:8080 https://www.google.com` and HAR logs can be accessed at http://localhost:8082.
