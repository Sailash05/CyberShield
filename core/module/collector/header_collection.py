import requests


class HeaderCollector:

    def __init__(self, url):
        self.url = url

    def collect(self):

        try:

            response = requests.get(
                self.url,
                timeout=10,
                allow_redirects=True
            )

            headers = dict(response.headers)

            return {

                "url": response.url,

                "server_headers": {

                    "Server":
                        headers.get("Server"),

                    "X-Powered-By":
                        headers.get("X-Powered-By"),

                    "Via":
                        headers.get("Via"),

                    "Alt-Svc":
                        headers.get("Alt-Svc")
                },

                "content_headers": {

                    "Content-Type":
                        headers.get("Content-Type"),

                    "Content-Length":
                        headers.get("Content-Length"),

                    "Content-Encoding":
                        headers.get("Content-Encoding"),

                    "Content-Language":
                        headers.get("Content-Language"),

                    "Cache-Control":
                        headers.get("Cache-Control"),

                    "Expires":
                        headers.get("Expires"),

                    "ETag":
                        headers.get("ETag"),

                    "Last-Modified":
                        headers.get("Last-Modified")
                },

                "security_headers": {

                    "Strict-Transport-Security":
                        headers.get("Strict-Transport-Security"),

                    "Content-Security-Policy":
                        headers.get("Content-Security-Policy"),

                    "X-Frame-Options":
                        headers.get("X-Frame-Options"),

                    "X-Content-Type-Options":
                        headers.get("X-Content-Type-Options"),

                    "Referrer-Policy":
                        headers.get("Referrer-Policy"),

                    "Permissions-Policy":
                        headers.get("Permissions-Policy"),

                    "Cross-Origin-Embedder-Policy":
                        headers.get("Cross-Origin-Embedder-Policy"),

                    "Cross-Origin-Opener-Policy":
                        headers.get("Cross-Origin-Opener-Policy"),

                    "Cross-Origin-Resource-Policy":
                        headers.get("Cross-Origin-Resource-Policy"),

                    "Access-Control-Allow-Origin":
                        headers.get("Access-Control-Allow-Origin"),

                    "Access-Control-Allow-Credentials":
                        headers.get("Access-Control-Allow-Credentials")
                },

                "all_headers": headers

            }

        except Exception as e:

            return {
                "error": str(e)
            }

