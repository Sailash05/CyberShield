import requests
from urllib.parse import urlparse


class HTTPInfoCollector:

    def __init__(self, url):
        self.url = url

    def collect(self):
        try:
            response = requests.get(
                self.url,
                timeout=10,
                allow_redirects=True
            )

            redirect_history = []

            for r in response.history:
                redirect_history.append({
                    "status_code": r.status_code,
                    "url": r.url
                })

            cookies = []

            for cookie in response.cookies:
                cookies.append({
                    "name": cookie.name,
                    "value": cookie.value,
                    "domain": cookie.domain,
                    "path": cookie.path,
                    "secure": cookie.secure,
                    "expires": cookie.expires
                })

            return {

                "url": response.url,

                "scheme": urlparse(response.url).scheme,

                "hostname": urlparse(response.url).hostname,

                "status_code": response.status_code,

                "reason": response.reason,

                "http_version": response.raw.version,

                "response_time_ms": round(
                    response.elapsed.total_seconds() * 1000,
                    2
                ),

                "redirected": len(response.history) > 0,

                "redirect_count": len(response.history),

                "redirect_history": redirect_history,

                "cookies": cookies
            }

        except Exception as e:
            return {
                "error": str(e)
            }


if __name__ == "__main__":

    from pprint import pprint

    collector = HTTPInfoCollector("https://www.angelcab.in")

    pprint(collector.collect())