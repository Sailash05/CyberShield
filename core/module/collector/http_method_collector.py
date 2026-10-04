import requests


class HTTPMethodsCollector:

    COMMON_METHODS = [
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
        "HEAD",
        "OPTIONS",
        "TRACE",
        "CONNECT"
    ]

    def __init__(self, url):
        self.url = url

    def collect(self):

        report = {
            "url": self.url,
            "allow_header": [],
            "supported_methods": [],
            "tested_methods": [],
            "errors": []
        }

        # OPTIONS request
        try:
            response = requests.options(
                self.url,
                timeout=10,
                allow_redirects=True
            )

            allow = response.headers.get("Allow")

            if allow:
                report["allow_header"] = [
                    method.strip()
                    for method in allow.split(",")
                ]

        except Exception as e:
            report["errors"].append(str(e))

        # Test each method
        for method in self.COMMON_METHODS:

            try:

                response = requests.request(
                    method=method,
                    url=self.url,
                    timeout=5,
                    allow_redirects=False
                )

                report["tested_methods"].append({
                    "method": method,
                    "status_code": response.status_code
                })

                # Usually anything except 405 means the server handled it
                if response.status_code != 405:
                    report["supported_methods"].append(method)

            except Exception:
                pass

        return report


# if __name__ == "__main__":

#     from pprint import pprint

#     collector = HTTPMethodsCollector("https://example.com")

#     pprint(collector.collect())