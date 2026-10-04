import requests
import builtwith
from bs4 import BeautifulSoup


class TechnologyCollector:

    def __init__(self, url):
        self.url = url

    def collect(self):

        report = {

            "url": self.url,

            "technologies": {},

            "server": None,

            "powered_by": None,

            "generator": None,

            "framework": None,

            "language": None,

            "cdn": None
        }

        try:

            response = requests.get(
                self.url,
                timeout=10
            )

            headers = response.headers

            report["server"] = headers.get("Server")

            report["powered_by"] = headers.get("X-Powered-By")

            soup = BeautifulSoup(
                response.text,
                "html.parser"
            )

            generator = soup.find(
                "meta",
                attrs={"name": "generator"}
            )

            if generator:
                report["generator"] = generator.get("content")

            report["technologies"] = builtwith.parse(self.url)

            # Simple framework detection
            technologies = str(report["technologies"]).lower()

            frameworks = [
                "react",
                "next.js",
                "vue",
                "angular",
                "django",
                "flask",
                "laravel",
                "wordpress",
                "express"
            ]

            for fw in frameworks:
                if fw in technologies:
                    report["framework"] = fw
                    break

            # Simple language detection
            languages = [
                "php",
                "python",
                "java",
                "node.js",
                "asp.net"
            ]

            for lang in languages:
                if lang in technologies:
                    report["language"] = lang
                    break

            if "cloudflare" in technologies:
                report["cdn"] = "Cloudflare"

        except Exception as e:

            report["error"] = str(e)

        return report


if __name__ == "__main__":

    from pprint import pprint

    collector = TechnologyCollector(
        "https://example.com"
    )

    pprint(collector.collect())