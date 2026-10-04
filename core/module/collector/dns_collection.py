import dns.resolver
import socket


class DNSCollector:

    def __init__(self, domain):
        self.domain = domain

    def _resolve_record(self, record_type):
        """
        Returns a list of DNS records or an empty list.
        """

        try:
            answers = dns.resolver.resolve(self.domain, record_type)

            records = []

            for answer in answers:
                records.append(str(answer))

            return records

        except Exception:
            return []

    def collect(self):

        report = {

            "domain": self.domain,

            "resolved_ipv4": [],

            "resolved_ipv6": [],

            "dns_records": {

                "A": [],

                "AAAA": [],

                "MX": [],

                "NS": [],

                "CNAME": [],

                "TXT": [],

                "SOA": [],

                "CAA": [],

                "PTR": []

            }

        }

        # -----------------------------
        # IPv4
        # -----------------------------
        try:

            report["resolved_ipv4"].append(
                socket.gethostbyname(self.domain)
            )

        except Exception:
            pass

        # -----------------------------
        # IPv6
        # -----------------------------
        try:

            infos = socket.getaddrinfo(
                self.domain,
                None,
                socket.AF_INET6
            )

            ipv6 = []

            for info in infos:

                addr = info[4][0]

                if addr not in ipv6:
                    ipv6.append(addr)

            report["resolved_ipv6"] = ipv6

        except Exception:
            pass

        # -----------------------------
        # DNS Records
        # -----------------------------
        record_types = [

            "A",
            "AAAA",
            "MX",
            "NS",
            "CNAME",
            "TXT",
            "SOA",
            "CAA",
            "PTR"

        ]

        for record in record_types:

            report["dns_records"][record] = self._resolve_record(record)

        return report


# if __name__ == "__main__":

#     from pprint import pprint

#     collector = DNSCollector("example.com")

#     pprint(collector.collect())