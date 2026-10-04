import whois
from datetime import datetime, timezone

class WHOISCollector:

    def __init__(self, domain):
        self.domain = domain

    def _format_datetime(self, value):
        if isinstance(value, list):
            value = value[0]

        if isinstance(value, datetime):
            return value.isoformat()

        return value

    def collect(self):

        try:

            data = whois.whois(self.domain)

            report = {

                "domain": self.domain,

                "domain_name": data.domain_name,

                "registrar": data.registrar,

                "whois_server": data.whois_server,

                "referral_url": data.referral_url,

                "creation_date": self._format_datetime(
                    data.creation_date
                ),

                "updated_date": self._format_datetime(
                    data.updated_date
                ),

                "expiration_date": self._format_datetime(
                    data.expiration_date
                ),

                "name_servers": data.name_servers,

                "status": data.status,

                "emails": data.emails,

                "dnssec": data.dnssec,

                "registrant": {

                    "name": data.name,

                    "organization": data.org,

                    "country": data.country,

                    "state": data.state,

                    "city": data.city,

                    "zipcode": data.zipcode,

                    "address": data.address

                },

                "admin_contact": {

                    "name": data.name,

                    "email": data.emails

                }

            }

            if data.creation_date:
                creation = data.creation_date
                if isinstance(creation, list):
                    creation = creation[0]

                # Make creation timezone-aware if it isn't already
                if creation.tzinfo is None:
                    creation = creation.replace(tzinfo=timezone.utc)

                report["domain_age_days"] = (
                    datetime.now(timezone.utc) - creation
                ).days

            return report

        except Exception as e:

            return {
                "error": str(e)
            }


if __name__ == "__main__":

    from pprint import pprint

    collector = WHOISCollector("example.com")

    pprint(collector.collect())