import socket
import time

class PortCollector:

    DEFAULT_PORTS = [
        20, 21, 22, 23, 25,
        53, 80, 110, 111, 135,
        139, 143, 389, 443, 445,
        465, 587, 993, 995,
        1433, 1521, 2049,
        3306, 3389, 5432,
        5900, 6379, 8080,
        8443, 9200, 27017,
        3000, 5173, 8000
    ]

    def __init__(self, host, ports=None, timeout=1):
        self.host = host
        self.ports = ports if ports else self.DEFAULT_PORTS
        self.timeout = timeout

    def _service_name(self, port):
        try:
            return socket.getservbyport(port)
        except OSError:
            return "Unknown"

    def _grab_banner(self, sock):
        try:
            sock.settimeout(1)
            data = sock.recv(1024)

            if data:
                return data.decode(errors="ignore").strip()

        except Exception:
            pass

        return None

    def collect(self):

        report = {
            "host": self.host,
            "open_ports": [],
            "closed_ports": [],
            "total_ports_scanned": len(self.ports)
        }

        for port in self.ports:

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            start = time.perf_counter()

            try:

                result = sock.connect_ex((self.host, port))

                latency = round(
                    (time.perf_counter() - start) * 1000,
                    2
                )

                if result == 0:

                    report["open_ports"].append({

                        "port": port,

                        "service": self._service_name(port),

                        "latency_ms": latency,

                        "banner": self._grab_banner(sock)

                    })

                else:

                    report["closed_ports"].append(port)

            except Exception:
                report["closed_ports"].append(port)

            finally:
                sock.close()

        return report


if __name__ == "__main__":

    from pprint import pprint

    collector = PortCollector("example.com")

    pprint(collector.collect())