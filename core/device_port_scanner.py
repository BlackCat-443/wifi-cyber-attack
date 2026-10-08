"""
Device Port Scanner
Scan port terbuka pada device tertentu di jaringan
"""

import threading
import socket
import time
from datetime import datetime

# Common ports yang sering di-scan
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

# Port ranges untuk scan cepat
QUICK_SCAN_PORTS = [22, 80, 443, 8080, 3389, 5900]


class DevicePortScanner:
    """
    Scanner port untuk device tertentu di jaringan.
    
    Fitur:
    - Scan port umum (22, 80, 443, dll)
    - Scan port range custom
    - Identifikasi service dari port number
    - Threading untuk scan cepat
    """
    
    def __init__(self):
        self.scan_results = {}  # {ip: {ports: [], scan_time: '', status: ''}}
        self._lock = threading.Lock()
        self.timeout = 1.0  # Timeout untuk koneksi socket (detik)
        self.max_threads = 50  # Maksimum thread concurrent
    
    def scan_common_ports(self, ip, ports=None):
        """
        Scan port umum pada device tertentu.
        
        Args:
            ip: IP address device target
            ports: List port yang mau di-scan (default: COMMON_PORTS.keys())
        
        Returns:
            Dict dengan hasil scan: {ip, ports: [{port, service, status}], scan_time, duration}
        """
        if ports is None:
            ports = list(COMMON_PORTS.keys())
        
        return self._scan_ports_threaded(ip, ports)
    
    def scan_quick(self, ip):
        """Scan cepat - hanya port penting"""
        return self._scan_ports_threaded(ip, QUICK_SCAN_PORTS)
    
    def scan_port_range(self, ip, start_port, end_port):
        """
        Scan range port tertentu.
        
        Args:
            ip: IP address device target
            start_port: Port awal
            end_port: Port akhir
        
        Returns:
            Dict dengan hasil scan
        """
        ports = list(range(start_port, end_port + 1))
        return self._scan_ports_threaded(ip, ports)
    
    def _scan_ports_threaded(self, ip, ports):
        """
        Scan port menggunakan threading untuk kecepatan.
        """
        start_time = time.time()
        open_ports = []
        closed_ports = []
        
        # Gunakan thread pool untuk scan concurrent
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        def check_port(port):
            """Check single port"""
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    service = COMMON_PORTS.get(port, "Unknown")
                    return {'port': port, 'service': service, 'status': 'open'}
                return None
            except Exception:
                return None
        
        # Scan dengan thread pool
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_port = {executor.submit(check_port, port): port for port in ports}
            
            for future in as_completed(future_to_port):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        # Sort by port number
        open_ports.sort(key=lambda x: x['port'])
        
        duration = round(time.time() - start_time, 2)
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        result = {
            'ip': ip,
            'ports': open_ports,
            'scan_time': scan_time,
            'duration': duration,
            'total_scanned': len(ports),
            'open_count': len(open_ports)
        }
        
        # Simpan hasil
        with self._lock:
            self.scan_results[ip] = result
        
        return result
    
    def get_scan_result(self, ip):
        """Ambil hasil scan terakhir untuk IP tertentu"""
        with self._lock:
            return self.scan_results.get(ip)
    
    def get_service_name(self, port):
        """Get nama service dari port number"""
        return COMMON_PORTS.get(port, "Unknown")


# Singleton instance
device_port_scanner = DevicePortScanner()