import argparse
import socket
import sys
import json
import time
from concurrent.futures import ThreadPoolExecutor
from ipaddress import ip_network, IPv4Address
from typing import List, Dict
from scapy.all import ICMP, IP, TCP, sr1, sr, traceroute, conf  # Requiere instalar scapy

# Configuración de colores
COLORS = {
    "RED": "\033[91m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "BLUE": "\033[94m",
    "END": "\033[0m"
}

# Mapeo de TTL a sistemas operativos (valores comunes)
OS_TTL = {
    64: "Linux/Unix",
    128: "Windows",
    255: "Router/Cisco",
    60: "AIX",
}

def print_banner() -> None:
    """Muestra un banner profesional."""
    banner = f"""
{COLORS['BLUE']}
  _____           _      ____                  
 |  __ \         | |    / __ \                 
 | |__) |__  _ __| |_  | |  | |_ __   ___ _ __ 
 |  ___/ _ \| '__| __| | |  | | '_ \ / _ \ '__|
 | |  | (_) | |  | |_  | |__| | |_) |  __/ |   
 |_|   \___/|_|   \__|  \____/| .__/ \___|_|   
                              | |              
                              |_| {COLORS['END']}"""
    print(banner)
    print(f"{COLORS['YELLOW']}Port Scanner Pro - System Identifier v2.0{COLORS['END']}\n")

def os_ttl_guess(ttl: int) -> str:
    """Intenta adivinar el SO basado en el TTL."""
    return OS_TTL.get(ttl, "Desconocido")

def run_traceroute(target: str) -> None:
    """Ejecuta traceroute usando Scapy con paquetes UDP (para evitar restricciones en Windows)."""
    print(f"\n{COLORS['BLUE']}[*] Iniciando traceroute a {target}...{COLORS['END']}")
    # Usamos UDP (puerto 33434) para evitar restricciones de TCP en raw sockets en Windows.
    ans, _ = traceroute(target, dport=33434, maxttl=30, verbose=0)
    for snd, rcv in ans:
        print(f"TTL: {snd.ttl} | IP: {rcv.src}")

def detect_os(target: str) -> None:
    """Detecta el SO basado en el TTL usando un ping ICMP."""
    print(f"\n{COLORS['BLUE']}[*] Detectando SO de {target}...{COLORS['END']}")
    packet = IP(dst=target)/ICMP()
    response = sr1(packet, timeout=2, verbose=0)
    if response:
        ttl = response.ttl
        os_guess = os_ttl_guess(ttl)
        print(f"IP: {target} | TTL: {ttl} | Posible SO: {os_guess}")
    else:
        print(f"{COLORS['RED']}[!] No se recibió respuesta.{COLORS['END']}")

def scan_port(ip: str, port: int, timeout: float = 1.0) -> Dict[str, str]:
    """Escanea un puerto TCP y devuelve resultados."""
    result = {"ip": ip, "port": port, "status": "closed", "service": "unknown"}
    try:
        pkt = IP(dst=ip)/TCP(dport=port, flags="S")
        response = sr1(pkt, timeout=timeout, verbose=0)
        if response and response.haslayer(TCP):
            # Si se recibe SYN-ACK (flag 0x12), el puerto está abierto.
            if response.getlayer(TCP).flags == 0x12:
                result["status"] = "open"
                try:
                    result["service"] = socket.getservbyport(port, "tcp")
                except Exception:
                    result["service"] = "unknown"
                # Enviar RST para cerrar la conexión sin completar el handshake.
                sr(IP(dst=ip)/TCP(dport=port, flags="R"), timeout=1, verbose=0)
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    return result

def parse_ports(ports_str: str) -> List[int]:
    """
    Convierte una cadena de puertos a una lista de enteros.
    Ejemplos:
      "80,443"  -> [80, 443]
      "1-1024"  -> [1, 2, ..., 1024]
    """
    ports = []
    if '-' in ports_str:
        parts = ports_str.split('-')
        start = int(parts[0])
        end = int(parts[1])
        ports = list(range(start, end + 1))
    elif ',' in ports_str:
        parts = ports_str.split(',')
        ports = [int(p.strip()) for p in parts]
    else:
        ports = [int(ports_str)]
    return ports

def scan_ports_multithread(target: str, ports: List[int], workers: int = 100) -> List[Dict[str, str]]:
    """Escanea múltiples puertos utilizando ThreadPoolExecutor."""
    results = []
    print(f"\n{COLORS['BLUE']}[*] Iniciando escaneo de puertos en {target}...{COLORS['END']}")
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_port = {executor.submit(scan_port, target, port): port for port in ports}
        for future in future_to_port:
            try:
                result = future.result()
                if result["status"] == "open":
                    print(f"🔵 Puerto {result['port']} abierto ({result['service']})")
                results.append(result)
            except Exception as e:
                port = future_to_port[future]
                print(f"Error en puerto {port}: {e}")
    return results

def parse_arguments() -> argparse.Namespace:
    """Configura los argumentos de línea de comandos."""
    parser = argparse.ArgumentParser(
        description="Port Scanner Pro - Escaneo de puertos, traceroute y detección de SO",
        epilog="Ejemplo: python SystemIdentifierV2.py -t 192.168.1.1 -p 1-1024 -tr -s"
    )
    parser.add_argument("-t", "--target", required=True, help="IP o rango (ej: 192.168.1.1 o 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", default="1-1024", help="Puertos a escanear (ej: 80,443 o 1-1024)")
    parser.add_argument("-o", "--output", help="Archivo de salida JSON")
    parser.add_argument("-T", "--threads", type=int, default=100, help="Número de hilos")
    parser.add_argument("-tr", "--traceroute", action="store_true", help="Ejecutar traceroute")
    parser.add_argument("-s", "--os-detect", action="store_true", help="Detectar sistema operativo")
    return parser.parse_args()

def main() -> None:
    print_banner()
    args = parse_arguments()
    target = args.target.split("/")[0]  # Si se pasa un rango, usar solo la IP base

    # Ejecutar traceroute si se especifica.
    if args.traceroute:
        run_traceroute(target)

    # Ejecutar detección de SO si se especifica.
    if args.os_detect:
        detect_os(target)

    # Escaneo de puertos.
    if args.ports:
        ports_list = parse_ports(args.ports)
        print(f"\n{COLORS['BLUE']}[*] Escaneando puertos en {target}: {ports_list[0]} - {ports_list[-1]}{COLORS['END']}")
        scan_results = scan_ports_multithread(target, ports_list, args.threads)
        # Si se especifica un archivo de salida, guardamos los resultados en formato JSON.
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(scan_results, f, indent=4)

if __name__ == "__main__":
    conf.verb = 0  # Desactiva logs verbosos de Scapy
    main()
