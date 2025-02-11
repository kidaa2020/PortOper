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
    print(f"{COLORS['YELLOW']}Port Scanner Professional v3.0{COLORS['END']}\n")

def os_ttl_guess(ttl: int) -> str:
    """Intenta adivinar el SO basado en el TTL."""
    return OS_TTL.get(ttl, "Desconocido")

def run_traceroute(target: str) -> None:
    """Ejecuta traceroute usando Scapy."""
    print(f"\n{COLORS['BLUE']}[*] Iniciando traceroute a {target}...{COLORS['END']}")
    ans, _ = traceroute(target, maxttl=30, verbose=0)
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
            if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
                result["status"] = "open"
                result["service"] = socket.getservbyport(port, "tcp")
                sr(IP(dst=ip)/TCP(dport=port, flags="R"), timeout=1, verbose=0)  # Cierra conexión
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    return result

def parse_arguments() -> argparse.Namespace:
    """Configura los argumentos de línea de comandos."""
    parser = argparse.ArgumentParser(
        description="Port Scanner Pro - Escaneo de puertos, traceroute y detección de SO",
        epilog="Ejemplo: python port_scanner_pro.py -t 192.168.1.1 -p 80 -tr -s"
    )
    parser.add_argument("-t", "--target", required=True, help="IP o rango (ej: 192.168.1.1 o 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", default="1-1024", help="Puertos a escanear (ej: 80,443 o 1-1000)")
    parser.add_argument("-o", "--output", help="Archivo de salida JSON")
    parser.add_argument("-T", "--threads", type=int, default=100, help="Número de hilos")
    parser.add_argument("-tr", "--traceroute", action="store_true", help="Ejecutar traceroute")
    parser.add_argument("-s", "--os-detect", action="store_true", help="Detectar sistema operativo")
    return parser.parse_args()

def main() -> None:
    print_banner()
    args = parse_arguments()

    # Ejecutar traceroute si se especificó
    if args.traceroute:
        run_traceroute(args.target.split("/")[0])  # Usa solo la IP base

    # Detectar SO si se especificó
    if args.os_detect:
        detect_os(args.target.split("/")[0])

    # Escaneo de puertos (similar a la versión anterior)
    # ... (incluir aquí el resto de funciones como scan_network, parse_ports, etc.)

if __name__ == "__main__":
    conf.verb = 0  # Desactiva logs de Scapy
    main()