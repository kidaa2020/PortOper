# PortOper
una herramienta de red profesional desarrollada en Python que combina funcionalidades de escaneo de puertos, traceroute y detección de sistema operativo. Está diseñada para analizar hosts y rangos de IP
## Características

- **Escaneo de Puertos:**  
  Realiza escaneos TCP mediante envío de paquetes SYN para identificar puertos abiertos en el host objetivo.
  
- **Traceroute:**  
  Rastrea la ruta que toman los paquetes hasta alcanzar el destino. En Windows se recomienda utilizar la variante basada en UDP para evitar restricciones con los raw sockets.

- **Detección de Sistema Operativo:**  
  Estima el sistema operativo del host analizando el valor del TTL en las respuestas ICMP, utilizando un mapeo heurístico (por ejemplo, TTL=64 para Linux/Unix, TTL=128 para Windows).

- **Multihilo:**  
  Utiliza `ThreadPoolExecutor` para realizar el escaneo de puertos de forma concurrente, acelerando el proceso.

- **Soporte para Rangos de IP:**  
  Permite escanear tanto una única IP como un rango de direcciones (por ejemplo, `192.168.1.0/24`).

## Requisitos

- Python 3.x  
- [Scapy](https://scapy.net/) (versión ≥ 2.5.0) (instalable mediante el archivo requirements.txt)

> **Nota:** Para enviar paquetes RAW es necesario ejecutar el script con permisos de administrador (por ejemplo, utilizando `sudo` en Linux o ejecutándolo como administrador en Windows).  
> En Windows, se recomienda tener instalado [Npcap](https://nmap.org/npcap/) para asegurar la compatibilidad con raw sockets.

## Instalación

1. **Clona el repositorio:**
IMPORTANTE A LA HORA DE EJECUTAR EL SCRIPT EN MOO ADMINISTRADOR
   ```bash
   git clone https://github.com/kidaa2020/PortOper.git
   cd PortOper
   pip install -r requirements.txt
   PortOper -h
   
