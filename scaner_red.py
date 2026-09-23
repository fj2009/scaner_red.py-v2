#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scaner_red.py — Auditoría de red automatizada para entornos controlados
y con autorización previa (laboratorio propio / pentest autorizado).

Pipeline implementado:
    Rango de Red -> Descubrimiento de Hosts (-sn)
                  -> Puertos y Servicios por host
                  -> Detección de SO (-O, si root)
                  -> Análisis de Vulnerabilidades (NSE: --script=vuln)

Requisitos:
    - Python 3 y el binario `nmap` instalado. Todo lo demás se prepara solo:
      la primera ejecución crea el venv ~/venv-nmap, instala `python-nmap`
      y relanza el script con ese intérprete automáticamente.
    - Ejecutar como root para escaneos SYN (-sS) y detección de SO (-O)
      (el script se auto-eleva con sudo si hace falta).

Uso básico:
    python3 scaner_red.py                    (asistente con barra de selección)
    python3 scaner_red.py 192.168.1.0/24     (directo; pedirá root vía sudo)
    python3 scaner_red.py 192.168.1.1-254 --mode sigiloso
    python3 scaner_red.py 10.0.0.5 --mode normal --no-vuln

Resultados:
    - reporte_red.json  (estructurado, organizado por host)
    - reporte_red.txt   (legible)
    - scaner_red.log    (progreso del escaneo)
"""

import argparse
import ipaddress
import json
import logging
import os
import re
import sys
import time
from datetime import datetime


# ----------------------------------------------------------------------------
# Configuración de logging global
# (console = INFO, archivo = DEBUG) para rastrear el progreso del escaneo.
# ----------------------------------------------------------------------------
def configurar_logging(log_dir: str) -> logging.Logger:
    logger = logging.getLogger("scaner_red")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False  # evitar duplicados si ya existe un handler

    formato_archivo = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    formato_consola = _ConsolaColoreada()

    # Handler de consola: nivel INFO
    consola = logging.StreamHandler(sys.stdout)
    consola.setLevel(logging.INFO)
    consola.setFormatter(formato_consola)
    logger.addHandler(consola)

    # Handler de archivo: nivel DEBUG
    archivo = logging.FileHandler(os.path.join(log_dir, "scaner_red.log"))
    archivo.setLevel(logging.DEBUG)
    archivo.setFormatter(formato_archivo)
    logger.addHandler(archivo)

    return logger


# ----------------------------------------------------------------------------
# UI de terminal: colores ANSI, recuadros y banner con fallback a texto plano
# cuando la salida no es un TTY (tuberías, logs, agentes automatizados).
# ----------------------------------------------------------------------------
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_ACTIVAR_COLOR = (
    sys.stdout.isatty()
    and os.environ.get("NO_COLOR") is None
    and os.environ.get("TERM") != "dumb"
)
_SELECTOR_DISPONIBLE = sys.stdin.isatty() and sys.stdout.isatty()

RESET = "\x1b[0m"
NEGRITA = "\x1b[1m"
ATENUADO = "\x1b[2m"
CURSIVA = "\x1b[3m"
SUBRAYADO = "\x1b[4m"
GRIS = "\x1b[90m"
ROJO = "\x1b[31m"
VERDE = "\x1b[32m"
AMARILLO = "\x1b[33m"
AZUL = "\x1b[34m"
MAGENTA = "\x1b[35m"
CIAN = "\x1b[36m"
B_ROJO = "\x1b[1;31m"
B_VERDE = "\x1b[1;32m"
B_AMARILLO = "\x1b[1;33m"
B_AZUL = "\x1b[1;34m"
B_MAGENTA = "\x1b[1;35m"
B_CIAN = "\x1b[1;36m"
B_BLANCO = "\x1b[1;37m"


def pintar(texto, *estilos):
    """Envuelve `texto` en códigos ANSI solo si la terminal admite color."""
    if not _ACTIVAR_COLOR:
        return texto
    return "".join(estilos) + texto + RESET


def _resaltar(texto):
    """Barra invertida (video reverso + tinte cian) para el ítem seleccionado."""
    if _ACTIVAR_COLOR:
        return f"\x1b[7;36m{texto}\x1b[0m"
    return f"\x1b[7m{texto}\x1b[0m"


def ancho_visible(texto):
    """Ancho en columnas ignorando los códigos ANSI incrustados."""
    return len(_ANSI_RE.sub("", texto))


def alinear(texto, ancho, justificacion="<"):
    """Rellena `texto` (posiblemente coloreado) hasta `ancho` visibles."""
    relleno = ancho - ancho_visible(texto)
    if relleno <= 0:
        return texto
    if justificacion == "<":
        return texto + " " * relleno
    return " " * relleno + texto


def centrar(texto, ancho):
    """Centra `texto` (posiblemente coloreado) dentro de `ancho` visibles."""
    relleno = ancho - ancho_visible(texto)
    if relleno <= 0:
        return texto
    izquierda = relleno // 2
    return " " * izquierda + texto + " " * (relleno - izquierda)


def caja(titulo, lineas, color=B_CIAN):
    """Recuadro de terminal ┌─┐ con título centrado y cuerpo alineado a la izquierda."""
    contenidos = [titulo] + list(lineas)
    ancho_max = max(ancho_visible(t) for t in contenidos) if contenidos else 0
    ancho = ancho_max + 4

    def borde(inicio, fin):
        print(pintar(inicio + "─" * ancho + fin, GRIS))

    borde("┌", "┐")
    cabecera = pintar(titulo, color, NEGRITA)
    print(pintar("│ ", GRIS) + centrar(cabecera, ancho_max) + pintar(" │", GRIS))
    if lineas:
        for linea in lineas:
            relleno = ancho_max - ancho_visible(linea)
            print(pintar("│ ", GRIS) + linea + " " * relleno + pintar(" │", GRIS))
    borde("└", "┘")


PASOS_PIPELINE = [
    "▸ Descubrimiento",
    "▸ Puertos y servicios",
    "▸ Detección de SO",
    "▸ Vulnerabilidades",
]


def banner():
    """Cabecera decorativa con el nombre y las fases del pipeline."""
    sub = pintar("Auditoría de red automatizada · Nmap + python-nmap", GRIS, CURSIVA)
    pasos = "   ".join(
        pintar(paso, B_AZUL if i < len(PASOS_PIPELINE) - 1 else B_MAGENTA)
        for i, paso in enumerate(PASOS_PIPELINE)
    )
    caja("scaner_red.py", [sub, pasos], color=B_CIAN)
    print()


class _ConsolaColoreada(logging.Formatter):
    """Formatter de consola que pinta el nivel de log según su severidad."""

    _COLORES = {
        logging.DEBUG: GRIS,
        logging.INFO: VERDE,
        logging.WARNING: AMARILLO,
        logging.ERROR: ROJO,
        logging.CRITICAL: B_ROJO,
    }

    def format(self, record):
        estilo = self._COLORES.get(record.levelno)
        nivel = pintar(record.levelname, estilo, NEGRITA) if estilo else record.levelname
        hora = pintar(self.formatTime(record, "%H:%M:%S"), GRIS)
        return f"{hora} [{nivel}] {record.getMessage()}"


# ----------------------------------------------------------------------------
# Validación de argumentos de red y puertos
# ----------------------------------------------------------------------------
def validar_targets(raw: str):
    """Acepta IP, CIDR (192.168.1.0/24) o rango con guion (192.168.1.1-254),
    separados por comas. Devuelve absolutamente lo que Nmap acepta."""
    partes = raw.replace(" ", "").split(",")
    validados = []
    for parte in partes:
        if "/" in parte:
            ipaddress.ip_network(parte, strict=False)  # lanza ValueError si es inválido
        elif "-" in parte:
            base, fin = parte.rsplit("-", 1)
            ipaddress.ip_address(base)                 # valida la parte de la IP
            if not fin.isdigit():
                raise ValueError(f"Rango inválido (parte final no numérica): {parte}")
            if "." not in fin and int(fin) > 255:
                raise ValueError(f"Octeto final fuera de rango: {parte}")
        else:
            ipaddress.ip_address(parte)                # IP simple
        validados.append(parte)
    return ",".join(validados)


def validar_puertos(raw: str):
    """Acepta '80,443,22' o '1-1000' o combinaciones, como -p de Nmap."""
    for token in raw.replace(" ", "").split(","):
        if "-" in token:
            ini, fin = token.split("-")
            assert ini.isdigit() and fin.isdigit(), f"Puerto inválido: {token}"
            assert 1 <= int(ini) <= int(fin) <= 65535, f"Puerto fuera de rango: {token}"
        else:
            assert token.isdigit(), f"Puerto no numérico: {token}"
            assert 1 <= int(token) <= 65535, f"Puerto fuera de rango: {token}"
    return raw.replace(" ", "")


# ----------------------------------------------------------------------------
# Funciones de reporte: consola (tabla), JSON y TXT
# ----------------------------------------------------------------------------
def tabla_terminal(headers, filas):
    """Imprime una tabla estilizada (┌─┬─┐) con encabezado resaltado."""
    ancho = [ancho_visible(h) for h in headers]
    for fila in filas:
        for i, celda in enumerate(fila):
            ancho[i] = max(ancho[i], ancho_visible(celda))

    def borde(inicio, fin, union):
        print(pintar(inicio + union.join("─" * (a + 2) for a in ancho) + fin, GRIS))

    def celda(texto, i):
        texto = str(texto)
        relleno = ancho[i] - ancho_visible(texto)
        return texto + " " * relleno

    borde("┌", "┐", "┬")
    encabezado = pintar(" │ ".join(celda(h, i) for i, h in enumerate(headers)), B_CIAN)
    print(pintar("│ ", GRIS) + encabezado + pintar(" │", GRIS))
    borde("├", "┤", "┼")
    for fila in filas:
        celdas = " │ ".join(celda(c, i) for i, c in enumerate(fila))
        print(pintar("│ ", GRIS) + celdas + pintar(" │", GRIS))
    borde("└", "┘", "┴")


# ----------------------------------------------------------------------------
# Clase principal del auditor
# ----------------------------------------------------------------------------
class AuditorRed:
    def __init__(self, target, args, logger):
        self.target = target
        self.args = args
        self.log = logger
        self.nm = None       # objeto nmap.PortScanner (import diferido)
        self.resultados = {} # {ip: dict} con toda la información recopilada

    # -- Import diferido de python-nmap con mensaje de instalación claro ------
    def _importar_nmap(self):
        try:
            import nmap
        except ImportError:
            self.log.error(
                "No se pudo importar 'python-nmap' tras la preparación automática.\n"
                "Revisa la instalación del binario 'nmap' y el estado de ~/venv-nmap."
            )
            sys.exit(1)
        self.nm = nmap.PortScanner()

    # -- Construcción de argumentos según el modo elegido ----------------------
    def _argumentos_escaneo(self):
        """Genera los argumentos de Nmap según modo y privilegios."""
        es_root = os.geteuid() == 0 if hasattr(os, "geteuid") else True
        modo = self.args.mode

        if modo == "sigiloso":
            # -sS (SYN, necesita root) o -sT si no hay privilegios;
            # -T2 reduce velocidad y ruido. Sin -sC ni -O para minimizar traza.
            tecnica = "-sS" if es_root else "-sT"
            timing = "-T2"
            extra = ""
        elif modo == "agresivo":
            # -sS + -sC (default scripts) + -T4 para velocidad máxima.
            tecnica = "-sS" if es_root else "-sT"
            timing = "-T4"
            extra = "-sC"
        else:  # "normal" (por defecto)
            tecnica = "-sT"
            timing = "-T3"
            extra = "-sC" if es_root else ""

        # Detección de SO: -O necesita root (o se descarta con aviso).
        os_flag = "-O" if es_root else ""

        # Descubrimiento ARP forzado (-PR) solo en red local y con root.
        discover = "-PR" if (self.args.arp and es_root) else "-PE -sn"

        vuln_script = "" if self.args.no_vuln else f"--script={self.args.vuln_scripts}"

        argumentos = " ".join(x for x in [discover, tecnica, timing, extra, os_flag, vuln_script] if x)
        self.log.debug("Argumentos Nmap: %s", argumentos)
        return argumentos

    # -- Fase 1: Descubrimiento de hosts activos ---------------------------------
    def descubrir_hosts(self):
        args = self._argumentos_escaneo().replace("-sS", "").replace("-sT", "")
        args = (args or "-sn")  # descubrimiento puro: -PE -sn / -PR -sn
        self.log.info(f"[Fase 1/4] Descubriendo hosts activos en {self.target} ...")
        self.nm.scan(hosts=self.target, arguments=args, sudo=os.geteuid() == 0)
        activos = [h for h in self.nm.all_hosts() if self.nm[h].state() == "up"]
        self.log.info(f"[Fase 1/4] {len(activos)} host(s) activo(s): {', '.join(activos) or 'ninguno'}")
        return activos

    # -- Fases 2-4 por host: puertos/servicios, SO y vulnerabilidades -------------
    def escanear_host(self, ip):
        self.log.info(f"[Fases 2-4] Escaneando {ip} (servicios, SO, vulns) ...")
        try:
            ports = validar_puertos(self.args.ports) if self.args.ports else None
        except AssertionError as e:
            self.log.error("Argumento de puertos inválido: %s", e)
            sys.exit(1)

        argumentos = self._argumentos_escaneo().replace("-PR", "").replace("-PE -sn", "").strip()
        # timeout por host: 5 min en normal, 8 en sigiloso, 3 en agresivo
        to_ms = {"sigiloso": 480000, "agresivo": 180000, "normal": 300000}[self.args.mode]
        self.nm.scan(
            hosts=ip,
            ports=ports,
            arguments=argumentos,
            sudo=os.geteuid() == 0,
            timeout=to_ms,
        )
        self._guardar_host(ip)

    # -- Extracción y almacenamiento de datos del host ----------------------------
    def _guardar_host(self, ip):
        host = self.nm[ip]
        datos = {"ip": ip, "estado": host.state(), "hostname": "", "puertos": [], "so": [], "vulnerabilidades": []}

        # Hostnames (DNS/NetBIOS)
        if "hostname" in host:
            datos["hostname"] = host["hostname"]

        # Puertos TCP abiertos con servicio, versión y scripts de puerto
        if "tcp" in host:
            for p, info in host["tcp"].items():
                if info["state"] != "open":
                    continue
                datos["puertos"].append({
                    "puerto": p,
                    "servicio": info.get("name", ""),
                    "producto": info.get("product", ""),
                    "version": info.get("version", ""),
                    "cpe": info.get("cpe", ""),
                    "script": info.get("script", ""),
                })

        # Detección de SO: lista de coincidencias ordenadas por precisión
        for m in host.get("osmatch", []):
            datos["so"].append({"nombre": m.get("name", ""), "precision": m.get("accuracy", "")})

        # Vulnerabilidades a nivel de host (hostscript: e.g. smb-vuln-*)
        for s in host.get("hostscript", []):
            datos["vulnerabilidades"].append({"script": s.get("id", ""), "detalle": s.get("output", "")})

        self.resultados[ip] = datos

    # -- Fase de reportes -----------------------------------------------------------
    def exportar_json(self, ruta):
        with open(ruta, "w", encoding="utf-8") as f:
            json.dump(self.resultados, f, indent=2)
        self.log.info(f"JSON guardado en: {ruta}")

    def exportar_txt(self, ruta):
        with open(ruta, "w", encoding="utf-8") as f:
            f.write(f"REPORTE DE AUDITORÍA DE RED — {datetime.now():%Y-%m-%d %H:%M:%S}\n")
            f.write(f"Target: {self.target} | Modo: {self.args.mode} | Vulns: {not self.args.no_vuln}\n")
            f.write("=" * 70 + "\n\n")
            for ip, d in self.resultados.items():
                f.write(f"Host: {ip}  (estado: {d['estado']})  hostname: {d['hostname'] or '-'}\n")
                f.write("-" * 70 + "\n")
                for p in d["puertos"]:
                    ver = f"{p['producto']} {p['version']}".strip() or "-"
                    f.write(f"  puerto {p['puerto']:<5} {p['servicio']:<12} {ver}\n")
                for s in d["so"]:
                    f.write(f"  OS: {s['nombre']} (precisión {s['precision']}%)\n")
                for v in d["vulnerabilidades"]:
                    f.write(f"  [!] {v['script']}: {v['detalle'][:200]}\n")
                f.write("\n")
        self.log.info(f"Reporte TXT guardado en: {ruta}")

    def mostrar_tabla(self):
        filas = []
        for ip, d in sorted(self.resultados.items()):
            puertos = ", ".join(f"{p['puerto']}/{p['servicio']}" for p in d["puertos"]) or "-"
            so = "; ".join(f"{s['nombre']} ({s['precision']}%)" for s in d["so"][:2]) if d["so"] else "-"
            estado = pintar(d["estado"], VERDE) if d["estado"] == "up" else pintar(d["estado"], AMARILLO)
            n = len(d["vulnerabilidades"])
            vulns = pintar(str(n), ROJO) if n else pintar("0", GRIS)
            filas.append([
                pintar(ip, B_CIAN),
                estado,
                pintar(puertos, CIAN) if puertos != "-" else pintar("-", GRIS),
                pintar(so, MAGENTA) if so != "-" else pintar("-", GRIS),
                vulns,
            ])
        if not filas:
            print(pintar("  [!] No se detectaron hosts activos.", AMARILLO))
        print(pintar("═══ RESUMEN FINAL ═══", B_VERDE))
        tabla_terminal(["Host", "Estado", "Puertos abiertos", "OS detectado", "#Vulns"], filas)

    def _resumen_final(self, inicio):
        """Caja-resumen con los conteos globales y la duración."""
        puertos = sum(len(d["puertos"]) for d in self.resultados.values())
        sistemas = sum(len(d["so"]) for d in self.resultados.values())
        vulns = sum(len(d["vulnerabilidades"]) for d in self.resultados.values())
        caja(
            "Estadísticas de la auditoría",
            [
                pintar(alinear("Hosts analizados", 22), B_BLANCO)
                + pintar(str(len(self.resultados)), B_CIAN),
                pintar(alinear("Puertos abiertos", 22), B_BLANCO)
                + pintar(str(puertos), B_CIAN),
                pintar(alinear("Sistemas (SO)", 22), B_BLANCO)
                + pintar(str(sistemas), B_CIAN),
                pintar(alinear("Vulnerabilidades", 22), B_BLANCO)
                + (pintar(str(vulns), ROJO) if vulns else pintar("0", VERDE)),
                pintar(alinear("Duración", 22), B_BLANCO)
                + pintar(f"{time.time() - inicio:.1f} s", B_CIAN),
            ],
            color=B_VERDE,
        )

    # -- Orquestación completa --------------------------------------------------------
    def ejecutar(self):
        self._importar_nmap()
        banner()
        inicio = time.time()
        activos = self.descubrir_hosts()
        for ip in activos:
            try:
                self.escanear_host(ip)
            except Exception as e:  # noqa: BLE001 — un fallo no aborta la auditoría
                self.log.error(f"Error escaneando {ip}: {e}")
        self.mostrar_tabla()
        self._resumen_final(inicio)
        self.exportar_json(self.args.output_dir + "/reporte_red.json")
        self.exportar_txt(self.args.output_dir + "/reporte_red.txt")
        self.log.info(f"Auditoría completada en {time.time() - inicio:.1f} s. Hosts analizados: {len(self.resultados)}")


# ----------------------------------------------------------------------------
# Preparación automática del entorno: si falta 'python-nmap', se crea (o reusa)
# el venv ~/venv-nmap del usuario invocador, se instala la librería y el script
# se relanza con ese intérprete. Así basta con `python3 scaner_red.py <target>`.
# ----------------------------------------------------------------------------
def _home_usuario():
    if os.geteuid() == 0 and os.environ.get("SUDO_USER"):
        return os.path.expanduser("~" + os.environ["SUDO_USER"])
    return os.path.expanduser("~")


def _asegurar_entorno():
    try:
        import nmap  # noqa: F401
        return  # ya está disponible en este intérprete
    except ImportError:
        pass

    import shutil
    import subprocess

    venv = os.path.join(_home_usuario(), "venv-nmap")
    venv_python = os.path.join(venv, "bin", "python")

    if not os.path.exists(venv_python):
        print(f"Creando entorno virtual {venv} ...", file=sys.stderr)
        subprocess.run([shutil.which("python3") or sys.executable, "-m", "venv", venv], check=True)

    print("Instalando librería 'python-nmap' ...", file=sys.stderr)
    subprocess.run([venv_python, "-m", "pip", "install", "--quiet", "python-nmap"], check=True)

    # Relanzar con el intérprete del venv, que ya tiene la librería.
    os.execv(venv_python, [venv_python, os.path.abspath(__file__)] + sys.argv[1:])


def args_a_cli(args):
    """Convierte un Namespace del menú interactivo en argumentos CLI."""
    cli = [args.target]
    if args.mode != "normal":
        cli += ["--mode", args.mode]
    if args.ports:
        cli += ["--ports", args.ports]
    if getattr(args, "vuln_scripts", "vuln") != "vuln":
        cli += ["--vuln-scripts", args.vuln_scripts]
    if getattr(args, "no_vuln", False):
        cli += ["--no-vuln"]
    if getattr(args, "arp", False):
        cli += ["--arp"]
    if getattr(args, "output_dir", None) not in (None, os.getcwd()):
        cli += ["--output-dir", args.output_dir]
    return cli


# ----------------------------------------------------------------------------
# Elevación de privilegios: el script exige root desde el primer momento.
# Si no se ejecuta como root, se relanza a sí mismo a través de `sudo`
# (que pedirá la contraseña en la terminal) y así TODAS las opciones quedan
# disponibles: escaneo SYN (-sS), detección de SO (-O) y ARP (-PR).
# ----------------------------------------------------------------------------
def _auto_elevar(args=None):
    if os.geteuid() == 0:
        return  # ya se es root, no hace falta elevar

    import shutil
    sudo = shutil.which("sudo")
    if not sudo:
        print("ERROR: el script requiere privilegios de root y no se encontró 'sudo'.", file=sys.stderr)
        sys.exit(1)

    # Se relanza el mismo script con los mismos argumentos, ahora vía sudo.
    # Si se arrancó desde el menú interactivo (argv vacío), se reconstruyen
    # los equivalentes CLI para que el proceso elevado NO muestre el menú
    # otra vez y conserve las respuestas del usuario.
    argv_extra = list(sys.argv[1:])
    if not argv_extra and args is not None:
        argv_extra = args_a_cli(args)

    print("Se requieren privilegios de root. Solicitando permisos con sudo ...", file=sys.stderr)
    comando = [sudo, sys.executable, os.path.abspath(__file__)] + argv_extra
    try:
        os.execv(sudo, comando)  # reemplaza el proceso actual por el elevado
    except OSError:
        print("ERROR: no se pudo relanzar el script con sudo.", file=sys.stderr)
        sys.exit(1)


# ----------------------------------------------------------------------------
# Menú interactivo: si se invoca el script sin argumentos, se muestran las
# opciones en listado numerado y el usuario selecciona paso a paso.
# ----------------------------------------------------------------------------
def _leer_tecla(fd):
    """Lee una pulsación en modo crudo; distingue flechas, Enter y teclas ASCII."""
    import select

    b = os.read(fd, 1)
    if not b:
        return None
    if b == b"\x1b":  # secuencia de escape: flechas, Home/Fin o ESC simple
        if not select.select([sys.stdin], [], [], 0.1)[0]:
            return "esc"
        resto = b""
        while select.select([sys.stdin], [], [], 0.02)[0]:
            try:
                resto += os.read(fd, 16)
            except BlockingIOError:
                break
        secuencias = {
            b"[A": "arriba", b"OA": "arriba",
            b"[B": "abajo", b"OB": "abajo",
            b"[C": "derecha", b"OC": "derecha",
            b"[D": "izquierda", b"OD": "izquierda",
            b"[H": "inicio", b"OH": "inicio", b"[1~": "inicio",
            b"[F": "fin", b"OF": "fin", b"[4~": "fin",
        }
        return secuencias.get(resto, "otro")
    if b in (b"\r", b"\n"):
        return "enter"
    if b == b"\x7f":  # retroceso / DEL
        return "backspace"
    try:
        return b.decode("ascii")
    except UnicodeDecodeError:
        return "otro"


def _selector(opciones, default="1"):
    """Barra de selección navegable con ↑/↓ y atajos numéricos (requiere TTY)."""
    import termios
    import tty

    n_opciones = len(opciones)
    actual = int(default) - 1 if default.isdigit() and 1 <= int(default) <= n_opciones else 0
    ayuda = pintar(f"  ↑/↓ mover · Enter aceptar · 1-{n_opciones} atajo · Esc cancelar", GRIS)
    filas_lienzo = n_opciones + 1  # opciones + línea de ayuda

    def fila_contenido(i):
        marca = "▸" if i == actual else " "
        cuerpo = f"{marca} {i + 1}. {opciones[i]}"
        if str(i + 1) == str(default):
            cuerpo += "   ← por defecto"
        if i == actual:
            cuerpo = _resaltar(cuerpo)
        return cuerpo

    def lienzo():
        filas = [fila_contenido(i) for i in range(n_opciones)]
        ancho = max(ancho_visible(f) for f in filas)
        return [f + " " * (ancho - ancho_visible(f)) for f in filas]

    def dibujar_inicial():
        for fila in lienzo():
            print(fila)
        print(ayuda)

    def redibujar():
        sys.stdout.write(f"\x1b[{filas_lienzo}A\r")
        for fila in lienzo():
            sys.stdout.write(fila + "\n")
        sys.stdout.write(ayuda + "\n")
        sys.stdout.flush()

    dibujar_inicial()
    fd = sys.stdin.fileno()
    anterior = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        while True:
            tecla = _leer_tecla(fd)
            if tecla in ("arriba", "izquierda"):
                actual = (actual - 1) % n_opciones
            elif tecla in ("abajo", "derecha"):
                actual = (actual + 1) % n_opciones
            elif tecla == "enter":
                break
            elif tecla in ("esc", "q"):
                print(pintar("  ¡Hasta luego!", GRIS))
                sys.exit(130)
            elif tecla == "j":
                actual = (actual + 1) % n_opciones
            elif tecla == "k":
                actual = (actual - 1) % n_opciones
            elif tecla == "inicio":
                actual = 0
            elif tecla == "fin":
                actual = n_opciones - 1
            elif tecla is not None and tecla.isdigit() and 1 <= int(tecla) <= n_opciones:
                actual = int(tecla) - 1
                break
            redibujar()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, anterior)

    print()
    return opciones[actual], str(actual + 1)


def _elegir_opcion(opciones, prompt, default="1"):
    """Selección interactiva: barra navegable y, sin TTY, entrada numérica."""
    if _SELECTOR_DISPONIBLE:
        return _selector(opciones, default)

    for i, opcion in enumerate(opciones, 1):
        pred = "  ← por defecto" if str(i) == default else ""
        num = pintar(str(i), B_CIAN if str(i) == default else AZUL)
        print(f"  {num} ▸ {opcion}{pintar(pred, GRIS)}")
    while True:
        try:
            eleccion = input(pintar(prompt, AMARILLO)).strip() or default
        except (KeyboardInterrupt, EOFError):
            print(pintar("  ¡Hasta luego!", GRIS))
            sys.exit(130)
        if eleccion in (str(i) for i in range(1, len(opciones) + 1)):
            return opciones[int(eleccion) - 1], eleccion
        print(pintar(f"  [!] Opción inválida, elige 1-{len(opciones)}.", ROJO))


def _preguntar(texto, default=None):
    """`input()` con manejo de Ctrl-C; devuelve el texto (vacío si se aborta)."""
    try:
        if default is not None:
            return input(pintar(texto, B_BLANCO) + pintar(f" [{default}]", GRIS)).strip() or default
        return input(pintar(texto, B_BLANCO)).strip()
    except (KeyboardInterrupt, EOFError):
        print(pintar("  ¡Hasta luego!", GRIS))
        sys.exit(130)


def menu_interactivo() -> argparse.Namespace:
    banner()
    caja(
        "Uso rápido",
        [
            pintar("  python3 scaner_red.py <target> [opciones]", B_BLANCO),
            pintar("  › 192.168.1.0/24 · 10.0.0.5 · 192.168.1.1-254", CIAN),
            pintar("  › --mode sigiloso --no-vuln --output-dir ~/audit", CIAN),
            pintar("  Sin argumentos abres este asistente.", GRIS, CURSIVA),
        ],
        color=B_CIAN,
    )
    print()
    caja(
        "Auditoría de red",
        [
            pintar("Este proceso lanza un ", AMARILLO)
            + pintar("escaneo real", AMARILLO, SUBRAYADO)
            + pintar(" contra el target indicado y exige privilegios de root.", AMARILLO),
            pintar("Usa el script solo en redes propias o con autorización explícita.", GRIS, CURSIVA),
        ],
        color=B_MAGENTA,
    )
    print()

    caja(
        "Target",
        [
            pintar("Acepta IP, CIDR (192.168.1.0/24), rango con guion (192.168.1.1-254)", GRIS, CURSIVA),
            pintar("o varios separados por comas.", GRIS, CURSIVA),
        ],
        color=B_CIAN,
    )
    print()
    while True:
        target = _preguntar("  Target ▸ ")
        try:
            target = validar_targets(target)
            break
        except ValueError as e:
            print(pintar(f"  [!] Inválido: {e}", ROJO))

    print("\n" + pintar("· Modo de escaneo", B_BLANCO))
    modo, _ = _elegir_opcion(
        ("normal", "sigiloso", "agresivo"),
        "  Selecciona el modo [1-3, default 1]: ",
        "1",
    )

    print("\n" + pintar("· Fase de vulnerabilidades (--script=vuln)", B_BLANCO))
    vuln, _ = _elegir_opcion(("Sí (por defecto)", "No"),
                             "  ¿Ejecutar la fase de vulnerabilidades? [1-2]: ", "1")
    no_vuln = vuln == "No"
    vuln_scripts = "vuln"
    if not no_vuln:
        vuln_scripts = _preguntar("  Scripts NSE de vulnerabilidad", vuln_scripts)

    print("\n" + pintar("· Descubrimiento ARP (-PR, solo red local)", B_BLANCO))
    arp_opt, _ = _elegir_opcion(("No (por defecto)", "Sí"),
                                "  ¿Usar ARP? [1-2]: ", "1")
    arp = arp_opt == "Sí"

    print("\n" + pintar("· Puertos a escanear", B_BLANCO))
    puertos = _preguntar("  Puertos (vacío = todos; ej: 80,443 o 1-1000) ▸ ") or None
    if puertos:
        try:
            puertos = validar_puertos(puertos)
        except AssertionError as e:
            print(pintar(f"  [!] Puertos inválidos ({e}) — se escanearán todos.", AMARILLO))
            puertos = None

    output_dir = _preguntar("  Directorio de reportes ▸ ", os.getcwd())

    caja(
        "Resumen de la auditoría",
        [
            pintar(alinear("Target", 14), B_BLANCO) + pintar(f"▸ {target}", B_CIAN),
            pintar(alinear("Modo", 14), B_BLANCO) + pintar(f"▸ {modo}", CIAN),
            pintar(alinear("Puertos", 14), B_BLANCO) + pintar(f"▸ {puertos or 'todos'}", CIAN),
            pintar(alinear("Vulnerab.", 14), B_BLANCO)
            + (pintar(f"▸ sí ({vuln_scripts})", VERDE) if not no_vuln else pintar("▸ no", GRIS)),
            pintar(alinear("ARP", 14), B_BLANCO) + (pintar("▸ sí", VERDE) if arp else pintar("▸ no", GRIS)),
            pintar(alinear("Output dir", 14), B_BLANCO) + pintar(f"▸ {output_dir}", CIAN),
        ],
        color=B_VERDE,
    )

    confirmacion = _preguntar("  ¿Confirmar y arrancar la auditoría? [s/N]")
    if confirmacion.lower() != "s":
        print(pintar("  Cancelado.", AMARILLO))
        sys.exit(0)

    return argparse.Namespace(target=target, mode=modo, ports=puertos,
                              vuln_scripts=vuln_scripts, no_vuln=no_vuln,
                              arp=arp, output_dir=output_dir)


# ----------------------------------------------------------------------------
# Punto de entrada
# ----------------------------------------------------------------------------
def main():
    _asegurar_entorno()  # prepara python-nmap automáticamente si falta
    parser = argparse.ArgumentParser(
        description="Auditoría de red automatizada (Nmap + python-nmap)."
                    " Para uso exclusivo en entornos controlados y autorizados."
    )
    parser.add_argument("target", nargs="?", default=None,
                        help="Rango de red: 192.168.1.0/24, 10.0.0.5 o 192.168.1.1-254."
                             " Si se omite, se abre el menú interactivo.")
    parser.add_argument("--ports", default=None, help="Puertos a escanear: '80,443,22' o '1-1000'")
    parser.add_argument("--mode", choices=("sigiloso", "normal", "agresivo"), default="normal",
                        help="Perfil de escaneo (por defecto: normal)")
    parser.add_argument("--vuln-scripts", default="vuln",
                        help="Scripts NSE de vulnerabilidad (por defecto: categoría 'vuln')."
                             " Ej: 'vulners' o 'smb-vuln-ms17-010'")
    parser.add_argument("--no-vuln", action="store_true", help="Omitir la fase de vulnerabilidades")
    parser.add_argument("--arp", action="store_true", help="Usar descubrimiento ARP (-PR, red local, root)")
    parser.add_argument("--output-dir", default=os.getcwd(), help="Directorio para los reportes")
    args = parser.parse_args()

    if args.target is None:
        args = menu_interactivo()  # sin argumentos: selección por listado

    _auto_elevar(args)  # exigir root antes de iniciar el escaneo
    os.makedirs(args.output_dir, exist_ok=True)
    logger = configurar_logging(args.output_dir)

    try:
        target = validar_targets(args.target)
    except ValueError as e:
        logger.error("Target inválido: %s", e)
        sys.exit(1)

    AuditorRed(target, args, logger).ejecutar()


if __name__ == "__main__":
    main()