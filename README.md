# scaner_red.py-v2

<img width="953" height="1016" alt="Captura desde 2026-09-23 11-37-29" src="https://github.com/user-attachments/assets/1bd9b5cc-f398-435d-bd13-ca324addfd41" />
<img width="953" height="1016" alt="Captura desde 2026-09-23 11-37-13" src="https://github.com/user-attachments/assets/45392a73-1420-4722-8d6b-94846eee0366" />

Auditoría de red automatizada para entornos **autorizados** (laboratorio propio / pentest autorizado). Envuelve Nmap (vía `python-nmap`) en un pipeline de 4 fases: descubrimiento de hosts, escaneo de puertos y servicios, detección de SO y análisis de vulnerabilidades.

## Requisitos

Todo se prepara solo en la primera ejecución:

- Python 3 y el binario `nmap` instalado (`/usr/bin/nmap`).
- Si falta `python-nmap`, el script crea (o reutiliza) el venv `~/venv-nmap`, instala la librería y se relanza con ese intérprete automáticamente.
- Se auto-eleva a root con `sudo` (pide la contraseña en la terminal) para habilitar `-sS`, `-O` y `-PR`.

## Inicio rápido

**Modo interactivo (asistente por menú):**

```
python3 scaner_red.py
```

Se abre un asistente con banner y paneles: eliges el target, el modo de escaneo con una **barra de selección** (flechas `↑/↓` o atajos `1-N`), la fase de vulnerabilidades, ARP, puertos y el directorio de reportes. Al final muestra un resumen y pide confirmación antes de ejecutar. El valor elegido se conserva al relanzar con `sudo` (el menú no se repite).

**Directo desde terminal:**

```
python3 scaner_red.py 192.168.1.0/24
```

Ambos configuran el entorno automáticamente y piden la contraseña de sudo antes del escaneo.

## Uso

```
python3 scaner_red.py <target> [opciones]
```

`<target>` acepta:

| Formato          | Ejemplo                      |
|------------------|------------------------------|
| IP simple        | `10.0.0.5`                   |
| CIDR             | `192.168.1.0/24`             |
| Rango con guion  | `192.168.1.1-254`            |
| Varios (comas)   | `192.168.1.0/24,10.0.0.5`    |

## Interfaz interactiva

Sin argumentos se abre el asistente; con `target` en la línea de comandos se salta el menú. Las selecciones usan una **barra de selección** navegable (requiere una terminal real; si la entrada/salida no es interactiva cae a la entrada numérica por teclado):

| Tecla            | Acción                              |
|------------------|-------------------------------------|
| `↑` / `↓` (o `k`/`j`) | Mover el cursor en la lista  |
| `←` / `→`        | Mismo efecto que `↑` / `↓`          |
| `1`–`N`          | Seleccionar la opción N al instante |
| `Enter`          | Aceptar la opción resaltada         |
| `Home` / `Fin`   | Ir al primero / último              |
| `Esc` o `q`      | Salir sin ejecutar                  |

Los colores (banner, recuadros, tablas y logs) se activan solo en una terminal interactiva; se desactivan con `NO_COLOR` o `TERM=dumb`. Fuera de un TTY todo se muestra en texto plano.

## Opciones

| Opción              | Descripción                                                          | Default        |
|---------------------|----------------------------------------------------------------------|----------------|
| `--mode`            | Perfil de escaneo: `normal`, `sigiloso` o `agresivo`                 | `normal`       |
| `--ports`           | Puertos a escanear: `80,443,22` o `1-1000`                           | todos         |
| `--vuln-scripts`    | Scripts NSE de vulnerabilidad (`vulners`, `smb-vuln-ms17-010`, ...) | `vuln`         |
| `--no-vuln`         | Omite la fase de vulnerabilidades                                     | desactivado    |
| `--arp`             | Descubrimiento ARP `-PR` (solo red local con root)                   | desactivado    |
| `--output-dir`      | Directorio para los reportes                                          | directorio actual |

### Modos de escaneo

| Modo       | Técnica          | Timing | Extras         |
|------------|------------------|--------|----------------|
| `normal`   | `-sT`            | `-T3`  | `-sC` si root  |
| `sigiloso` | `-sS`/`-sT`      | `-T2`  | sin `-sC`; `-O` si root |
| `agresivo` | `-sS`/`-sT`      | `-T4`  | `-sC`          |

`normal` usa siempre `-sT` (nunca `-sS`); `sigiloso` y `agresivo` usan `-sS` con root y `-sT` sin él. La detección de SO (`-O`) se añade **siempre** que haya root, en cualquier modo.

Timeout por host: 5 min `normal`, 8 min `sigiloso`, 3 min `agresivo`.

## Pipeline

1. Fase 1 — Descubrimiento de hosts activos (`-sn`, ICMP `-PE` o ARP `-PR`).
2. Fases 2-4 — Por cada host activo: puertos/servicios, SO (`-O` si hay root) y vulnerabilidades NSE (`--script=vuln`). Un fallo en un host no aborta la auditoría.

## Resultados

| Archivo            | Contenido                                   |
|--------------------|---------------------------------------------|
| `reporte_red.json` | Estructurado, organizado por host           |
| `reporte_red.txt`  | Legible (puertos, SO y vulns por host)      |
| `scaner_red.log`   | Progreso del escaneo (DEBUG)                |

En consola, al terminar, se muestra la tabla `RESUMEN FINAL` (host, estado, puertos, SO y nº de vulns) y un recuadro con las estadísticas globales (hosts, puertos abiertos, sistemas, vulnerabilidades y duración).

## Ejemplos

```
# Escaneo normal de una red completa
python3 scaner_red.py 192.168.1.0/24 --output-dir ~/Escritorio/auditoria

# Host específico, sin fase de vulns
python3 scaner_red.py 10.0.0.5 --mode normal --no-vuln

# Barrido silencioso con descubrimiento ARP
python3 scaner_red.py 192.168.1.1-254 --mode sigiloso --arp

# Solo ciertos puertos con scripts 'vulners'
python3 scaner_red.py 192.168.1.0/24 --ports 80,443,22 --vuln-scripts vulners
```

## Advertencia

El script ejecuta escaneos reales contra el target indicado y exige root. Usar **solo** en redes propias o con autorización explícita.
