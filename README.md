# PCI CardScan4Linux

Herramienta de escaneo de datos de tarjeta de pago (PAN) para sistemas **Ubuntu y Debian**, orientada a auditorías de cumplimiento **PCI DSS v4.0**.

Detecta Primary Account Numbers (PAN) en texto claro, los valida con el algoritmo de Luhn, y genera un informe de auditoría profesional en formato `.docx`.

---

## Características

- Detección robusta de archivos binarios (por extensión y análisis de bytes) — sin errores `UnicodeDecodeError`
- Validación con algoritmo **Luhn (ISO/IEC 7812)** para eliminar falsos positivos
- Soporte para **Visa, Mastercard, Amex, Discover, Diners Club y JCB**
- PAN enmascarado en todos los registros (primeros 6 + últimos 4 dígitos, PCI DSS Req. 3.3.1)
- Exclusión automática de rutas de sistema (`/proc`, `/sys`, `/dev`, `/snap`, etc.)
- Salida estructurada en **JSON** para integración con pipelines de auditoría
- Generación automática de **informe Word (.docx)** listo para auditor QSA

---

## Requisitos

| Componente | Versión mínima | Notas |
|---|---|---|
| Python | 3.9+ | Incluido en Ubuntu 22.04+ / Debian 11+ |
| Node.js | 18+ | Para el generador de informes |
| npm | 8+ | Para instalar dependencias JS |

### Instalación de dependencias

```bash
# Dependencia JS para generación del informe Word
npm install docx
```

No se requieren paquetes Python adicionales. El escáner usa sólo la biblioteca estándar.

---

## Uso rápido

### 1. Escanear un directorio

```bash
python3 pci_cardscan.py /var/www
```

Genera `pci_scan_results.json` en el directorio actual.

### 2. Generar el informe de auditoría

```bash
node pci_report_generator.js pci_scan_results.json --output informe_pci.docx
```


---

## Opciones del escáner

```
python3 pci_cardscan.py <directorio> [opciones]

Argumentos:
  directorio            Ruta raíz a escanear

Opciones:
  --output FILE         Archivo JSON de salida (por defecto: pci_scan_results.json)
  --exclude DIR [DIR…]  Directorios adicionales a excluir
  --quiet               Suprime la salida por consola de cada hallazgo
```

### Probar el correcto funcionamiento de la herramienta:

```
python3 pci_cardscan.py . --output test_results.json
# → Resultado esperado: 14 hallazgos
```



### Ejemplos

```bash
# Escaneo completo del servidor web
python3 pci_cardscan.py /var/www --output resultados_$(date +%Y%m%d).json

# Escaneo de home excluyendo backups
python3 pci_cardscan.py /home --exclude /home/backups /home/archives

# Escaneo silencioso para uso en scripts/cron
python3 pci_cardscan.py /opt/app --quiet --output /var/log/pci/scan.json
```

---

## Estructura del repositorio

```
pci-cardscan4linux/
├── pci_cardscan.py            # Escáner principal
├── pci_report_generator.js    # Generador de informe Word
├── README.md                  # Este archivo
└── example/
    └── pci_scan_results.json  # Ejemplo de salida JSON
```

---

## Formato de salida JSON

```json
{
  "meta": {
    "hostname": "srv-web01.empresa.local",
    "os": "Ubuntu 24.04 LTS",
    "scan_root": "/var/www",
    "scan_start": "2026-03-09T18:00:00Z",
    "scan_end": "2026-03-09T18:04:37Z",
    "duration_seconds": 277.4
  },
  "summary": {
    "files_scanned": 14823,
    "total_findings": 7,
    "files_with_pan": 4,
    "findings_by_card_type": { "Visa": 4, "Mastercard": 2, "Amex": 1 }
  },
  "findings": [
    {
      "file": "/var/www/html/storage/logs/payment_debug.log",
      "line": 142,
      "card_type": "Visa",
      "pan_masked": "411111******1111",
      "pan_length": 16,
      "context": "[2025-12-01] DEBUG card=411111******1111 amount=129.90"
    }
  ]
}
```

---

## El informe de auditoría

El archivo `.docx` generado incluye:

1. **Portada** con estado de cumplimiento (PASS / MEDIUM / HIGH)
2. **Resumen ejecutivo** con valoración de conformidad PCI DSS
3. **Estadísticas del escaneo** — cobertura, archivos analizados, omitidos
4. **Detalle de hallazgos** por archivo con PAN enmascarados
5. **Marco normativo** — estado de Requisitos 3.3, 3.4 y 3.5 de PCI DSS v4.0
6. **Recomendaciones** de remediación inmediata y controles preventivos
7. **Metodología** técnica del escaneo

---

## Uso como tarea programada (cron)

```bash
# Escaneo semanal automatizado (domingos a las 2:00 AM)
0 2 * * 0 /usr/bin/python3 /opt/pci-cardscan/pci_cardscan.py /var/www \
    --quiet \
    --output /var/log/pci/scan_$(date +\%Y\%m\%d).json && \
  /usr/bin/node /opt/pci-cardscan/pci_report_generator.js \
    /var/log/pci/scan_$(date +\%Y\%m\%d).json \
    --output /var/log/pci/informe_$(date +\%Y\%m\%d).docx
```

---

## Consideraciones de seguridad

- **Este script requiere permisos de lectura** sobre los directorios escaneados. Ejecútalo con el usuario mínimo necesario.
- Los archivos JSON y `.docx` generados contienen **información sensible enmascarada** — protege el acceso a los informes.
- Este escáner **no modifica ningún archivo** del sistema analizado.
- No cubre: bases de datos en ejecución, memoria de procesos, ni volúmenes cifrados montados. Complementa con escaneo de BBDD y análisis de tráfico de red.

---

## Limitaciones conocidas

- Archivos mayores de **50 MB** se omiten por rendimiento.
- No escanea el interior de archivos comprimidos (`.zip`, `.tar.gz`, etc.).
- Los falsos negativos son posibles si el PAN está ofuscado, dividido en columnas, o almacenado en formato no textual.

---

## Licencia

MIT — ver `LICENSE` para más detalles.
