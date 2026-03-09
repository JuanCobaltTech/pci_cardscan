#!/usr/bin/env node
/**
 * pci_report_generator.js — PCI DSS Audit Report Generator
 * Reads JSON output from pci_cardscan.py and creates a .docx audit report.
 *
 * Usage:
 *   node pci_report_generator.js pci_scan_results.json
 *   node pci_report_generator.js pci_scan_results.json --output audit_report.docx
 */

const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, HeadingLevel, BorderStyle, WidthType,
  ShadingType, VerticalAlign, PageNumber, PageBreak, LevelFormat,
  TableOfContents
} = require('docx');
const fs   = require('fs');
const path = require('path');

// ─────────────────────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────────────────────

const COLORS = {
  red:        "C0392B",
  orange:     "E67E22",
  green:      "27AE60",
  navy:       "1B3A6B",
  lightBlue:  "D5E8F0",
  tableHead:  "1B3A6B",
  tableAlt:   "EBF4FA",
  white:      "FFFFFF",
  lightGray:  "F5F5F5",
  borderGray: "CCCCCC",
  textDark:   "1A1A1A",
  textGray:   "555555",
};

function cellBorders(color = COLORS.borderGray) {
  const b = { style: BorderStyle.SINGLE, size: 1, color };
  return { top: b, bottom: b, left: b, right: b };
}

function hCell(text, widthDXA, bgColor = COLORS.tableHead) {
  return new TableCell({
    borders: cellBorders(COLORS.navy),
    width: { size: widthDXA, type: WidthType.DXA },
    shading: { fill: bgColor, type: ShadingType.CLEAR },
    margins: { top: 80, bottom: 80, left: 160, right: 160 },
    verticalAlign: VerticalAlign.CENTER,
    children: [new Paragraph({
      alignment: AlignmentType.CENTER,
      children: [new TextRun({ text, bold: true, color: COLORS.white, size: 18, font: "Arial" })]
    })]
  });
}

function dCell(text, widthDXA, options = {}) {
  const { center = false, bold = false, color = COLORS.textDark, bg = COLORS.white, mono = false } = options;
  return new TableCell({
    borders: cellBorders(),
    width: { size: widthDXA, type: WidthType.DXA },
    shading: { fill: bg, type: ShadingType.CLEAR },
    margins: { top: 60, bottom: 60, left: 160, right: 160 },
    verticalAlign: VerticalAlign.CENTER,
    children: [new Paragraph({
      alignment: center ? AlignmentType.CENTER : AlignmentType.LEFT,
      children: [new TextRun({ text: String(text ?? ""), bold, color, size: 18,
                               font: mono ? "Courier New" : "Arial" })]
    })]
  });
}

function para(runs, options = {}) {
  return new Paragraph({ ...options, children: Array.isArray(runs) ? runs : [runs] });
}

function h1(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    children: [new TextRun({ text, font: "Arial", size: 32, bold: true, color: COLORS.navy })],
    spacing: { before: 360, after: 180 },
    border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: COLORS.navy, space: 1 } }
  });
}

function h2(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_2,
    children: [new TextRun({ text, font: "Arial", size: 26, bold: true, color: COLORS.navy })],
    spacing: { before: 240, after: 120 },
  });
}

function bodyText(text, options = {}) {
  const { bold = false, color = COLORS.textDark, italic = false } = options;
  return para(new TextRun({ text, font: "Arial", size: 22, bold, color, italic }),
    { spacing: { after: 120 } });
}

function bullet(text, reference = "bullets") {
  return new Paragraph({
    numbering: { reference, level: 0 },
    children: [new TextRun({ text, font: "Arial", size: 22, color: COLORS.textDark })],
    spacing: { after: 60 }
  });
}

function spacer(lines = 1) {
  return new Paragraph({
    children: [new TextRun("")],
    spacing: { after: lines * 160 }
  });
}

function pageBreak() {
  return new Paragraph({ children: [new PageBreak()] });
}

function severityLabel(count) {
  if (count === 0) return { label: "PASS", color: COLORS.green };
  if (count < 10)  return { label: "MEDIUM", color: COLORS.orange };
  return { label: "HIGH", color: COLORS.red };
}

// ─────────────────────────────────────────────────────────────────────────────
//  Report Builder
// ─────────────────────────────────────────────────────────────────────────────

function buildReport(data) {
  const { meta, summary, findings } = data;
  const scanDate  = new Date(meta.scan_end).toLocaleString("es-ES", { timeZone: "UTC" }) + " UTC";
  const totalPANs = summary.total_findings;
  const { label: sev, color: sevColor } = severityLabel(totalPANs);

  // ── Findings grouped by file (sorted by file path)
  const byFile = {};
  for (const f of findings) {
    if (!byFile[f.file]) byFile[f.file] = [];
    byFile[f.file].push(f);
  }
  const sortedFiles = Object.keys(byFile).sort();

  // ── Cover page
  const coverPage = [
    spacer(4),
    para(new TextRun({ text: "INFORME DE AUDITORÍA PCI DSS", font: "Arial",
                       size: 52, bold: true, color: COLORS.navy }),
      { alignment: AlignmentType.CENTER }),
    spacer(1),
    para(new TextRun({ text: "Escaneo de Datos de Tarjeta en Sistemas Linux", font: "Arial",
                       size: 30, color: COLORS.textGray }),
      { alignment: AlignmentType.CENTER }),
    spacer(3),

    // Status badge table
    new Table({
      width: { size: 3600, type: WidthType.DXA },
      columnWidths: [3600],
      alignment: AlignmentType.CENTER,
      rows: [new TableRow({ children: [
        new TableCell({
          borders: cellBorders(sevColor),
          width: { size: 3600, type: WidthType.DXA },
          shading: { fill: sevColor, type: ShadingType.CLEAR },
          margins: { top: 160, bottom: 160, left: 200, right: 200 },
          verticalAlign: VerticalAlign.CENTER,
          children: [new Paragraph({
            alignment: AlignmentType.CENTER,
            children: [new TextRun({ text: `ESTADO: ${sev}`, bold: true,
                                     color: COLORS.white, size: 28, font: "Arial" })]
          })]
        })
      ]})]
    }),

    spacer(3),
    para(new TextRun({ text: `Fecha de escaneo: ${scanDate}`, font: "Arial", size: 22, color: COLORS.textGray }),
      { alignment: AlignmentType.CENTER }),
    para(new TextRun({ text: `Host analizado: ${meta.hostname}`, font: "Arial", size: 22, color: COLORS.textGray }),
      { alignment: AlignmentType.CENTER }),
    para(new TextRun({ text: `Directorio raíz: ${meta.scan_root}`, font: "Arial", size: 22, color: COLORS.textGray }),
      { alignment: AlignmentType.CENTER }),
    para(new TextRun({ text: `Sistema operativo: ${meta.os}`, font: "Arial", size: 22, color: COLORS.textGray }),
      { alignment: AlignmentType.CENTER }),
    spacer(2),
    para(new TextRun({ text: `PCI DSS v4.0 — Requisito 3.3 y 3.4`, font: "Arial",
                       size: 20, italic: true, color: COLORS.textGray }),
      { alignment: AlignmentType.CENTER }),
    pageBreak(),
  ];

  // ── 1. Resumen ejecutivo
  const execSummary = [
    h1("1. Resumen Ejecutivo"),
    bodyText(
      `Este informe documenta los resultados del escaneo automatizado de datos de tarjeta de pago ` +
      `(PAN — Primary Account Numbers) realizado sobre el sistema "${meta.hostname}". ` +
      `El análisis se ejecutó el ${scanDate} sobre el directorio "${meta.scan_root}" ` +
      `con una duración total de ${meta.duration_seconds} segundos.`
    ),
    bodyText(
      `El escáner examinó ${summary.files_scanned.toLocaleString()} archivos de texto, descartando ` +
      `${summary.files_skipped_binary.toLocaleString()} archivos binarios y ` +
      `${summary.files_skipped_permission.toLocaleString()} archivos sin permiso de lectura. ` +
      `Se aplicó validación mediante el algoritmo de Luhn para eliminar falsos positivos.`
    ),
    bodyText(
      totalPANs === 0
        ? "No se encontraron datos de tarjeta en texto claro. El sistema cumple con el requisito 3.3 de PCI DSS respecto al almacenamiento de PAN."
        : `Se encontraron ${totalPANs} instancias de PAN en texto claro distribuidas en ` +
          `${summary.files_with_pan} archivo(s). Esto constituye una NO CONFORMIDAD con PCI DSS ` +
          `Requisito 3.3 que prohíbe almacenar datos de tarjeta sensibles tras la autorización.`,
      { bold: totalPANs > 0, color: totalPANs > 0 ? COLORS.red : COLORS.green }
    ),
    spacer(1),
  ];

  // ── 2. Estadísticas del escaneo
  const statsSection = [
    h1("2. Estadísticas del Escaneo"),
    h2("2.1 Cobertura"),
    new Table({
      width: { size: 9360, type: WidthType.DXA },
      columnWidths: [5200, 4160],
      rows: [
        new TableRow({ children: [ hCell("Métrica", 5200), hCell("Valor", 4160) ] }),
        new TableRow({ children: [ dCell("Archivos de texto analizados", 5200, { bg: COLORS.lightGray }), dCell(summary.files_scanned.toLocaleString(), 4160, { center: true, bold: true, bg: COLORS.lightGray }) ] }),
        new TableRow({ children: [ dCell("Archivos binarios omitidos", 5200), dCell(summary.files_skipped_binary.toLocaleString(), 4160, { center: true }) ] }),
        new TableRow({ children: [ dCell("Archivos sin permiso de acceso", 5200, { bg: COLORS.lightGray }), dCell(summary.files_skipped_permission.toLocaleString(), 4160, { center: true, bg: COLORS.lightGray }) ] }),
        new TableRow({ children: [ dCell("Archivos demasiado grandes (>50 MB)", 5200), dCell(summary.files_skipped_large.toLocaleString(), 4160, { center: true }) ] }),
        new TableRow({ children: [ dCell("Directorios excluidos", 5200, { bg: COLORS.lightGray }), dCell(summary.dirs_excluded.toLocaleString(), 4160, { center: true, bg: COLORS.lightGray }) ] }),
        new TableRow({ children: [ dCell("Duración del escaneo", 5200), dCell(`${meta.duration_seconds} segundos`, 4160, { center: true }) ] }),
      ]
    }),
    spacer(1),
    h2("2.2 Hallazgos por Red de Tarjeta"),
    new Table({
      width: { size: 9360, type: WidthType.DXA },
      columnWidths: [4680, 2360, 2320],
      rows: [
        new TableRow({ children: [ hCell("Red de Tarjeta", 4680), hCell("Instancias encontradas", 2360), hCell("Archivos afectados", 2320) ] }),
        ...(Object.keys(summary.findings_by_card_type).length === 0
          ? [new TableRow({ children: [ dCell("Sin hallazgos", 4680, { italic: true, color: COLORS.green }), dCell("0", 2360, { center: true }), dCell("0", 2320, { center: true }) ] })]
          : Object.entries(summary.findings_by_card_type)
              .sort((a, b) => b[1] - a[1])
              .map(([ctype, cnt], i) => {
                const filesForType = new Set(findings.filter(f => f.card_type === ctype).map(f => f.file)).size;
                const bg = i % 2 === 0 ? COLORS.white : COLORS.lightGray;
                return new TableRow({ children: [
                  dCell(ctype, 4680, { bg }),
                  dCell(cnt, 2360, { center: true, bold: true, color: COLORS.red, bg }),
                  dCell(filesForType, 2320, { center: true, bg }),
                ]});
              })
        ),
        new TableRow({ children: [
          dCell("TOTAL", 4680, { bold: true, bg: COLORS.tableAlt }),
          dCell(totalPANs, 2360, { center: true, bold: true, color: totalPANs > 0 ? COLORS.red : COLORS.green, bg: COLORS.tableAlt }),
          dCell(summary.files_with_pan, 2320, { center: true, bold: true, bg: COLORS.tableAlt }),
        ]})
      ]
    }),
    spacer(1),
    pageBreak(),
  ];

  // ── 3. Detalle de hallazgos
  const findingsSection = [
    h1("3. Detalle de Hallazgos"),
  ];

  if (findings.length === 0) {
    findingsSection.push(
      bodyText("No se encontraron PAN en texto claro.", { color: COLORS.green, bold: true })
    );
  } else {
    findingsSection.push(
      bodyText(
        `A continuación se detallan los ${totalPANs} hallazgos encontrados. Los PAN están enmascarados ` +
        `mostrando únicamente los primeros 6 y últimos 4 dígitos, conforme a PCI DSS Req. 3.3.1.`
      )
    );

    for (const filePath of sortedFiles) {
      const fileFindings = byFile[filePath];
      findingsSection.push(h2(`Archivo: ${path.basename(filePath)}`));
      findingsSection.push(
        bodyText(`Ruta completa: ${filePath}`, { italic: true, color: COLORS.textGray })
      );
      findingsSection.push(
        new Table({
          width: { size: 9360, type: WidthType.DXA },
          columnWidths: [700, 1600, 2200, 4860],
          rows: [
            new TableRow({ children: [
              hCell("Línea", 700),
              hCell("Red", 1600),
              hCell("PAN (enmascarado)", 2200),
              hCell("Contexto", 4860),
            ]}),
            ...fileFindings.map((f, i) => {
              const bg = i % 2 === 0 ? COLORS.white : COLORS.lightGray;
              return new TableRow({ children: [
                dCell(f.line, 700, { center: true, bg }),
                dCell(f.card_type, 1600, { bg }),
                dCell(f.pan_masked, 2200, { mono: true, bg }),
                dCell(f.context.substring(0, 80), 4860, { mono: true, bg, color: COLORS.textGray }),
              ]});
            })
          ]
        })
      );
      findingsSection.push(spacer(1));
    }
  }

  findingsSection.push(pageBreak());

  // ── 4. Rutas excluidas
  const excludedSection = [
    h1("4. Rutas Excluidas del Análisis"),
    bodyText("Las siguientes rutas fueron excluidas del escaneo para evitar errores en archivos del sistema:"),
    spacer(0),
    ...meta.excluded_paths.map(p => bullet(p)),
    spacer(1),
    pageBreak(),
  ];

  // ── 5. Marco normativo
  const normativeSection = [
    h1("5. Marco Normativo PCI DSS v4.0"),
    h2("5.1 Requisitos Aplicables"),
    new Table({
      width: { size: 9360, type: WidthType.DXA },
      columnWidths: [1600, 3600, 4160],
      rows: [
        new TableRow({ children: [ hCell("Req.", 1600), hCell("Descripción", 3600), hCell("Estado", 4160) ] }),
        new TableRow({ children: [
          dCell("3.3", 1600, { bg: COLORS.lightGray }),
          dCell("No almacenar datos de autenticación sensibles tras la autorización", 3600, { bg: COLORS.lightGray }),
          dCell(totalPANs === 0 ? "✓ CONFORME" : "✗ NO CONFORME — PAN encontrados en texto claro", 4160, {
            bg: COLORS.lightGray, bold: true,
            color: totalPANs === 0 ? COLORS.green : COLORS.red
          }),
        ]}),
        new TableRow({ children: [
          dCell("3.4", 1800),
          dCell("Los PAN deben ser ilegibles donde estén almacenados (cifrado, hash, tokenización)", 3600),
          dCell(totalPANs === 0 ? "✓ Sin evidencia de PAN no cifrados" : "✗ Verificar cifrado en archivos afectados", 4160, {
            bold: true, color: totalPANs === 0 ? COLORS.green : COLORS.orange
          }),
        ]}),
        new TableRow({ children: [
          dCell("3.5", 1600, { bg: COLORS.lightGray }),
          dCell("Proteger los PAN donde quiera que sean almacenados", 3600, { bg: COLORS.lightGray }),
          dCell("Ver hallazgos en sección 3", 4160, { bg: COLORS.lightGray, italic: true, color: COLORS.textGray }),
        ]}),
      ]
    }),
    spacer(1),
    pageBreak(),
  ];

  // ── 6. Recomendaciones
  const recoSection = [
    h1("6. Recomendaciones"),
    h2("6.1 Acciones Inmediatas (Si se encontraron hallazgos)"),
    bullet("Identificar el propósito legítimo de cada archivo que contiene PAN."),
    bullet("Eliminar los PAN en texto claro que no sean necesarios para operaciones del negocio."),
    bullet("Aplicar cifrado (AES-256) o tokenización a los archivos que deban conservarse."),
    bullet("Revocar accesos de lectura innecesarios a los archivos afectados."),
    bullet("Documentar y notificar los hallazgos al Responsable de Cumplimiento PCI."),
    spacer(1),
    h2("6.2 Controles Preventivos"),
    bullet("Implementar monitoreo continuo de integridad de archivos (FIM) con herramientas como AIDE o Tripwire."),
    bullet("Configurar reglas DLP (Data Loss Prevention) a nivel de kernel (auditd) para detectar acceso a PAN."),
    bullet("Establecer políticas de retención de datos y destrucción segura con shred/wipe."),
    bullet("Ejecutar este escaneo de forma periódica (mínimo trimestral) y tras cada cambio mayor de sistema."),
    bullet("Revisar las configuraciones de aplicaciones para garantizar que no escriban PAN en logs."),
    spacer(1),
    h2("6.3 Controles de Logging y Auditoría"),
    bullet("Asegurar que auditd registre accesos a directorios sensibles (/etc, /var/log, /home)."),
    bullet("Integrar los resultados de este escaneo en el SIEM corporativo."),
    bullet("Conservar este informe como evidencia para el proceso de auditoría QSA."),
    spacer(1),
    pageBreak(),
  ];

  // ── 7. Metodología
  const methodSection = [
    h1("7. Metodología del Escaneo"),
    bodyText("El escaneo se realizó con las siguientes características técnicas:"),
    spacer(0),
    bullet(`Versión del escáner: PCI CardScan4Linux v${data.meta.scanner_version ?? "1.0.0"}`),
    bullet("Algoritmo de validación: Luhn (ISO/IEC 7812) para eliminar falsos positivos."),
    bullet("Detección de binarios: por extensión de archivo (.gz, .whl, .deb, etc.) y análisis de bytes."),
    bullet("Tamaño máximo de archivo: 50 MB por archivo individual."),
    bullet("Expresiones regulares aplicadas: Visa (16d), Mastercard (16d), Amex (15d), Discover (16d), Diners (14d), JCB (15-16d)."),
    bullet("Máscara de PAN en registros: primeros 6 + últimos 4 dígitos visibles (PCI DSS Req. 3.3.1)."),
    spacer(1),
    para(new TextRun({
      text: "Nota: Este escaneo detecta PAN en archivos de texto accesibles desde el sistema de ficheros. " +
            "No cubre bases de datos en ejecución, memorias de procesos, o almacenamiento cifrado montado. " +
            "Se recomienda complementar con escaneo de bases de datos y análisis de tráfico de red.",
      font: "Arial", size: 20, italic: true, color: COLORS.textGray
    }), { spacing: { after: 120 } }),
  ];

  // ─────────────────────────────────────────────────────────────────────────
  //  Assemble Document
  // ─────────────────────────────────────────────────────────────────────────

  const doc = new Document({
    styles: {
      default: { document: { run: { font: "Arial", size: 22 } } },
      paragraphStyles: [
        {
          id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
          run: { size: 32, bold: true, font: "Arial", color: COLORS.navy },
          paragraph: { spacing: { before: 360, after: 180 }, outlineLevel: 0 }
        },
        {
          id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
          run: { size: 26, bold: true, font: "Arial", color: COLORS.navy },
          paragraph: { spacing: { before: 240, after: 120 }, outlineLevel: 1 }
        },
      ]
    },
    numbering: {
      config: [{
        reference: "bullets",
        levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 720, hanging: 360 } } } }]
      }]
    },
    sections: [{
      properties: {
        page: {
          size: { width: 11906, height: 16838 }, // A4
          margin: { top: 1134, right: 1134, bottom: 1134, left: 1134 } // 2cm margins
        }
      },
      headers: {
        default: new Header({
          children: [
            new Paragraph({
              children: [
                new TextRun({ text: "INFORME DE AUDITORÍA PCI DSS  |  ", font: "Arial", size: 18, color: COLORS.textGray }),
                new TextRun({ text: meta.hostname, font: "Arial", size: 18, bold: true, color: COLORS.navy }),
                new TextRun({ text: `  |  ${new Date(meta.scan_end).toLocaleDateString("es-ES")}`, font: "Arial", size: 18, color: COLORS.textGray }),
              ],
              border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: COLORS.navy, space: 1 } },
            })
          ]
        })
      },
      footers: {
        default: new Footer({
          children: [
            new Paragraph({
              alignment: AlignmentType.CENTER,
              border: { top: { style: BorderStyle.SINGLE, size: 4, color: COLORS.borderGray, space: 1 } },
              children: [
                new TextRun({ text: "CONFIDENCIAL — Documento de auditoría PCI DSS. Distribución restringida.  |  Página ", font: "Arial", size: 16, color: COLORS.textGray }),
                new TextRun({ children: [PageNumber.CURRENT], font: "Arial", size: 16, color: COLORS.textGray }),
                new TextRun({ text: " de ", font: "Arial", size: 16, color: COLORS.textGray }),
                new TextRun({ children: [PageNumber.TOTAL_PAGES], font: "Arial", size: 16, color: COLORS.textGray }),
              ]
            })
          ]
        })
      },
      children: [
        ...coverPage,
        ...execSummary,
        ...statsSection,
        ...findingsSection,
        ...excludedSection,
        ...normativeSection,
        ...recoSection,
        ...methodSection,
      ]
    }]
  });

  return doc;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Entry Point
// ─────────────────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
if (args.length === 0) {
  console.error("Usage: node pci_report_generator.js <results.json> [--output report.docx]");
  process.exit(1);
}

const inputFile  = args[0];
const outputIdx  = args.indexOf("--output");
const outputFile = outputIdx !== -1 ? args[outputIdx + 1] : "pci_audit_report.docx";

if (!fs.existsSync(inputFile)) {
  console.error(`[ERROR] Input file not found: ${inputFile}`);
  process.exit(1);
}

const data = JSON.parse(fs.readFileSync(inputFile, "utf-8"));
console.log(`Generating report from ${inputFile}...`);

const doc = buildReport(data);

Packer.toBuffer(doc).then(buffer => {
  fs.writeFileSync(outputFile, buffer);
  console.log(`Report saved: ${outputFile}`);
}).catch(err => {
  console.error("Error generating report:", err);
  process.exit(1);
});
