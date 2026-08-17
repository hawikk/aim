// Minimal dependency-free text-to-PDF renderer.
//
// The executive governance report must be exportable as a PDF without adding
// a rendering dependency (no headless browser in the image). The report's
// content is tabular text, so a line-based renderer over the PDF base-14
// Courier font is sufficient: fixed-width font ⇒ column alignment is plain
// string padding, and the layout is fully deterministic (same lines in ⇒
// byte-identical layout out, which keeps exported PDFs diffable alongside
// the stored report JSON).
//
// Scope, deliberately: single font (Courier), one font size, Letter pages,
// latin-1 text only (anything else is replaced with '?'). No compression, no
// images. This is a document-export path, not a general PDF library.

const PAGE_W = 612; // Letter, points
const PAGE_H = 792;
const MARGIN = 50;
const FONT_SIZE = 9;
const LINE_HEIGHT = 12;
const LINES_PER_PAGE = Math.floor((PAGE_H - 2 * MARGIN) / LINE_HEIGHT); // 57

// PDF string escaping + latin-1 sanitization.
function pdfText(s) {
  const clean = String(s).replace(/[^\x20-\x7E\xA0-\xFF]/g, '?');
  return clean.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
}

// Render one page's content stream: each line as an absolute-positioned Tj.
function pageStream(lines) {
  const parts = [`BT /F1 ${FONT_SIZE} Tf ${LINE_HEIGHT} TL`];
  lines.forEach((line, i) => {
    const y = PAGE_H - MARGIN - i * LINE_HEIGHT;
    parts.push(`1 0 0 1 ${MARGIN} ${y} Tm (${pdfText(line)}) Tj`);
  });
  parts.push('ET');
  return parts.join('\n');
}

// lines: string[] (already wrapped to fit ~95 cols). title: optional metadata.
// Returns a Buffer holding a complete, valid PDF 1.4 document.
export function textToPdf(lines, { title } = {}) {
  const pages = [];
  for (let i = 0; i < lines.length; i += LINES_PER_PAGE) {
    pages.push(lines.slice(i, i + LINES_PER_PAGE));
  }
  if (pages.length === 0) pages.push([]);

  // Object layout: 1 catalog, 2 pages, 3 font, then per page a page object
  // and its content stream. Info object last.
  const objects = [];
  const pageCount = pages.length;
  const pageObjStart = 4;
  const infoObj = pageObjStart + pageCount * 2;

  objects[1] = '<< /Type /Catalog /Pages 2 0 R >>';
  objects[2] = `<< /Type /Pages /Kids [${pages.map((_, i) => `${pageObjStart + i * 2} 0 R`).join(' ')}] /Count ${pageCount} >>`;
  objects[3] = '<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>';
  pages.forEach((pageLines, i) => {
    const pageObj = pageObjStart + i * 2;
    const contentObj = pageObj + 1;
    objects[pageObj] =
      `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PAGE_W} ${PAGE_H}] ` +
      `/Resources << /Font << /F1 3 0 R >> >> /Contents ${contentObj} 0 R >>`;
    const stream = pageStream(pageLines);
    objects[contentObj] = `<< /Length ${Buffer.byteLength(stream, 'latin1')} >>\nstream\n${stream}\nendstream`;
  });
  objects[infoObj] = `<< /Producer (aim-api governance report)${title ? ` /Title (${pdfText(title)})` : ''} >>`;

  // Serialize with a real xref table (offsets in bytes).
  let out = '%PDF-1.4\n';
  const offsets = [0];
  for (let i = 1; i <= infoObj; i++) {
    offsets[i] = Buffer.byteLength(out, 'latin1');
    out += `${i} 0 obj\n${objects[i]}\nendobj\n`;
  }
  const xrefStart = Buffer.byteLength(out, 'latin1');
  out += `xref\n0 ${infoObj + 1}\n`;
  out += '0000000000 65535 f \n';
  for (let i = 1; i <= infoObj; i++) {
    out += `${String(offsets[i]).padStart(10, '0')} 00000 n \n`;
  }
  out += `trailer\n<< /Size ${infoObj + 1} /Root 1 0 R /Info ${infoObj} 0 R >>\nstartxref\n${xrefStart}\n%%EOF\n`;
  return Buffer.from(out, 'latin1');
}
