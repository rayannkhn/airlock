"""Build docs/AirLock_Report.docx from docs/report.md.

    python tools/build_report.py

Needs pandoc. The styling (fonts, heading colours, table borders) lives in
tools/report-reference.docx. Edit docs/report.md, then re-run this script.
"""
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
lines = (ROOT / 'docs' / 'report.md').read_text(encoding='utf-8').split('\n')
PB = '\n```{=openxml}\n<w:p><w:r><w:br w:type="page"/></w:r></w:p>\n```\n'
out = []; i = 0
def cells(row): return [c.strip() for c in row.strip().strip('|').split('|')]
while i < len(lines):
    ln = lines[i]
    if ln.strip() == '---':
        i += 1; continue
    if re.match(r'^\*\*(Course|Author|Date):\*\*', ln):
        out.append(ln.rstrip() + '\\'); i += 1; continue
    if ln.startswith('## Abstract') or ln.startswith('## References') or ln.startswith('## Appendix A'):
        out.append(PB)
    m = re.match(r'!\[(.*?)\]\((.*?)\)\s*$', ln)
    if m:
        out.append(f'![{m.group(1)}]({m.group(2)}){{width=6.2in}}'); i += 1; continue
    if ln.startswith('|') and i + 1 < len(lines) and re.match(r'^\|[\s:|-]+\|\s*$', lines[i + 1]):
        j = i; block = []
        while j < len(lines) and lines[j].startswith('|'):
            block.append(lines[j]); j += 1
        rows = [cells(r) for k, r in enumerate(block) if k != 1]
        def need(c):
            texts = [re.sub(r'[*`\[\]]', '', r[c]) for r in rows if c < len(r)]
            word = max((len(w) for t in texts for w in t.split()), default=6)
            cell = max((len(t) for t in texts), default=6)
            return int(word * 1.5 + min(cell, 60) * 0.6) + 2   # longest word must fit unbroken
        widths = [need(c) for c in range(len(rows[0]))]
        out.append(block[0]); out.append('|' + '|'.join('-' * w for w in widths) + '|'); out.extend(block[2:])
        i = j; continue
    out.append(ln); i += 1
with tempfile.TemporaryDirectory() as tmp:
    pre = Path(tmp) / "report_pre.md"
    pre.write_text("\n".join(out), encoding="utf-8")
    target = ROOT / "docs" / "AirLock_Report.docx"
    subprocess.run([
        "pandoc", str(pre),
        "-f", "markdown+pipe_tables+lists_without_preceding_blankline-implicit_figures",
        "-t", "docx", "--columns=30", "--shift-heading-level-by=-1",
        f"--resource-path={ROOT / 'docs'}",
        f"--reference-doc={ROOT / 'tools' / 'report-reference.docx'}",
        "-o", str(target),
    ], check=True)
    # Drop folder entries from the ZIP: Word has refused files containing them when
    # they are opened through a cloud co-editing service.
    import zipfile
    clean = Path(tmp) / "clean.docx"
    with zipfile.ZipFile(target) as src, zipfile.ZipFile(clean, "w", zipfile.ZIP_DEFLATED) as dst:
        for item in src.infolist():
            if not item.filename.endswith("/"):
                dst.writestr(item, src.read(item.filename))
    import shutil
    shutil.move(str(clean), str(target))  # works across filesystems, unlike Path.replace
    print(f"wrote {target}")
