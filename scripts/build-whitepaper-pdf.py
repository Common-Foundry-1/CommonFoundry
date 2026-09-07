"""Render the investor technical whitepaper with repeatable print styling."""
from pathlib import Path
import re
from html import escape
from reportlab.pdfgen import canvas
from reportlab.platypus import (BaseDocTemplate, PageTemplate, Frame, Paragraph,
    Spacer, PageBreak, Table, TableStyle, Preformatted, KeepTogether)
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'docs/whitepaper.md'
OUTPUT = ROOT / 'output/pdf/Common-Foundry-Technical-Whitepaper-v0.3.pdf'
OUTPUT.parent.mkdir(parents=True, exist_ok=True)
FONTDIR = Path('C:/Windows/Fonts')
for name, file in [('Body','segoeui.ttf'),('Bold','segoeuib.ttf'),('Italic','segoeuii.ttf'),('Mono','consola.ttf')]:
    pdfmetrics.registerFont(TTFont(name, str(FONTDIR/file)))
pdfmetrics.registerFontFamily('Body', normal='Body', bold='Bold', italic='Italic', boldItalic='Bold')
INK=colors.HexColor('#172B36'); COPPER=colors.HexColor('#AD642E')
MUTED=colors.HexColor('#536773'); PALE=colors.HexColor('#F2F5F6')
W,H=595.276,841.89; M=48; CW=W-2*M
styles={
 'body':ParagraphStyle('body',fontName='Body',fontSize=9.5,leading=14.3,textColor=INK,spaceAfter=8),
 'h1':ParagraphStyle('h1',fontName='Bold',fontSize=18,leading=23,textColor=INK,spaceBefore=18,spaceAfter=12,keepWithNext=True),
 'h2':ParagraphStyle('h2',fontName='Bold',fontSize=11.5,leading=16,textColor=COPPER,spaceBefore=12,spaceAfter=7,keepWithNext=True),
 'cell':ParagraphStyle('cell',fontName='Body',fontSize=8.1,leading=11.5,textColor=INK),
 'th':ParagraphStyle('th',fontName='Bold',fontSize=8.1,leading=11.5,textColor=colors.white),
 'code':ParagraphStyle('code',fontName='Mono',fontSize=8,leading=11,textColor=INK,backColor=PALE,borderPadding=9,spaceBefore=3,spaceAfter=11),
 'small':ParagraphStyle('small',fontName='Body',fontSize=8,leading=11.5,textColor=MUTED,spaceAfter=6),
 'toc':ParagraphStyle('toc',fontName='Body',fontSize=11,leading=24,textColor=INK),
}

def inline(t):
    t=escape(t)
    t=re.sub(r'`([^`]+)`',r'<font name="Mono" size="8">\1</font>',t)
    t=re.sub(r'\*\*([^*]+)\*\*',r'<b>\1</b>',t)
    t=re.sub(r'(https://[^\s<]+)',r'<link href="\1" color="#AD642E">\1</link>',t)
    return t

def footer(c,doc):
    if doc.page==1:return
    c.saveState(); c.setStrokeColor(colors.HexColor('#D9E1E4'))
    c.line(M, H-36, W-M, H-36)
    c.setFont('Bold',8); c.setFillColor(MUTED)
    c.drawString(M,H-27,'COMMON FOUNDRY')
    c.setFont('Body',8); c.drawRightString(W-M,H-27,'TECHNICAL WHITEPAPER  /  SEPTEMBER 2026')
    c.line(M,37,W-M,37); c.drawString(M,24,'Version 0.3  |  Open compute. Verifiable work. Direct settlement.')
    c.drawRightString(W-M,24,str(doc.page)); c.restoreState()

class Cover(Spacer):
    def __init__(self):super().__init__(1,690)
    def draw(self):
        c=self.canv; y=660
        c.setFillColor(COPPER);c.rect(0,y-5,48,5,fill=1,stroke=0)
        c.setFont('Bold',12);c.drawString(0,y-38,'COMMON FOUNDRY')
        c.setFillColor(INK);c.setFont('Bold',35)
        for i,line in enumerate(['Open Compute,','Verifiable Work,','Direct Settlement']):c.drawString(0,y-112-i*46,line)
        c.setFillColor(MUTED);c.setFont('Body',13)
        c.drawString(0,y-245,'Technical Whitepaper  |  Version 0.3')
        c.setFont('Body',11);c.drawString(0,y-268,'September 7, 2026')
        p=Paragraph('Matrix-oriented proof of work, transparent verification, and a direct settlement foundation for GPU services.',ParagraphStyle('covertext',fontName='Body',fontSize=15,leading=23,textColor=INK))
        p.wrap(CW-30,100);p.drawOn(c,0,y-390)
        cells=[('384','sequential layers'),('6.093 s','RTX 5090 online proof'),('RCNet-1','live release candidate')]
        for i,(a,b) in enumerate(cells):
            x=i*CW/3;c.setFillColor(PALE);c.rect(x,y-520,CW/3-8,79,fill=1,stroke=0)
            c.setFillColor(COPPER);c.setFont('Bold',18);c.drawString(x+11,y-470,a)
            c.setFillColor(MUTED);c.setFont('Body',8);c.drawString(x+11,y-491,b)
        p=Paragraph('A technical foundation for an open operator ecosystem.\nMeasured software, consumer GPUs, and a defined path to service-market deployment.',styles['small'])
        p.wrap(CW,70);p.drawOn(c,0,30)

text=SOURCE.read_text(encoding='utf-8')
body=text[text.index('## 1. Executive thesis'):]
story=[Cover(),PageBreak(),Paragraph('Inside this edition',styles['h1'])]
for line in body.splitlines():
    if line.startswith('## '):story.append(Paragraph(inline(line[3:]),styles['toc']))
story += [Spacer(1,24),Paragraph('Reading guide',styles['h2']),Paragraph('Sections 1-2 explain the commercial thesis and adoption sequence. Sections 3-6 describe the active technology and operating evidence. Sections 7-9 cover monetary design, service settlement, and execution. The appendices collect protocol parameters and source notes.',styles['body']),PageBreak()]
lines=body.splitlines();i=0
while i<len(lines):
    line=lines[i].strip()
    if not line or line=='---':i+=1;continue
    if line.startswith('## '):
        if line.startswith('## Appendix B'):story.append(PageBreak())
        story.append(Paragraph(inline(line[3:]),styles['h1']));i+=1;continue
    if line.startswith('### '):story.append(Paragraph(inline(line[4:]),styles['h2']));i+=1;continue
    if line.startswith('```'):
        block=[];i+=1
        while i<len(lines) and not lines[i].startswith('```'):block.append(lines[i]);i+=1
        story.append(KeepTogether([Preformatted('\n'.join(block),styles['code'],maxLineLength=88)]));i+=1;continue
    if line.startswith('|'):
        rows=[]
        while i<len(lines) and lines[i].strip().startswith('|'):
            cells=[x.strip() for x in lines[i].strip().strip('|').split('|')]
            if not all(re.fullmatch(r'[:\- ]+',x) for x in cells):rows.append(cells)
            i+=1
        n=len(rows[0]);ratios={2:[.39,.61],3:[.25,.37,.38],4:[.31,.23,.25,.21],5:[.20]*5}[n]
        data=[[Paragraph(inline(x),styles['th'] if r==0 else styles['cell']) for x in row] for r,row in enumerate(rows)]
        table=Table(data,colWidths=[CW*x for x in ratios],repeatRows=1,hAlign='LEFT')
        table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),INK),('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),8),('RIGHTPADDING',(0,0),(-1,-1),8),('TOPPADDING',(0,0),(-1,-1),7),('BOTTOMPADDING',(0,0),(-1,-1),7),('ROWBACKGROUNDS',(0,1),(-1,-1),[PALE,colors.white]),('LINEBELOW',(0,0),(-1,0),1,COPPER)]))
        story.extend([table,Spacer(1,10)]);continue
    para=[line];i+=1
    while i<len(lines) and lines[i].strip() and not re.match(r'^(#|\||```|\d+\. )',lines[i]):para.append(lines[i].strip());i+=1
    story.append(Paragraph(inline(' '.join(para)),styles['body']))

doc=BaseDocTemplate(str(OUTPUT),pagesize=(W,H),leftMargin=M,rightMargin=M,topMargin=51,bottomMargin=51,title='Common Foundry - Open Compute, Verifiable Work, Direct Settlement',author='Common Foundry',subject='Technical Whitepaper v0.3 - September 2026')
doc.addPageTemplates(PageTemplate(id='main',frames=[Frame(M,51,CW,H-102,leftPadding=0,rightPadding=0,topPadding=0,bottomPadding=0)],onPage=footer))
doc.build(story)
print(OUTPUT)


