"""Render the investor technical whitepaper with repeatable print styling."""
from pathlib import Path
import re
from html import escape
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.platypus import (BaseDocTemplate, PageTemplate, Frame, Paragraph,
    Spacer, PageBreak, CondPageBreak, Table, TableStyle, Preformatted, KeepTogether)
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'docs/whitepaper.md'
OUTPUT = ROOT / 'output/pdf/Common-Foundry-Technical-Whitepaper-v0.4.pdf'
OUTPUT.parent.mkdir(parents=True, exist_ok=True)
FONTDIR = Path('C:/Windows/Fonts')
for name, file in [('Body','segoeui.ttf'),('Bold','segoeuib.ttf'),('Italic','segoeuii.ttf'),('Mono','consola.ttf')]:
    pdfmetrics.registerFont(TTFont(name, str(FONTDIR/file)))
pdfmetrics.registerFontFamily('Body', normal='Body', bold='Bold', italic='Italic', boldItalic='Bold')
INK=colors.HexColor('#172B36'); COPPER=colors.HexColor('#AD642E')
MUTED=colors.HexColor('#536773'); PALE=colors.HexColor('#F2F5F6')
W,H=595.276,841.89; M=48; CW=W-2*M
styles={
 'body':ParagraphStyle('body',fontName='Body',fontSize=10,leading=15,textColor=INK,spaceAfter=9),
 'h1':ParagraphStyle('h1',fontName='Bold',fontSize=18,leading=23,textColor=INK,spaceBefore=18,spaceAfter=12,keepWithNext=True),
 'h2':ParagraphStyle('h2',fontName='Bold',fontSize=11.5,leading=16,textColor=COPPER,spaceBefore=12,spaceAfter=7,keepWithNext=True),
 'cell':ParagraphStyle('cell',fontName='Body',fontSize=8.6,leading=12.3,textColor=INK),
 'th':ParagraphStyle('th',fontName='Bold',fontSize=8.6,leading=12.3,textColor=colors.white),
 'code':ParagraphStyle('code',fontName='Mono',fontSize=8,leading=11,textColor=INK,backColor=PALE,borderPadding=9,spaceBefore=3,spaceAfter=11),
 'small':ParagraphStyle('small',fontName='Body',fontSize=8,leading=11.5,textColor=MUTED,spaceAfter=6),
 'toc':ParagraphStyle('toc',fontName='Body',fontSize=11,leading=20,spaceBefore=5,textColor=INK),
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
    c.setFont('Body',8); c.drawRightString(W-M,H-27,'TECHNICAL WHITEPAPER  /  MAINNET LAUNCH EDITION')
    c.line(M,37,W-M,37); c.drawString(M,24,'Version 0.4  |  Inference first. Built to lead.')
    c.drawRightString(W-M,24,str(doc.page)); c.restoreState()

class Cover(Spacer):
    def __init__(self):super().__init__(1,690)
    def draw(self):
        c=self.canv
        c.setFillColor(COPPER); c.rect(0,673,48,5,fill=1,stroke=0)
        c.setFont('Bold',14); c.setFillColor(INK); c.drawString(0,646,'COMMON FOUNDRY')
        c.setFont('Body',10); c.setFillColor(MUTED)
        c.drawString(0,625,'TECHNICAL WHITEPAPER  /  MAINNET LAUNCH EDITION')
        art=ROOT/'apps/website/public/assets/common-foundry-inference-first.png'
        c.drawImage(ImageReader(str(art)),0,285,width=CW,height=318,preserveAspectRatio=True,anchor='c',mask='auto')
        p=Paragraph('The operator-first route<br/>to open inference.',ParagraphStyle('cover-title',fontName='Bold',fontSize=25,leading=31,textColor=INK))
        _,ph=p.wrap(CW,100); p.drawOn(c,0,257-ph)
        p=Paragraph('Compute-oriented mining. CPU-verifiable work. Direct service settlement. A technical foundation built for people who operate GPUs and the applications they can power.',ParagraphStyle('covertext',fontName='Body',fontSize=12,leading=18,textColor=MUTED))
        _,ph=p.wrap(CW,90); p.drawOn(c,0,170-ph)
        c.setStrokeColor(COPPER); c.line(0,80,CW,80)
        c.setFillColor(INK); c.setFont('Bold',10)
        c.drawString(0,59,'SOURCE: OCTOBER 2'); c.drawRightString(CW,59,'MINING: OCTOBER 3')
        c.setFillColor(MUTED); c.setFont('Body',9)
        c.drawString(0,42,'2026  |  Both at noon CDT / 17:00 UTC  |  Planned launch schedule')
        c.drawString(0,17,'Version 0.4  |  September 24, 2026  |  commonfoundry.ai')

class WhitepaperDocument(BaseDocTemplate):
    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph) and flowable.style.name=='h1' and getattr(flowable,'toc_entry',False):
            label=flowable.getPlainText()
            key='section-'+str(getattr(flowable,'section_number',0))
            self.canv.bookmarkPage(key)
            self.canv.addOutlineEntry(label,key,0,False)
            self.notify('TOCEntry',(0,label,self.page,key))

text=SOURCE.read_text(encoding='utf-8')
body=text[text.index('## 1. '):]
story=[Cover(),PageBreak(),Paragraph('Inside this edition',styles['h1'])]
toc=TableOfContents(); toc.levelStyles=[styles['toc']]; toc.dotsMinLevel=0
story.append(toc)
story += [Spacer(1,20),Paragraph('How to read this paper',styles['h2']),Paragraph('Start with Sections 1-2 for the proposition. Sections 3-6 explain the computation, proof and shared launch. Sections 7-9 cover money, inference settlement and operator software. Sections 10-11 separate demonstrated results from the next product milestones. The appendices provide exact parameters and evidence pointers.',styles['body']),Paragraph('Launch status - September 24, 2026',styles['h2']),Paragraph('Mainnet is not live yet. Source and launch packages are planned for October 2 at noon CDT / 17:00 UTC; mining is planned for October 3 at the same time. Final package and deployment checks remain in progress. Customer-paid inference is in development, not a feature of the initial mainnet launch.',styles['body']),PageBreak()]
lines=body.splitlines();i=0;section_number=0
while i<len(lines):
    line=lines[i].strip()
    if not line or line=='---':i+=1;continue
    if line.startswith('## '):
        if section_number:
            story.append(PageBreak() if line.startswith('## Appendix A') else CondPageBreak(220))
        section_number+=1
        heading=Paragraph(inline(line[3:]),styles['h1']); heading.toc_entry=True; heading.section_number=section_number
        story.append(heading);i+=1;continue
    if line.startswith('### '):
        story.append(CondPageBreak(180))
        story.append(Paragraph(inline(line[4:]),styles['h2']));i+=1;continue
    if line.startswith('```'):
        block=[];i+=1
        while i<len(lines) and not lines[i].startswith('```'):block.append(lines[i]);i+=1
        story.append(KeepTogether([Preformatted('\n'.join(block),styles['code'],maxLineLength=86)]));i+=1;continue
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

doc=WhitepaperDocument(str(OUTPUT),pagesize=(W,H),leftMargin=M,rightMargin=M,topMargin=51,bottomMargin=51,title='Common Foundry - Inference First. Built to Lead.',author='Common Foundry',subject='Technical Whitepaper v0.4 - Mainnet Launch Edition, September 24, 2026')
doc.addPageTemplates(PageTemplate(id='main',frames=[Frame(M,51,CW,H-102,leftPadding=0,rightPadding=0,topPadding=0,bottomPadding=0)],onPage=footer))
doc.multiBuild(story)
print(OUTPUT)


