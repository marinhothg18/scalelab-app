#!/usr/bin/env python3
"""Aplica a marca SCALROI (nome, logo e cores) no código do sistema.
Roda na raiz do repositório: python3 aplicar-marca.py
Pode rodar de novo em cima de um main mais novo (só troca o que ainda está com a marca antiga)."""
import re, os, sys, base64, subprocess

RAIZ = os.getcwd()
AQUI = os.path.dirname(os.path.abspath(__file__))
ICONE_ORIGEM = os.path.join(AQUI, 'marca-scalroi-icone.jpg')     # 1254x1254, o "S" com a seta
LOGO_ORIGEM = os.path.join(AQUI, 'marca-scalroi-logo.jpg')       # 1600x533, SCALROI por extenso

def ler(p): return open(os.path.join(RAIZ, p), encoding='utf-8').read()
def gravar(p, s): open(os.path.join(RAIZ, p), 'w', encoding='utf-8').write(s)

# ── cores: de (TMX) → para (SCALROI) ──
HEX = {
  '#3E1493': '#0E9F35', '#2509E4': '#15803D', '#1B9CFA': '#16A34A', '#5b5ef4': '#16A34A',
  '#4F46E5': '#050A18', '#C52C58': '#E5484D', '#FF5926': '#F59E0B', '#080a12': '#050A18',
  '#6366F1': '#0EA5E9', '#818CF8': '#38BDF8', '#a5a7ff': '#86EFAC', '#7C3AED': '#15803D',
  '#1a1040': '#0B2A1A', '#07060F': '#050A18',
  '#8B6CFF': '#7CFF5A', '#5B7CFF': '#22D94A', '#5EB8FF': '#4ADE80',
  '#111524': '#0B1426', '#171b2e': '#121D33', '#0a0c16': '#050A18', '#8b93ab': '#94A3B8', '#5f6884': '#64748B',
}
RGBA = {
  (27, 156, 250): (22, 163, 74), (91, 94, 244): (22, 163, 74), (62, 20, 147): (14, 159, 53),
  (37, 9, 228): (21, 128, 61), (79, 70, 229): (5, 10, 24), (197, 44, 88): (229, 72, 77),
  (255, 89, 38): (245, 158, 11), (99, 102, 241): (14, 165, 233),
}
def trocar_cores(s):
  for de, para in HEX.items():
    s = re.sub(re.escape(de) + r'(?![0-9a-fA-F])', para, s, flags=re.I)
  for de, para in RGBA.items():
    s = re.sub(r'rgba\(\s*%d\s*,\s*%d\s*,\s*%d\s*,' % de, 'rgba(%d,%d,%d,' % para, s)
  return s

ICONE = '/marca/scalroi-icone.png'

def por_css(s, css):
  """Põe o bloco <style id="marca-scalroi"> antes do </head>, trocando o que já existir."""
  s = re.sub(r'<style id="marca-scalroi">.*?</style>\n?', '', s, flags=re.S)
  return s.replace('</head>', css + '</head>', 1)

def sistema():
  p = 'public/ScaleLab.html'; s = ler(p)
  s = s.replace('<title>TMX Digital</title>', '<title>SCALROI</title>')
  # tema claro: destaque verde-escuro (texto branco legível em cima)
  s = s.replace('--accent: #0284C7; --accent2: #059669;', '--accent: #15803D; --accent2: #16A34A;')
  s = s.replace('--accent-grad: linear-gradient(135deg,#0284C7,#38BDF8);', '--accent-grad: linear-gradient(135deg,#15803D,#16A34A);')
  s = s.replace('--blue: #0284C7; --purple:', '--blue: #15803D; --purple:')   # no claro, o 'azul' é a cor de ação
  s = trocar_cores(s)
  # logo do menu
  s = s.replace('<span class="logo-tmx">TMX</span>\n      <span class="logo-text" style="font-size:12px;font-weight:700;letter-spacing:2.5px;color:var(--text2);align-self:center;padding-top:4px;">DIGITAL</span>',
                '<img class="logo-ic" src="' + ICONE + '" alt="">\n      <span class="logo-tmx">SCAL<span class="logo-roi">ROI</span></span>')
  # logo da tela de entrar
  s = s.replace('<div class="login-logo-text" style="font-size:40px;letter-spacing:-1px;">TMX</div>\n      <div style="font-size:14px;font-weight:700;letter-spacing:4px;color:var(--text2);align-self:center;padding-top:8px;">DIGITAL</div>',
                '<img src="' + ICONE + '" alt="" style="width:52px;height:52px;border-radius:13px">\n      <div class="login-logo-text scal" style="font-size:40px;letter-spacing:-1px;">SCAL<span>ROI</span></div>')
  s = s.replace('TMX Digital', 'SCALROI')
  # tema escuro na pegada do esboço: verde neon do logo com texto escuro em cima
  base = re.sub(r'<style id="marca-scalroi">.*?</style>', '', s, flags=re.S)
  regras = ''.join(re.findall(r'<style[^>]*>(.*?)</style>', base, re.S))
  sels = set()
  for m in re.finditer(r'([^{}]+)\{([^{}]*)\}', regras):
    sel, corpo = m.group(1).strip(), m.group(2)
    if re.search(r'background(?:-color)?\s*:\s*var\(--(accent|accent-grad|blue|accent2|purple)\)', corpo) and re.search(r'(^|;)\s*color\s*:\s*(#fff|#ffffff|white)\b', corpo, re.I):
      for x in sel.split(','):
        x = re.sub(r'/\*.*?\*/', '', x, flags=re.S).strip()
        if x and not x.startswith('.light-mode') and not x.startswith('@') and x != '.nav-item.active':
          sels.add(x)
  inl = []
  for v in ('accent', 'accent-grad', 'blue', 'accent2', 'purple'):
    inl += ['[style*="background:var(--%s)"]' % v, '[style*="background: var(--%s)"]' % v]
  escuro = ',\n'.join('body:not(.light-mode) ' + x for x in sorted(sels) + inl)
  claro = ',\n'.join('body.light-mode ' + x for x in sorted(sels) + inl)
  css_escuro = (':root{--accent:#22D94A;--accent2:#22D94A;--accent-grad:linear-gradient(135deg,#22D94A,#7CFF5A);--blue:#22D94A;--purple:#22D94A;--green:#4ADE80;--red:#F87171;--sidebar-bg:#0B1426;--text2:#94A3B8;--text3:#64748B}\n'
    + escuro + '{color:#04210E !important}\n'
    + 'body:not(.light-mode) .nav-item.active{background:rgba(34,217,74,.14) !important;color:#7CFF5A !important;box-shadow:inset 3px 0 0 #22D94A !important}\n'
    + 'body:not(.light-mode) .nav-item.active .nav-svg{stroke:#7CFF5A !important}\n'
    + 'body:not(.light-mode) .btn-primary,body:not(.light-mode) .login-btn{box-shadow:0 8px 24px rgba(34,217,74,.28) !important;font-weight:700}\n'
    + 'body:not(.light-mode) .card,body:not(.light-mode) .stat-card{border-color:rgba(255,255,255,.08)}\n'
    + claro + '{background:linear-gradient(135deg,#22D94A,#7CFF5A) !important;color:#04210E !important;border-color:transparent !important}\n'
    + 'body.light-mode .btn-primary,body.light-mode .login-btn{box-shadow:0 6px 18px rgba(34,217,74,.30) !important;font-weight:700}\n')
  css = ('<style id="marca-scalroi">\n/* Marca SCALROI: ícone + nome (SCAL na cor do texto, ROI em verde) */\n' + css_escuro +

    '.logo-ic{width:30px;height:30px;border-radius:8px;flex:none;display:block}\n'
    '.logo-tmx{background:none !important;-webkit-text-fill-color:currentColor !important;color:var(--text) !important;font-size:21px !important;font-weight:900 !important;letter-spacing:-.3px !important}\n'
    '.logo-roi{color:#22D94A;-webkit-text-fill-color:#22D94A}\n.light-mode .logo-roi{color:#16A34A;-webkit-text-fill-color:#16A34A}\n'
    '.sidebar.collapsed .logo-tmx{display:none !important}\n'
    '.login-logo-text.scal{background:none !important;-webkit-text-fill-color:#fff !important;color:#fff;font-weight:900}\n'
    '.login-logo-text.scal span{color:#22D94A;-webkit-text-fill-color:#22D94A}\n</style>\n')
  s = por_css(s, css)
  gravar(p, s)

def central():
  p = 'public/admin.html'; s = ler(p)
  s = trocar_cores(s)
  s = s.replace('<title>Central TMX Admin</title>', '<title>Central SCALROI</title>')
  s = s.replace('<div class="logo">TMX</div>', '<img class="logo" src="' + ICONE + '" alt="">')
  s = s.replace('<b>Central TMX</b>', '<b>Central SCAL<i>ROI</i></b>')
  s = s.replace('Abrindo a Central TMX Admin…', 'Abrindo a Central SCALROI…')
  css = '<style id="marca-scalroi">.marca .logo{object-fit:cover;background:none !important;box-shadow:none !important}.marca b i{font-style:normal;color:#22D94A}</style>\n'
  s = por_css(s, css)
  gravar(p, s)

def planos():
  p = 'public/planos.html'; s = ler(p)
  s = trocar_cores(s)
  s = re.sub(r'<title>[^<]*</title>', '<title>Planos · SCALROI</title>', s, count=1)
  s = s.replace('aria-label="TMX Digital"><b>TMX</b><span>DIGITAL</span>', 'aria-label="SCALROI"><img src="' + ICONE + '" alt=""><b>SCAL<em>ROI</em></b>')
  s = s.replace('<div class="lg"><b>TMX</b><span>DIGITAL</span></div>', '<div class="lg"><img src="' + ICONE + '" alt=""><b>SCAL<em>ROI</em></b></div>')
  s = s.replace('TMX Digital', 'SCALROI')
  css = ('<style id="marca-scalroi">\n/* Identidade SCALROI na página de vendas: marinho do logo, verde neon da seta, grade de dados */\n'
    ':root{--bg:#050A18;--bg2:#071027;--painel:#0A1430;--linha:rgba(124,255,90,.10);--linha2:rgba(255,255,255,.14);--azul:#22D94A;--azul2:#7CFF5A;--ok:#22D94A;--grad:linear-gradient(135deg,#22D94A,#7CFF5A)}\n'
    'body{background:radial-gradient(1100px 620px at 88% -8%,rgba(34,217,74,.16),transparent 60%),radial-gradient(900px 560px at -12% 35%,rgba(37,99,235,.13),transparent 62%),#050A18;background-attachment:fixed}\n'
    '.cab{background:rgba(5,10,24,.82) !important;border-bottom-color:rgba(124,255,90,.14) !important}\n'
    '.logo{align-items:center !important}\n.logo img{width:32px;height:32px;border-radius:9px;flex:none;box-shadow:0 0 0 1px rgba(124,255,90,.25),0 6px 20px rgba(34,217,74,.25)}\n'
    '.lg{display:flex !important;align-items:center;gap:5px}\n.lg img{width:16px;height:16px;border-radius:4px;flex:none}\n'
    '.logo b,.lg b{background:none !important;-webkit-text-fill-color:currentColor !important;font-weight:900 !important}\n'
    '.logo b{color:#fff;font-size:24px !important;letter-spacing:-.02em !important}\n.lg b{color:#0F172A}\n'
    '.logo b em,.lg b em{font-style:normal;color:#22D94A;-webkit-text-fill-color:#22D94A}\n.lg b em{color:#16A34A;-webkit-text-fill-color:#16A34A}\n'
    '.btn{background:linear-gradient(135deg,#22D94A,#7CFF5A) !important;color:#04210E !important;font-weight:800 !important;box-shadow:0 10px 30px rgba(34,217,74,.32),inset 0 -2px 0 rgba(4,33,14,.18) !important}\n'
    '.btn:hover{filter:brightness(1.06) saturate(1.05)}\n'
    '.btn.contorno{background:rgba(255,255,255,.04) !important;color:#F5F6FB !important;border-color:rgba(124,255,90,.35) !important;box-shadow:none !important}\n'
    '.btn.contorno:hover{background:rgba(34,217,74,.10) !important;border-color:#22D94A !important}\n'
    '.rot{color:#7CFF5A !important;display:inline-flex;align-items:center;gap:8px}\n.rot::before{content:"";width:18px;height:2px;border-radius:2px;background:linear-gradient(90deg,#22D94A,#7CFF5A)}\n'
    '.hero{background:none !important;isolation:isolate}\n.hero .larg{position:relative;z-index:1}\n'
    '.hero::before{content:"";position:absolute;right:-6%;top:-14%;width:min(720px,70vw);aspect-ratio:1;background:url("data:image/svg+xml,%3Csvg xmlns=%27http://www.w3.org/2000/svg%27 viewBox=%270 0 100 100%27%3E%3Cdefs%3E%3ClinearGradient id=%27g%27 x1=%270%27 y1=%271%27 x2=%271%27 y2=%270%27%3E%3Cstop offset=%270%27 stop-color=%27%2322D94A%27 stop-opacity=%270%27/%3E%3Cstop offset=%271%27 stop-color=%27%237CFF5A%27/%3E%3C/linearGradient%3E%3C/defs%3E%3Cpath d=%27M8 92 L66 34 L56 24 L92 8 L76 44 L66 34%27 fill=%27none%27 stroke=%27url(%23g)%27 stroke-width=%279%27 stroke-linejoin=%27round%27 stroke-linecap=%27round%27/%3E%3C/svg%3E") no-repeat center/contain;opacity:.10;pointer-events:none;z-index:0}\n'
    '.hero::after{content:"";position:absolute;inset:0;z-index:0;pointer-events:none;background-image:linear-gradient(rgba(124,255,90,.05) 1px,transparent 1px),linear-gradient(90deg,rgba(124,255,90,.05) 1px,transparent 1px);background-size:56px 56px;-webkit-mask-image:radial-gradient(800px 480px at 72% 30%,#000,transparent 72%);mask-image:radial-gradient(800px 480px at 72% 30%,#000,transparent 72%)}\n'
    '.hero h1 em{background:linear-gradient(120deg,#22D94A,#7CFF5A) !important;-webkit-background-clip:text !important;background-clip:text !important}\n'
    '.hero .miudo span::before{color:#22D94A !important}\n'
    '.jan{box-shadow:0 30px 90px rgba(0,0,0,.6),0 0 0 1px rgba(124,255,90,.18),0 0 110px rgba(34,217,74,.16) !important}\n'
    '.func li::before{background:linear-gradient(135deg,#22D94A,#7CFF5A) url("data:image/svg+xml,%3Csvg xmlns=%27http://www.w3.org/2000/svg%27 viewBox=%270 0 24 24%27 fill=%27none%27 stroke=%27%2304210E%27 stroke-width=%273.2%27 stroke-linecap=%27round%27 stroke-linejoin=%27round%27%3E%3Cpath d=%27M5 12l5 5L20 7%27/%3E%3C/svg%3E") center/13px no-repeat !important}\n'
    '.func h2,.sec h2{color:#fff}\n'
    '.modulos{background:rgba(7,16,39,.7) !important;border-color:rgba(124,255,90,.12) !important}\n.modulos a:hover{border-color:#22D94A !important;color:#fff !important}\n'
    '.vant div{border-top-color:#22D94A !important}\n.vant b{color:#fff}\n'
    '.plano{background:linear-gradient(180deg,rgba(255,255,255,.03),rgba(255,255,255,.01)),#0A1430 !important;border-color:rgba(255,255,255,.12) !important}\n'
    '.plano.dest{border-color:#22D94A !important;background:linear-gradient(180deg,rgba(34,217,74,.16),#0A1430 55%) !important;box-shadow:0 24px 70px rgba(34,217,74,.22),0 0 0 1px rgba(124,255,90,.35) !important}\n'
    '.plano li::before{color:#22D94A !important}\n.ciclo button[aria-pressed="true"] small{color:#04210E !important;background:#7CFF5A !important}\n'
    '.final{background:radial-gradient(800px 340px at 50% 0%,rgba(34,217,74,.28),transparent 70%),#071027 !important;border-top-color:rgba(124,255,90,.18) !important}\n'
    '.rod{border-top-color:rgba(124,255,90,.12) !important}\n'
    '@media (prefers-reduced-motion:no-preference){.hero::before{animation:sobe 9s ease-in-out infinite alternate}@keyframes sobe{from{transform:translate(0,0)}to{transform:translate(-10px,-12px)}}}\n'
    '</style>\n')
  s = por_css(s, css)
  gravar(p, s)

def cadastro():
  p = 'public/cadastro.html'; s = ler(p)
  s = trocar_cores(s)
  s = s.replace('<div class="login-logo-text">TMX</div><div class="login-logo-sub">DIGITAL</div>',
                '<img src="' + ICONE + '" alt="" style="width:48px;height:48px;border-radius:12px"><div class="login-logo-text">SCAL<span>ROI</span></div>')
  s = re.sub(r'<title>([^<]*)TMX([^<]*)</title>', r'<title>\1SCALROI\2</title>', s, count=1)
  s = s.replace('TMX Digital', 'SCALROI')
  css = '<style id="marca-scalroi">.login-logo-text{background:none !important;-webkit-text-fill-color:#fff !important;color:#fff;font-weight:900 !important}.login-logo-text span{color:#22D94A;-webkit-text-fill-color:#22D94A}</style>\n'
  s = por_css(s, css)
  gravar(p, s)

def manifesto_e_icones():
  p = 'public/manifest.json'; s = ler(p)
  s = s.replace('"name": "TMX Digital"', '"name": "SCALROI"').replace('"short_name": "TMX Digital"', '"short_name": "SCALROI"')
  s = s.replace('Sistema de gestão de tráfego pago TMX Digital', 'SCALROI: a operação inteira, do anúncio ao lucro')
  s = s.replace('"background_color": "#0A1628"', '"background_color": "#050A18"').replace('"theme_color": "#3E1493"', '"theme_color": "#050A18"')
  gravar(p, s)
  os.makedirs(os.path.join(RAIZ, 'public/marca'), exist_ok=True)
  # O ícone de origem é um quadrado arredondado sobre fundo branco. Daqui saem dois:
  #  cheio: quadrado inteiro no fundo escuro (tela de início do iPhone e Android, que arredondam sozinhos)
  #  recortado: cantos transparentes (aba do navegador e logo do menu), sem o branco em volta
  from PIL import Image, ImageDraw
  im = Image.open(ICONE_ORIGEM).convert('RGB')
  cinza = im.convert('L')
  escuro = cinza.point(lambda v: 255 if v < 60 else 0)
  x0, y0, x1, y1 = escuro.getbbox()
  lado = int(min(x1 - x0, y1 - y0) * .975)   # tira 1,25% de cada borda: o canto da origem não é um arco perfeito
  cx, cy = (x0 + x1) // 2, (y0 + y1) // 2
  im = im.crop((cx - lado // 2, cy - lado // 2, cx - lado // 2 + lado, cy - lado // 2 + lado))
  fundo = im.crop((int(lado * .03), int(lado * .45), int(lado * .07), int(lado * .55))).resize((1, 1), Image.BOX).getpixel((0, 0))
  R = int(lado * .28)   # o arredondado da origem é 25% do lado (medido na diagonal); 28% cobre todo o branco
  cantos = Image.new('L', (lado * 4, lado * 4), 255)
  ImageDraw.Draw(cantos).rounded_rectangle((0, 0, lado * 4 - 1, lado * 4 - 1), radius=R * 4, fill=0)
  cantos = cantos.resize((lado, lado), Image.LANCZOS)
  cheio = im.copy(); cheio.paste(Image.new('RGB', (lado, lado), fundo), (0, 0), cantos)
  recortado = im.convert('RGBA'); recortado.putalpha(cantos.point(lambda v: 255 - v))
  def png(tam, destino, base):
    base.resize((tam, tam), Image.LANCZOS).save(os.path.join(RAIZ, destino), optimize=True)
  png(256, 'public/marca/scalroi-icone.png', recortado); png(32, 'public/favicon-32.png', recortado)
  png(512, 'public/icon-512.png', cheio); png(192, 'public/icon-192.png', cheio)
  png(180, 'public/apple-touch-icon.png', cheio); png(120, 'public/apple-touch-icon-120.png', cheio)
  png(152, 'public/apple-touch-icon-152.png', cheio); png(167, 'public/apple-touch-icon-167.png', cheio)
  subprocess.run(['sips', '-s', 'format', 'png', '-Z', '1200', LOGO_ORIGEM, '--out', os.path.join(RAIZ, 'public/marca/scalroi-logo.png')], check=True, capture_output=True)
  import io
  buf = io.BytesIO(); recortado.resize((64, 64), Image.LANCZOS).save(buf, 'PNG', optimize=True)
  b64 = base64.b64encode(buf.getvalue()).decode()
  gravar('public/favicon.svg', '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><image width="64" height="64" href="data:image/png;base64,' + b64 + '"/></svg>\n')

def servidor():
  """Cor padrão da empresa (aplicada por cima do tema quando a empresa não escolheu outra)."""
  p = 'server.js'; s = ler(p)
  s = s.replace("const BRANDING_DEFAULT = {\n  nome: 'TMX Digital',\n  primary: '#5b5ef4',\n  secondary: '#3E1493',",
                "const BRANDING_DEFAULT = {\n  nome: 'SCALROI',\n  primary: '#22D94A',\n  secondary: '#0E9F35',")
  # o roxo da marca antiga salvo na empresa (a TMX tem) não conta como escolha: vale o verde
  antes = "    const branding = (t && t.branding) ? t.branding : {};\n    res.json({"
  depois = ("    const branding = Object.assign({}, (t && t.branding) ? t.branding : {});\n"
            "    // Roxo da marca antiga salvo na empresa (11/11/2026) não é escolha: vale a cor padrão da SCALROI.\n"
            "    if (String(branding.primary || '').toLowerCase() === '#5b5ef4') delete branding.primary;\n"
            "    if (String(branding.secondary || '').toLowerCase() === '#3e1493') delete branding.secondary;\n"
            "    res.json({")
  if antes in s: s = s.replace(antes, depois)
  gravar(p, s)

# ── textos: "TMX" (o sistema) vira SCALROI; "a TMX" (a empresa) só vira onde o cliente lê ──
_P = r'(?![A-Za-z0-9_\-]|\.[A-Za-z])'
_MASC = [(r'\bpelo TMX' + _P, 'pela SCALROI'), (r'\bPelo TMX' + _P, 'Pela SCALROI'), (r'\bno TMX' + _P, 'na SCALROI'), (r'\bNo TMX' + _P, 'Na SCALROI'),
         (r'\bdo TMX' + _P, 'da SCALROI'), (r'\bDo TMX' + _P, 'Da SCALROI'), (r'\bao TMX' + _P, 'à SCALROI'), (r'\bAo TMX' + _P, 'À SCALROI'),
         (r'\bnum TMX' + _P, 'numa SCALROI'), (r'\bseu TMX' + _P, 'sua SCALROI'), (r'\bSeu TMX' + _P, 'Sua SCALROI'), (r'\bnosso TMX' + _P, 'nossa SCALROI'),
         (r'\beste TMX' + _P, 'esta SCALROI'), (r'\bum TMX' + _P, 'uma SCALROI'), (r'\bo TMX' + _P, 'a SCALROI'), (r'\bO TMX' + _P, 'A SCALROI')]
_SOLTO = r"(?<![A-Za-z0-9_./\-'])TMX" + _P
_FRASES_CLIENTE = ['fale com a TMX', 'Fale com a TMX', 'Falar com a TMX', 'Esperando a TMX', 'A TMX respondeu', 'A TMX vai responder', 'A TMX responde', 'a TMX faz',
                   'O suporte da TMX', 'suporte da TMX', 'app da TMX', 'A TMX já foi avisada', 'enquanto a TMX libera', 'a TMX libera', 'A TMX libera']

_SERVIDOR_TROCAS = [("'TMX Digital <noreply@", "'SCALROI <noreply@"), ("Resetar senha · TMX Digital", "Resetar senha · SCALROI"),
  ("não aponta pro TMX Digital", "não aponta pra SCALROI"), ("'Teste TMX Digital'", "'Teste SCALROI'"),
  ("tenantNome: (t && t.nome) || 'TMX Digital'", "tenantNome: (t && t.nome) || 'SCALROI'"),
  ("a coluna TMX", "a coluna SCALROI"), ("Fontes: Utmify, Central TMX e VTurb", "Fontes: Utmify, SCALROI e VTurb"),
  ("'TMX ' + (c.vendasAnuncios", "'SCALROI ' + (c.vendasAnuncios"), ("Vendas = TMX / Utmify", "Vendas = SCALROI / Utmify"),
  ("a maior entre TMX e Utmify", "a maior entre SCALROI e Utmify"), ("DIVERGÊNCIAS (TMX / Utmify", "DIVERGÊNCIAS (SCALROI / Utmify"),
  ("=== FUNIL DO TMX", "=== FUNIL DA SCALROI"), ("'TMX API v1'", "'SCALROI API v1'"),
  ("name: ('TMX ' + p.nome", "name: ('SCALROI ' + p.nome"), ("statement_descriptor: 'TMX DIGITAL'", "statement_descriptor: 'SCALROI'"),
  ("name: 'TMX ' + p.nome", "name: 'SCALROI ' + p.nome"), ("'🛟 Suporte TMX · chamado #'", "'🛟 Suporte SCALROI · chamado #'"),
  ("Relatório Semanal TMX Digital", "Relatório Semanal SCALROI"), ("Relatório Diário TMX Digital", "Relatório Diário SCALROI"),
  ("'Notificação TMX Digital'", "'Notificação SCALROI'"), ("fonte: 'pixel TMX'", "fonte: 'pixel SCALROI'"),
  ("Tem uma tag do Central TMX", "Tem uma tag da SCALROI")]

def _linhas(s, troca):
  saida = []
  for ln in s.split('\n'):
    st = ln.lstrip()
    if st.startswith(('//', '/*', '*', '<!--')) or 'sl_empresa_nome' in ln:
      saida.append(ln); continue
    m = re.search(r'\s//\s', ln)
    codigo, resto = (ln[:m.start()], ln[m.start():]) if m else (ln, '')
    saida.append(troca(codigo) + resto)
  return '\n'.join(saida)

def _masc(t):
  for de, para in _MASC: t = re.sub(de, para, t)
  return t

def _tudo(t):
  t = t.replace('Empresa TMX', 'Empresa')
  t = t.replace("'TMX · '", "'SCALROI · '").replace("doc.text('TMX DIGITAL'", "doc.text('SCALROI'").replace(", 'TMX')", ", 'SCALROI')").replace(", 'TMX']", ", 'SCALROI']")
  t = _masc(t)
  return re.sub(_SOLTO, 'SCALROI', t)

def _servidor_txt(t):
  t = _masc(t)
  for de, para in _SERVIDOR_TROCAS: t = t.replace(de, para)
  for f in _FRASES_CLIENTE: t = t.replace(f, f.replace('TMX', 'SCALROI'))
  return t

def textos():
  for p in ['public/ScaleLab.html', 'public/planos.html', 'public/cadastro.html', 'public/paginas.html', 'public/conectar-meta.html', 'paginas.js']:
    if os.path.exists(os.path.join(RAIZ, p)): gravar(p, _linhas(ler(p), _tudo))
  gravar('public/admin.html', _linhas(ler('public/admin.html'), _masc))
  gravar('server.js', _linhas(ler('server.js'), _servidor_txt))

_ICONES = ('<link rel="icon" type="image/png" sizes="32x32" href="/favicon-32.png?v=scalroi">\n'
           '<link rel="icon" type="image/svg+xml" href="/favicon.svg?v=scalroi">\n'
           '<link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png?v=scalroi">')

def icones():
  """Ícone da SCALROI em todas as telas do cliente, com ?v=scalroi pro navegador não ficar com o da TMX guardado."""
  for p in ['public/planos.html', 'public/admin.html', 'public/cadastro.html', 'public/conectar-meta.html', 'public/paginas.html', 'public/reset-senha.html']:
    if not os.path.exists(os.path.join(RAIZ, p)): continue
    s = ler(p)
    if 'rel="icon"' not in s:
      s = re.sub(r'(<meta name="viewport"[^>]*>)', lambda m: m.group(1) + '\n' + _ICONES, s, count=1)
      gravar(p, s)
  s = ler('public/ScaleLab.html')
  s = s.replace("icon: '/favicon.ico',", "icon: '/icon-192.png?v=scalroi',")   # aviso do navegador: /favicon.ico não existe
  s = re.sub(r'href="(/(?:favicon-32\.png|favicon\.svg|apple-touch-icon(?:-\d+)?\.png|manifest\.json))"', r'href="\1?v=scalroi"', s)
  gravar('public/ScaleLab.html', s)
  s = ler('public/manifest.json')
  s = re.sub(r'"src": "(/icon-\d+\.png)"', r'"src": "\1?v=scalroi"', s)
  gravar('public/manifest.json', s)
  s = ler('public/sw.js')
  s = s.replace("showNotification(d.titulo || 'TMX Digital'", "showNotification(d.titulo || 'SCALROI'")
  gravar('public/sw.js', s)

def dominio(novo):
  """Troca o endereço que o cliente vê (app.centraltmx.com) pelo domínio novo. Só depois que ele responder.
  Comentários ficam como estão; app.centraltmx.com continua no ar (pixel, webhooks e MCP já instalados)."""
  for p in ['public/planos.html', 'public/site.html', 'public/ScaleLab.html']:
    if os.path.exists(os.path.join(RAIZ, p)):
      gravar(p, _linhas(ler(p), lambda t: t.replace('app.centraltmx.com', novo)))

if __name__ == '__main__':
  # python3 ferramentas/aplicar-marca-scalroi.py               -> nome, logo, cores e textos (endereço continua o atual)
  # python3 ferramentas/aplicar-marca-scalroi.py --dominio X   -> só a troca do endereço, quando X já estiver no ar
  if '--dominio' in sys.argv:
    novo = sys.argv[sys.argv.index('--dominio') + 1]
    dominio(novo); print('endereço trocado para ' + novo); sys.exit(0)
  sistema(); central(); planos(); cadastro(); manifesto_e_icones(); icones(); servidor(); textos()
  print('marca SCALROI aplicada')
