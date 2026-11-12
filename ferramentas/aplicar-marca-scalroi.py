#!/usr/bin/env python3
"""Aplica a marca SCALROI (nome, logo e cores) no código do sistema.
Roda na raiz do repositório: python3 aplicar-marca.py
Pode rodar de novo em cima de um main mais novo (só troca o que ainda está com a marca antiga)."""
import re, os, sys, base64, subprocess

RAIZ = os.getcwd()
AQUI = os.path.dirname(os.path.abspath(__file__))
ICONE_ORIGEM = os.path.join(AQUI, 'icone.jpg')     # 1254x1254, o "S" com a seta
LOGO_ORIGEM = os.path.join(AQUI, 'logo.jpg')       # 1600x533, SCALROI por extenso

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
  css = ('<style id="marca-scalroi">\n/* Marca SCALROI: ícone + nome (SCAL na cor do texto, ROI em verde) */\n'
    '.logo-ic{width:30px;height:30px;border-radius:8px;flex:none;display:block}\n'
    '.logo-tmx{background:none !important;-webkit-text-fill-color:currentColor !important;color:var(--text) !important;font-size:21px !important;font-weight:900 !important;letter-spacing:-.3px !important}\n'
    '.logo-roi{color:#22D94A;-webkit-text-fill-color:#22D94A}\n.light-mode .logo-roi{color:#16A34A;-webkit-text-fill-color:#16A34A}\n'
    '.sidebar.collapsed .logo-tmx{display:none !important}\n'
    '.login-logo-text.scal{background:none !important;-webkit-text-fill-color:#fff !important;color:#fff;font-weight:900}\n'
    '.login-logo-text.scal span{color:#22D94A;-webkit-text-fill-color:#22D94A}\n</style>\n')
  if 'id="marca-scalroi"' not in s: s = s.replace('</head>', css + '</head>', 1)
  gravar(p, s)

def central():
  p = 'public/admin.html'; s = ler(p)
  s = trocar_cores(s)
  s = s.replace('<title>Central TMX Admin</title>', '<title>Central SCALROI</title>')
  s = s.replace('<div class="logo">TMX</div>', '<img class="logo" src="' + ICONE + '" alt="">')
  s = s.replace('<b>Central TMX</b>', '<b>Central SCAL<i>ROI</i></b>')
  s = s.replace('Abrindo a Central TMX Admin…', 'Abrindo a Central SCALROI…')
  css = '<style id="marca-scalroi">.marca .logo{object-fit:cover;background:none !important;box-shadow:none !important}.marca b i{font-style:normal;color:#22D94A}</style>\n'
  if 'id="marca-scalroi"' not in s: s = s.replace('</head>', css + '</head>', 1)
  gravar(p, s)

def planos():
  p = 'public/planos.html'; s = ler(p)
  s = trocar_cores(s)
  s = re.sub(r'<title>[^<]*</title>', '<title>Planos · SCALROI</title>', s, count=1)
  s = s.replace('aria-label="TMX Digital"><b>TMX</b><span>DIGITAL</span>', 'aria-label="SCALROI"><img src="' + ICONE + '" alt=""><b>SCAL<em>ROI</em></b>')
  s = s.replace('<div class="lg"><b>TMX</b><span>DIGITAL</span></div>', '<div class="lg"><img src="' + ICONE + '" alt=""><b>SCAL<em>ROI</em></b></div>')
  s = s.replace('TMX Digital', 'SCALROI')
  css = ('<style id="marca-scalroi">\n.logo{align-items:center !important}\n.logo img{width:32px;height:32px;border-radius:9px;flex:none}\n'
    '.lg{display:flex !important;align-items:center;gap:5px}\n.lg img{width:16px;height:16px;border-radius:4px;flex:none}\n'
    '.logo b,.lg b{background:none !important;-webkit-text-fill-color:currentColor !important;font-weight:900 !important}\n'
    '.logo b{color:#fff}\n.lg b{color:#0F172A}\n.logo b em,.lg b em{font-style:normal;color:#22D94A;-webkit-text-fill-color:#22D94A}\n.lg b em{color:#16A34A;-webkit-text-fill-color:#16A34A}\n</style>\n')
  if 'id="marca-scalroi"' not in s: s = s.replace('</head>', css + '</head>', 1)
  gravar(p, s)

def cadastro():
  p = 'public/cadastro.html'; s = ler(p)
  s = trocar_cores(s)
  s = s.replace('<div class="login-logo-text">TMX</div><div class="login-logo-sub">DIGITAL</div>',
                '<img src="' + ICONE + '" alt="" style="width:48px;height:48px;border-radius:12px"><div class="login-logo-text">SCAL<span>ROI</span></div>')
  s = re.sub(r'<title>([^<]*)TMX([^<]*)</title>', r'<title>\1SCALROI\2</title>', s, count=1)
  s = s.replace('TMX Digital', 'SCALROI')
  css = '<style id="marca-scalroi">.login-logo-text{background:none !important;-webkit-text-fill-color:#fff !important;color:#fff;font-weight:900 !important}.login-logo-text span{color:#22D94A;-webkit-text-fill-color:#22D94A}</style>\n'
  if 'id="marca-scalroi"' not in s: s = s.replace('</head>', css + '</head>', 1)
  gravar(p, s)

def manifesto_e_icones():
  p = 'public/manifest.json'; s = ler(p)
  s = s.replace('"name": "TMX Digital"', '"name": "SCALROI"').replace('"short_name": "TMX Digital"', '"short_name": "SCALROI"')
  s = s.replace('Sistema de gestão de tráfego pago TMX Digital', 'SCALROI: a operação inteira, do anúncio ao lucro')
  s = s.replace('"background_color": "#0A1628"', '"background_color": "#050A18"').replace('"theme_color": "#3E1493"', '"theme_color": "#050A18"')
  gravar(p, s)
  os.makedirs(os.path.join(RAIZ, 'public/marca'), exist_ok=True)
  def png(tam, destino, origem=ICONE_ORIGEM):
    subprocess.run(['sips', '-s', 'format', 'png', '-Z', str(tam), origem, '--out', os.path.join(RAIZ, destino)], check=True, capture_output=True)
  png(256, 'public/marca/scalroi-icone.png'); png(512, 'public/icon-512.png'); png(192, 'public/icon-192.png')
  png(180, 'public/apple-touch-icon.png'); png(120, 'public/apple-touch-icon-120.png'); png(152, 'public/apple-touch-icon-152.png')
  png(167, 'public/apple-touch-icon-167.png'); png(32, 'public/favicon-32.png'); png(1200, 'public/marca/scalroi-logo.png', LOGO_ORIGEM)
  png(64, 'public/marca/_fav64.png')
  b64 = base64.b64encode(open(os.path.join(RAIZ, 'public/marca/_fav64.png'), 'rb').read()).decode()
  os.remove(os.path.join(RAIZ, 'public/marca/_fav64.png'))
  gravar('public/favicon.svg', '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><image width="64" height="64" href="data:image/png;base64,' + b64 + '"/></svg>\n')

if __name__ == '__main__':
  sistema(); central(); planos(); cadastro(); manifesto_e_icones()
  print('marca SCALROI aplicada')
