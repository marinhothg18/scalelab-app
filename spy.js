// Spy de anúncios (18/11/2026). Especificação: SPEC-spy-central-tmx.md (Downloads do Thiago), com as decisões dele no mesmo dia.
//
// Quem coleta é o Claude, numa tarefa agendada no Chrome do Thiago: ele abre a Biblioteca de Anúncios, lê os anúncios e
// manda tudo pra cá pelo MCP (spy_registrar_coleta). O servidor nunca abre o Facebook: só baixa o vídeo pelo link que veio
// na coleta (o link expira), tira a impressão digital, junta os iguais num criativo só, guarda no R2 e transcreve
// (AssemblyAI). O julgamento (etiquetas, cortes, família, "não modelar", sugestões, leitura do funil) é do Claude, também pelo
// MCP. Nenhuma chamada a modelo de IA parte daqui.
//
// Tudo mora em spy.sqlite no DATA_DIR (nada no db.json). Anúncio, criativo, vídeo e transcrição são guardados uma vez e
// servem a qualquer empresa no futuro; o que cada empresa acompanha (bibliotecas, nichos, regras, etiquetas, funis e
// rodadas) leva a coluna empresa. Hoje é só a TMX (decisão do Thiago). Nada é apagado: anúncio que sai do ar ganha
// fim_veiculacao, criativo repetido ganha mesclado_em, versão de funil e foto do dia ficam pra sempre.
// Vídeos: Cloudflare R2 da hospedagem, pasta spy-midia/. Nunca no volume do Railway (encheu e derrubou vendas); só rodando
// local, sem /data, vão pra pasta spy_midia.
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const SpyLink = require('./public/spy-link.js');

const DIA = 86400000;
const so_teste = v => (process.env[v] && !fs.existsSync('/data')) ? process.env[v] : '';
const diaBR = ms => new Date(ms - 3 * 3600000).toISOString().slice(0, 10);
const novoId = p => p + Date.now().toString(36) + crypto.randomBytes(4).toString('hex');
const sha256 = b => crypto.createHash('sha256').update(b).digest('hex');
const json = v => { try { return v ? JSON.parse(v) : null; } catch (e) { return null; } };
const nrm = s => String(s || '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().trim();

let FFMPEG = '';
try { FFMPEG = require('ffmpeg-static') || ''; if (FFMPEG && !fs.existsSync(FFMPEG)) FFMPEG = ''; } catch (e) { FFMPEG = ''; }

// ══════════════════════════════════════════════
// Impressão digital do vídeo: sha256 do arquivo junta cópias idênticas; quadros (dHash de 10 pontos do
// vídeo) e o desenho do volume do áudio juntam o mesmo vídeo subido de novo noutra página, que a Meta
// recodifica. Gancho diferente com o mesmo corpo NÃO é o mesmo criativo: isso é família (o Claude decide).
// ══════════════════════════════════════════════
function ff(args, opc) {
  opc = opc || {};
  return new Promise((ok, falha) => {
    if (!FFMPEG) return falha(new Error('ffmpeg não está instalado neste servidor'));
    const p = spawn(FFMPEG, ['-hide_banner', '-nostdin'].concat(args), { stdio: ['ignore', 'pipe', 'pipe'] });
    const out = [], max = opc.max || 64 * 1024 * 1024;
    let tam = 0, err = '';
    const t = setTimeout(() => { try { p.kill('SIGKILL'); } catch (e) {} }, opc.ms || 60000);
    p.stdout.on('data', b => { tam += b.length; if (tam <= max) out.push(b); });
    p.stderr.on('data', b => { if (err.length < 20000) err += b; });
    p.on('error', e => { clearTimeout(t); falha(e); });
    p.on('close', code => { clearTimeout(t); ok({ code, out: Buffer.concat(out), err }); });
  });
}
function dhash(px) {   // 9x8 em cinza → 64 bits em 16 letras hex
  if (!px || px.length < 72) return null;
  let h = '';
  for (let lin = 0; lin < 8; lin++) {
    let n = 0;
    for (let col = 0; col < 8; col++) n = (n << 1) | (px[lin * 9 + col] < px[lin * 9 + col + 1] ? 1 : 0);
    h += (n >>> 0).toString(16).padStart(2, '0');
  }
  return h;
}
function distancia(a, b) {
  if (!a || !b || a.length !== b.length) return 64;
  let d = 0;
  for (let i = 0; i < a.length; i++) { let x = parseInt(a[i], 16) ^ parseInt(b[i], 16); while (x) { d += x & 1; x >>= 1; } }
  return d;
}
async function infoMidia(arq) {
  const r = await ff(['-i', arq], { ms: 20000 });
  const m = r.err.match(/Duration:\s*(\d+):(\d+):(\d+(?:\.\d+)?)/);
  const v = r.err.match(/Stream #[^\n]*Video:[^\n]*?\b(\d{2,5})x(\d{2,5})\b/);
  return { duracao: m ? (+m[1]) * 3600 + (+m[2]) * 60 + parseFloat(m[3]) : 0, largura: v ? +v[1] : 0, altura: v ? +v[2] : 0, temAudio: /Stream #[^\n]*Audio:/.test(r.err), temVideo: !!v };
}
async function quadro(arq, seg) {
  const r = await ff(['-ss', String(Math.max(0, seg).toFixed(2)), '-i', arq, '-frames:v', '1', '-vf', 'scale=9:8:flags=area,format=gray', '-f', 'rawvideo', 'pipe:1'], { ms: 20000, max: 1000 });
  return dhash(r.out);
}
// volume a cada 100 ms, de 0 a 255 (log), em base64
async function desenhoAudio(arq) {
  const TAXA = 4000, JANELA = 400;
  const r = await ff(['-i', arq, '-vn', '-ac', '1', '-ar', String(TAXA), '-f', 's16le', 'pipe:1'], { ms: 60000, max: TAXA * 2 * 900 });
  if (r.out.length < JANELA * 2 * 5) return null;
  const n = Math.floor(r.out.length / 2), v = [];
  for (let i = 0; i + JANELA <= n; i += JANELA) {
    let s = 0;
    for (let j = 0; j < JANELA; j++) { const x = r.out.readInt16LE((i + j) * 2); s += x * x; }
    v.push(Math.min(255, Math.round(Math.log10(Math.sqrt(s / JANELA) + 1) * 55)));
  }
  return Buffer.from(v).toString('base64');
}
function correlacao(a64, b64) {
  const a = Buffer.from(a64 || '', 'base64'), b = Buffer.from(b64 || '', 'base64');
  const n = Math.min(a.length, b.length);
  if (n < 5 || Math.max(a.length, b.length) > n * 1.08 + 3) return null;
  let ma = 0, mb = 0;
  for (let i = 0; i < n; i++) { ma += a[i]; mb += b[i]; }
  ma /= n; mb /= n;
  let num = 0, da = 0, db = 0;
  for (let i = 0; i < n; i++) { const x = a[i] - ma, y = b[i] - mb; num += x * y; da += x * x; db += y * y; }
  if (da < 1 || db < 1) return null;   // silêncio: não serve pra comparar
  return num / Math.sqrt(da * db);
}
async function analisarVideo(arq) {
  const info = await infoMidia(arq);
  if (!info.temVideo) throw new Error('o arquivo não tem vídeo');
  const d = info.duracao || 1;
  const pontos = [Math.min(0.5, d / 4)].concat([0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9].map(f => f * d)).map(t => Math.min(t, Math.max(0, d - 0.08)));
  const quadros = [];
  for (const t of pontos) quadros.push(await quadro(arq, t));
  return { duracao: Math.round(d * 100) / 100, largura: info.largura, altura: info.altura, quadros, audio: info.temAudio ? await desenhoAudio(arq) : null };
}
async function analisarImagem(arq) {
  const info = await infoMidia(arq);
  return { duracao: 0, largura: info.largura, altura: info.altura, quadros: [await quadro(arq, 0)], audio: null };
}
// mesmo vídeo? duração igual, todos os quadros parecidos e o áudio com o mesmo desenho
function mesmoVideo(a, b) {
  if (!a || !b || !a.quadros || !b.quadros || a.quadros.length !== b.quadros.length) return false;
  const da = a.duracao || 0, db = b.duracao || 0;
  if (Math.abs(da - db) > Math.max(0.6, 0.02 * Math.max(da, db))) return false;
  const ds = a.quadros.map((q, i) => distancia(q, b.quadros[i]));
  if (Math.max.apply(null, ds) > 12 || ds.reduce((s, x) => s + x, 0) / ds.length > 6) return false;
  if (!!a.audio !== !!b.audio) return false;
  if (a.audio) { const c = correlacao(a.audio, b.audio); if (c !== null && c < 0.85) return false; }
  return true;
}

// ══════════════════════════════════════════════
// Endereços do Facebook: o domínio de destino do anúncio e o nome do arquivo de mídia no fbcdn
// ══════════════════════════════════════════════
function hostDe(u) {
  try {
    let x = new URL(String(u));
    if (/(^|\.)facebook\.com$/.test(x.hostname) && x.searchParams.get('u')) x = new URL(x.searchParams.get('u'));
    return x.hostname.toLowerCase().replace(/^www\./, '');
  } catch (e) { return ''; }
}
const nomeArquivo = u => { try { return path.basename(new URL(String(u)).pathname); } catch (e) { return ''; } };
// o link do fbcdn traz a validade em oe= (hexa, segundos)
function linkVenceu(u, agoraMs) {
  try { const oe = new URL(u).searchParams.get('oe'); if (!oe) return false; return parseInt(oe, 16) * 1000 < agoraMs; } catch (e) { return false; }
}

// ══════════════════════════════════════════════
// Armazenamento dos vídeos: R2 pela hospedagem, ou disco
// ══════════════════════════════════════════════
const TIPOS = { mp4: 'video/mp4', jpg: 'image/jpeg', png: 'image/png', webp: 'image/webp' };
function midiaDisco(dir) {
  try { fs.mkdirSync(dir, { recursive: true }); } catch (e) {}
  const arq = c => path.join(dir, c.replace(/\//g, '_'));
  return {
    nome: 'disco',
    async guardar(chave, origem) { if (Buffer.isBuffer(origem)) fs.writeFileSync(arq(chave), origem); else fs.copyFileSync(origem, arq(chave)); },
    async existe(chave) { return fs.existsSync(arq(chave)); },
    async ler(chave, faixa) {
      const f = arq(chave);
      if (!fs.existsSync(f)) return null;
      const tam = fs.statSync(f).size;
      let ini = 0, fim = tam - 1;
      if (faixa) { ini = faixa.ini != null ? faixa.ini : Math.max(0, tam - faixa.ult); fim = faixa.fim != null ? Math.min(faixa.fim, tam - 1) : tam - 1; }
      if (ini > fim || ini >= tam) return { tam, invalida: true };
      return { tam, ini, fim, parcial: !!faixa, corpo: fs.createReadStream(f, { start: ini, end: fim }) };
    },
    async buffer(chave) { const f = arq(chave); return fs.existsSync(f) ? fs.readFileSync(f) : null; }
  };
}
function midiaR2(hosp) {
  const k = c => 'spy-midia/' + c;
  return {
    nome: 'r2',
    async guardar(chave, origem) { await hosp.midiaGuardar(k(chave), Buffer.isBuffer(origem) ? origem : fs.readFileSync(origem), TIPOS[chave.split('.').pop()] || 'application/octet-stream'); },
    async existe(chave) { const r = await hosp.midiaLer(k(chave), null, 'HEAD'); return r.ok; },
    async ler(chave, faixa) {
      const cab = faixa ? 'bytes=' + (faixa.ini != null ? faixa.ini + '-' + (faixa.fim != null ? faixa.fim : '') : '-' + faixa.ult) : null;
      const r = await hosp.midiaLer(k(chave), cab);
      if (r.status === 404) return null;
      if (r.status === 416) return { tam: Number(r.headers.get('x-tmx-tamanho')) || 0, invalida: true };
      if (!r.ok) throw new Error('o armazenamento respondeu ' + r.status);
      const tam = Number(r.headers.get('x-tmx-tamanho')) || 0;
      const cr = String(r.headers.get('content-range') || '').match(/bytes (\d+)-(\d+)\//);
      const { Readable } = require('stream');
      return { tam, ini: cr ? +cr[1] : 0, fim: cr ? +cr[2] : tam - 1, parcial: r.status === 206, corpo: Readable.fromWeb(r.body) };
    },
    async buffer(chave) { const r = await hosp.midiaLer(k(chave), null); return r.ok ? Buffer.from(await r.arrayBuffer()) : null; }
  };
}

// ══════════════════════════════════════════════
// Transcrição plugável. Hoje: AssemblyAI (decisão do Thiago em 18/11): devolve cada fala com o tempo.
// ══════════════════════════════════════════════
function transcritorAssembly(chave, base) {
  const cab = { authorization: chave };
  async function pedir(metodo, caminho, corpo, tipo) {
    const r = await fetch(base + caminho, { method: metodo, headers: Object.assign({}, cab, corpo !== undefined ? { 'Content-Type': tipo || 'application/json' } : {}),
      body: corpo === undefined ? undefined : (tipo ? corpo : JSON.stringify(corpo)), signal: AbortSignal.timeout(120000) });
    const txt = await r.text();
    let j = null; try { j = JSON.parse(txt); } catch (e) {}
    if (!r.ok) {
      const e = new Error('AssemblyAI respondeu ' + r.status + (j && j.error ? ': ' + j.error : txt ? ': ' + txt.slice(0, 160) : ''));
      // chave errada, sem saldo ou acima da cota do plano grátis: espera, não é erro do vídeo
      e.aguardar = [401, 402, 403, 429].includes(r.status) || /balance|quota|limit|credit|saldo|cota/i.test(e.message);
      throw e;
    }
    return j;
  }
  return {
    nome: 'assemblyai',
    async transcrever(buf, idioma, esperarMs) {
      const up = await pedir('POST', '/v2/upload', buf, 'application/octet-stream');
      const pedido = { audio_url: up.upload_url, speech_models: ['assemblyai-stt-3-7', 'universal-2'], punctuate: true, format_text: true };
      if (idioma) pedido.language_code = idioma; else pedido.language_detection = true;
      const t = await pedir('POST', '/v2/transcript', pedido);
      const fim = Date.now() + (esperarMs || 6 * 60000);
      let st = t;
      while (st.status !== 'completed') {
        if (st.status === 'error') throw new Error('AssemblyAI não transcreveu: ' + (st.error || 'erro'));
        if (Date.now() > fim) throw new Error('a AssemblyAI demorou demais');
        await new Promise(r => setTimeout(r, so_teste('ASSEMBLYAI_BASE_TESTE') ? 50 : 2500));
        st = await pedir('GET', '/v2/transcript/' + encodeURIComponent(t.id));
      }
      const fr = await pedir('GET', '/v2/transcript/' + encodeURIComponent(t.id) + '/sentences');
      const segmentos = (fr.sentences || []).map(s => ({ inicio_s: Math.round(s.start / 10) / 100, fim_s: Math.round(s.end / 10) / 100, texto: String(s.text || '') }));
      return { texto: String(st.text || segmentos.map(s => s.texto).join(' ')), segmentos, idioma: String(st.language_code || idioma || '') };
    }
  };
}
const IDIOMA_DO_PAIS = { BR: 'pt', PT: 'pt', US: 'en', GB: 'en', CA: 'en', AU: 'en', ES: 'es', MX: 'es', AR: 'es', CO: 'es', FR: 'fr', DE: 'de', IT: 'it' };

// ══════════════════════════════════════════════
// O anúncio como o Claude manda pelo MCP (lido no Chrome, na Biblioteca de Anúncios)
// ══════════════════════════════════════════════
function lerData(v) {
  if (v == null || v === '') return null;
  if (typeof v === 'number' || /^\d+$/.test(String(v))) { const n = Number(v); return n > 1e12 ? Math.floor(n / 1000) : n > 1e9 ? n : null; }
  const s = String(v).trim();
  const t = /^\d{4}-\d{2}-\d{2}$/.test(s) ? Date.parse(s + 'T12:00:00Z') : Date.parse(s);
  return isFinite(t) ? Math.floor(t / 1000) : null;
}
function lerAnuncioMcp(a) {
  a = a || {};
  const m = a.midia || {};
  const urlVideo = String(m.url_video || a.url_video || ''), urlImg = String(m.url_imagem || a.url_imagem || ''), urlCapa = String(m.url_capa || a.url_capa || '');
  let tipo = String(m.tipo || '').toLowerCase();
  // sem o link (o Claude no Chrome não consegue repassar o do fbcdn) o vídeo chega depois, pela página de envio
  if (!['video', 'imagem', 'carrossel', 'texto'].includes(tipo)) tipo = urlVideo ? 'video' : urlImg ? 'imagem' : 'video';
  if (tipo === 'video' && !urlVideo && urlImg) tipo = 'imagem';
  const midia = tipo === 'video' ? urlVideo : (urlImg || urlVideo);
  const copy = String(a.copy || a.texto || '').slice(0, 8000), titulo = String(a.titulo || '').slice(0, 500);
  const link = String(a.link_destino || a.link || '').slice(0, 2000), legenda = String(a.legenda || '').slice(0, 300);
  const pageId = String(a.page_id || '').replace(/\D/g, '');
  // sem o arquivo, cada anúncio é um criativo até o vídeo chegar: a mesma copy roda com vídeos diferentes, então juntar
  // pela copy erraria. Quando o vídeo chega, a impressão digital junta os iguais.
  const chaveMidia = midia ? (tipo === 'video' ? 'v:' : tipo === 'carrossel' ? 'c:' : 'i:') + (nomeArquivo(midia) || sha256(midia).slice(0, 24))
    : tipo === 'texto' ? 't:' + sha256(copy + '|' + titulo + '|' + pageId).slice(0, 24) : 'a:' + String(a.ad_archive_id || a.id || '').replace(/\D/g, '');
  return { ad_archive_id: String(a.ad_archive_id || a.id || '').replace(/\D/g, ''), page_id: pageId, page_name: String(a.page_name || '').slice(0, 200),
    copy, titulo, cta_tipo: String(a.cta_tipo || '').slice(0, 60), cta_texto: String(a.cta || a.cta_texto || '').slice(0, 120), link_destino: link,
    dominio: hostDe(link) || (SpyLink.ehDominio(legenda) ? SpyLink.limparDominio(legenda) : ''), legenda, inicio: lerData(a.inicio_veiculacao),
    plataformas: (Array.isArray(a.plataformas) ? a.plataformas : String(a.plataformas || '').split(',')).map(x => String(x).trim().toLowerCase()).filter(Boolean),
    quantidade: Math.max(1, Math.min(10000, parseInt(a.quantidade, 10) || 1)), collation_id: String(a.collation_id || ''),
    tipo, midia, thumb: urlCapa || (tipo !== 'video' ? urlImg : ''), chaveMidia };
}

// ══════════════════════════════════════════════
// Núcleo: banco, coleta, mídia, etiquetas, funis e rodadas. Testável sem o servidor (test/spy.test.js).
// ══════════════════════════════════════════════
const CAMPOS_FUNIL = ['preco', 'ancoragem', 'parcelamento', 'lote', 'promessa', 'formato_oferta', 'video', 'checkout', 'bonus', 'rastreio'];
const REGRAS_PADRAO = { avisar_criativo_novo_em_ouro: true, biblioteca_nova_min_anuncios: 30, multiplicador_escala: 3, horario_rotina: '08:40' };
function criarNucleo(o) {
  const agora = o.agora || (() => Date.now());
  const EMP = o.empresa || 'tmx';
  const { DatabaseSync } = require('node:sqlite');
  const db = new DatabaseSync(path.join(o.dir, 'spy.sqlite'));
  db.exec(`
    PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=3000;
    CREATE TABLE IF NOT EXISTS spy_nicho (id TEXT PRIMARY KEY, empresa TEXT NOT NULL, nome TEXT NOT NULL, icone TEXT, pais TEXT NOT NULL DEFAULT 'BR',
      ativo INTEGER NOT NULL DEFAULT 1, min_anuncios INTEGER NOT NULL DEFAULT 10, palavras TEXT, ordem INTEGER, criado_em INTEGER, atualizado_em INTEGER);
    CREATE TABLE IF NOT EXISTS spy_regras (empresa TEXT PRIMARY KEY, dados TEXT);
    CREATE TABLE IF NOT EXISTS spy_biblioteca (id TEXT PRIMARY KEY, empresa TEXT NOT NULL, nome TEXT, nicho_id TEXT, tipo TEXT NOT NULL, referencia TEXT NOT NULL,
      pais TEXT NOT NULL DEFAULT 'BR', search_type TEXT, url_original TEXT, ouro INTEGER NOT NULL DEFAULT 0, origem TEXT, status TEXT, motivo TEXT,
      ads_ativos INTEGER NOT NULL DEFAULT 0, ultima_coleta_em INTEGER, erro TEXT, criado_em INTEGER, criado_por TEXT, atualizado_em INTEGER,
      UNIQUE (empresa, tipo, referencia, pais));
    CREATE TABLE IF NOT EXISTS spy_anuncio (ad_archive_id TEXT PRIMARY KEY, page_id TEXT, page_name TEXT, copy TEXT, titulo TEXT,
      cta_tipo TEXT, cta_texto TEXT, link_destino TEXT, dominio TEXT, legenda TEXT, inicio_veiculacao INTEGER, fim_veiculacao INTEGER,
      ativo INTEGER NOT NULL DEFAULT 1, quantidade INTEGER NOT NULL DEFAULT 1, visto_primeira_vez_em INTEGER, visto_ultima_vez_em INTEGER, criativo_id TEXT,
      plataformas TEXT, pais TEXT, collation_id TEXT, tipo TEXT, midia_url TEXT, thumb_url TEXT, bruto_json TEXT);
    CREATE INDEX IF NOT EXISTS spy_anuncio_criativo ON spy_anuncio(criativo_id);
    CREATE TABLE IF NOT EXISTS spy_anuncio_bib (ad_archive_id TEXT NOT NULL, biblioteca_id TEXT NOT NULL, ativo INTEGER NOT NULL DEFAULT 1,
      visto_primeira_vez_em INTEGER, visto_ultima_vez_em INTEGER, PRIMARY KEY (ad_archive_id, biblioteca_id));
    CREATE INDEX IF NOT EXISTS spy_anuncio_bib_bib ON spy_anuncio_bib(biblioteca_id);
    CREATE TABLE IF NOT EXISTS spy_criativo (id TEXT PRIMARY KEY, tipo TEXT, impressao_digital TEXT, quadros TEXT, audio TEXT, duracao_s REAL,
      largura INTEGER, altura INTEGER, arquivo TEXT, thumb TEXT, tamanho INTEGER, familia_id TEXT, primeiro_visto_em INTEGER, ultimo_visto_em INTEGER,
      inicio_mais_antigo INTEGER, fim_mais_recente INTEGER, anuncios_ativos INTEGER NOT NULL DEFAULT 0, anuncios_total INTEGER NOT NULL DEFAULT 0,
      tendencia TEXT, anuncios_antes INTEGER, status TEXT, nao_modelar INTEGER NOT NULL DEFAULT 0, nao_modelar_motivo TEXT, nao_modelar_origem TEXT,
      nao_modelar_por TEXT, partes TEXT, partes_origem TEXT, midia_status TEXT NOT NULL DEFAULT 'pendente', midia_erro TEXT,
      midia_tentativas INTEGER NOT NULL DEFAULT 0, transcricao_status TEXT, transcricao_erro TEXT, mesclado_em TEXT, criado_em INTEGER, atualizado_em INTEGER);
    CREATE INDEX IF NOT EXISTS spy_criativo_dig ON spy_criativo(impressao_digital);
    CREATE TABLE IF NOT EXISTS spy_chave (chave TEXT PRIMARY KEY, criativo_id TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS spy_familia (id TEXT PRIMARY KEY, nome TEXT NOT NULL, corpo_base TEXT, criado_em INTEGER);
    CREATE TABLE IF NOT EXISTS spy_snapshot (id INTEGER PRIMARY KEY AUTOINCREMENT, biblioteca_id TEXT NOT NULL, data TEXT NOT NULL,
      ads_ativos INTEGER, criativos_ativos INTEGER, novos INTEGER, parados INTEGER, anuncios_por_criativo TEXT, criado_em INTEGER,
      UNIQUE (biblioteca_id, data));
    CREATE TABLE IF NOT EXISTS spy_transcricao (id TEXT PRIMARY KEY, criativo_id TEXT NOT NULL, provedor TEXT, idioma TEXT, texto TEXT,
      segmentos TEXT, criado_em INTEGER);
    CREATE INDEX IF NOT EXISTS spy_transcricao_cr ON spy_transcricao(criativo_id);
    CREATE TABLE IF NOT EXISTS spy_etiqueta (id TEXT PRIMARY KEY, empresa TEXT NOT NULL, alvo_tipo TEXT NOT NULL, alvo_id TEXT NOT NULL, campo TEXT NOT NULL,
      valor TEXT, parte TEXT NOT NULL DEFAULT 'todo', origem TEXT NOT NULL, confianca REAL, por TEXT, atualizado_em INTEGER,
      UNIQUE (empresa, alvo_tipo, alvo_id, campo, parte));
    CREATE TABLE IF NOT EXISTS spy_coleta (id TEXT PRIMARY KEY, biblioteca_id TEXT, dia TEXT, recebida_em INTEGER, anuncios INTEGER, total_ativos INTEGER,
      novos INTEGER, parados INTEGER, completa INTEGER, por TEXT);
    CREATE TABLE IF NOT EXISTS spy_funil (id TEXT PRIMARY KEY, empresa TEXT NOT NULL, biblioteca_id TEXT, dominio TEXT NOT NULL, url_atual TEXT, tipo TEXT,
      criado_em INTEGER, atualizado_em INTEGER, UNIQUE (empresa, dominio));
    CREATE TABLE IF NOT EXISTS spy_funil_versao (id TEXT PRIMARY KEY, funil_id TEXT NOT NULL, dia TEXT NOT NULL, capturado_em INTEGER, url TEXT, campos TEXT,
      texto TEXT, leitura TEXT, fora_do_ar INTEGER NOT NULL DEFAULT 0, diff TEXT, por TEXT, UNIQUE (funil_id, dia));
    CREATE TABLE IF NOT EXISTS spy_rodada (id TEXT PRIMARY KEY, empresa TEXT NOT NULL, iniciada_em INTEGER, terminada_em INTEGER, numeros TEXT,
      resumo_texto TEXT, alertas TEXT, erros TEXT, criado_em INTEGER, por TEXT);
    CREATE TABLE IF NOT EXISTS spy_cfg (k TEXT PRIMARY KEY, v TEXT);
  `);
  // o servidor caiu no meio de um download ou transcrição: volta pra fila na próxima vez
  db.exec("UPDATE spy_criativo SET midia_status='pendente' WHERE midia_status='baixando'; UPDATE spy_criativo SET transcricao_status=NULL WHERE transcricao_status='rodando'");
  const Q = {};
  const q = sql => Q[sql] || (Q[sql] = db.prepare(sql));
  let emTx = 0;
  const tx = fn => {
    if (emTx) return fn();
    emTx++; db.exec('BEGIN');
    try { const r = fn(); db.exec('COMMIT'); return r; } catch (e) { try { db.exec('ROLLBACK'); } catch (e2) {} throw e; } finally { emTx--; }
  };
  const cfgLer = k => { const r = q('SELECT v FROM spy_cfg WHERE k=?').get(k); return r ? r.v : ''; };
  const cfgGravar = (k, v) => q('INSERT INTO spy_cfg(k, v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v').run(k, String(v));
  const erroHttp = (msg, http) => { const e = new Error(msg); e.http = http || 400; return e; };

  // ── Nichos e regras (Configurações) ──
  const nichoPub = n => n && ({ id: n.id, nome: n.nome, icone: n.icone || '', pais: n.pais, ativo: !!n.ativo, min_anuncios: n.min_anuncios, palavras: json(n.palavras) || [] });
  function nichos() { return q('SELECT * FROM spy_nicho WHERE empresa=? ORDER BY COALESCE(ordem, 999), criado_em').all(EMP).map(nichoPub); }
  function salvarNicho(d) {
    d = d || {};
    const t = agora();
    let n = d.id ? q('SELECT * FROM spy_nicho WHERE id=? AND empresa=?').get(String(d.id), EMP) : null;
    if (!n && d.nome) n = q('SELECT * FROM spy_nicho WHERE empresa=?').all(EMP).find(x => nrm(x.nome) === nrm(d.nome)) || null;
    const palavras = d.palavras !== undefined ? [...new Set((Array.isArray(d.palavras) ? d.palavras : String(d.palavras || '').split(','))
      .map(x => String(x).trim().replace(/\s+/g, ' ')).filter(Boolean).map(x => x.slice(0, 120)))].slice(0, 200) : null;
    const pais = d.pais !== undefined ? String(d.pais || 'BR').toUpperCase().slice(0, 3) : null;
    if (!n) {
      const nome = String(d.nome || '').trim().slice(0, 80);
      if (!nome) throw erroHttp('O nicho precisa de um nome.');
      const id = d.id && /^[\w-]{3,60}$/.test(d.id) ? String(d.id) : novoId('nic-');
      q('INSERT INTO spy_nicho (id, empresa, nome, icone, pais, ativo, min_anuncios, palavras, ordem, criado_em, atualizado_em) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
        .run(id, EMP, nome, String(d.icone || ''), pais || 'BR', d.ativo === false ? 0 : 1, Math.max(1, Number(d.min_anuncios) || 10), JSON.stringify(palavras || []), d.ordem == null ? null : Number(d.ordem), t, t);
      return nichoPub(q('SELECT * FROM spy_nicho WHERE id=?').get(id));
    }
    q(`UPDATE spy_nicho SET nome=?, icone=?, pais=?, ativo=?, min_anuncios=?, palavras=?, atualizado_em=? WHERE id=?`).run(
      d.nome !== undefined && String(d.nome).trim() ? String(d.nome).trim().slice(0, 80) : n.nome, d.icone !== undefined ? String(d.icone || '') : n.icone,
      pais || n.pais, d.ativo === undefined ? n.ativo : (d.ativo ? 1 : 0), d.min_anuncios === undefined ? n.min_anuncios : Math.max(1, Number(d.min_anuncios) || 10),
      palavras ? JSON.stringify(palavras) : n.palavras, t, n.id);
    return nichoPub(q('SELECT * FROM spy_nicho WHERE id=?').get(n.id));
  }
  function regras() { const r = q('SELECT dados FROM spy_regras WHERE empresa=?').get(EMP); return Object.assign({}, REGRAS_PADRAO, (r && json(r.dados)) || {}); }
  function salvarRegras(d) {
    const r = regras();
    if (d.avisar_criativo_novo_em_ouro !== undefined) r.avisar_criativo_novo_em_ouro = !!d.avisar_criativo_novo_em_ouro;
    if (d.biblioteca_nova_min_anuncios !== undefined) r.biblioteca_nova_min_anuncios = Math.max(1, Number(d.biblioteca_nova_min_anuncios) || 30);
    if (d.multiplicador_escala !== undefined) r.multiplicador_escala = Math.max(1, Number(d.multiplicador_escala) || 3);
    if (d.horario_rotina !== undefined && /^([01]\d|2[0-3]):[0-5]\d$/.test(String(d.horario_rotina))) r.horario_rotina = String(d.horario_rotina);
    q('INSERT INTO spy_regras (empresa, dados) VALUES (?,?) ON CONFLICT(empresa) DO UPDATE SET dados=excluded.dados').run(EMP, JSON.stringify(r));
    return r;
  }

  // ── Bibliotecas ──
  const bibRow = id => q('SELECT * FROM spy_biblioteca WHERE id=? AND empresa=?').get(String(id || ''), EMP);
  function bibIgual(d) { return q('SELECT * FROM spy_biblioteca WHERE empresa=? AND tipo=? AND referencia=? AND pais=?').get(EMP, d.tipo, d.referencia, (d.pais || 'BR').toUpperCase()); }
  function dadosDaBiblioteca(d) {
    let l = null;
    if (d.link) l = SpyLink.ler(d.link);
    else if (d.tipo && d.referencia) {
      const tipo = String(d.tipo);
      if (!['pagina', 'dominio', 'palavra'].includes(tipo)) throw erroHttp('tipo tem que ser pagina, dominio ou palavra');
      const ref = String(d.referencia).trim();
      l = { tipo, referencia: tipo === 'dominio' ? SpyLink.limparDominio(ref) : tipo === 'pagina' ? ref.replace(/\D/g, '') : ref.replace(/\s+/g, ' '), pais: String(d.pais || 'BR').toUpperCase(), searchType: String(d.search_type || '') };
    }
    if (!l || !l.referencia) throw erroHttp('Não reconheci esse link. Cole o endereço da Biblioteca de Anúncios com view_all_page_id= ou q=.');
    if (d.pais) l.pais = String(d.pais).toUpperCase();
    return l;
  }
  // cria ou devolve a que já existe (tipo + referência + país); devolve {biblioteca, existente}
  function criarBiblioteca(d, por) {
    const l = dadosDaBiblioteca(d);
    const ja = bibIgual(l);
    if (ja) return { biblioteca: ja, existente: true };
    const t = agora(), id = novoId('bib-');
    const nicho = d.nicho_id ? q('SELECT id FROM spy_nicho WHERE id=? AND empresa=?').get(String(d.nicho_id), EMP) : null;
    q(`INSERT INTO spy_biblioteca (id, empresa, nome, nicho_id, tipo, referencia, pais, search_type, url_original, ouro, origem, status, motivo, ads_ativos, criado_em,
      criado_por, atualizado_em) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(id, EMP, String(d.nome || '').trim().slice(0, 120) || l.referencia, nicho ? nicho.id : null,
      l.tipo, l.referencia, l.pais || 'BR', l.searchType || '', /^https?:\/\//i.test(String(d.link || '')) ? String(d.link).slice(0, 1000) : '', d.ouro === false ? 0 : (d.ouro ? 1 : 0),
      d.origem || 'manual', d.status || 'na_fila', String(d.motivo || '').slice(0, 300), Math.max(0, Number(d.ads_ativos) || 0), t, String(por || ''), t);
    return { biblioteca: bibRow(id), existente: false };
  }
  function mudarBiblioteca(id, d) {
    const b = bibRow(id);
    if (!b) throw erroHttp('Biblioteca não encontrada.', 404);
    const nicho = d.nicho_id === undefined ? b.nicho_id : (d.nicho_id ? (q('SELECT id FROM spy_nicho WHERE id=? AND empresa=?').get(String(d.nicho_id), EMP) || {}).id || null : null);
    const st = d.status !== undefined && ['na_fila', 'coletada', 'sugerida', 'ignorada', 'erro'].includes(d.status) ? d.status : b.status;
    q('UPDATE spy_biblioteca SET nome=?, nicho_id=?, ouro=?, status=?, motivo=?, atualizado_em=? WHERE id=?').run(
      d.nome !== undefined && String(d.nome).trim() ? String(d.nome).trim().slice(0, 120) : b.nome, nicho, d.ouro === undefined ? b.ouro : (d.ouro ? 1 : 0), st,
      d.motivo !== undefined ? String(d.motivo || '').slice(0, 300) : b.motivo, agora(), b.id);
    return bibRow(b.id);
  }
  function serieDe(bibId, n) {
    return q('SELECT data, ads_ativos, criativos_ativos FROM spy_snapshot WHERE biblioteca_id=? ORDER BY data DESC LIMIT ?').all(bibId, n || 31).reverse()
      .map(s => ({ dia: s.data, ads: s.ads_ativos, criativos: s.criativos_ativos }));
  }
  function bibPub(b, extra) {
    if (!b) return null;
    const x = Object.assign({ id: b.id, nome: b.nome, nicho_id: b.nicho_id || '', tipo: b.tipo, referencia: b.referencia, pais: b.pais, ouro: !!b.ouro,
      origem: b.origem || 'manual', status: b.status || 'na_fila', motivo: b.motivo || '', link: b.url_original || SpyLink.montar({ tipo: b.tipo, referencia: b.referencia, pais: b.pais, searchType: b.search_type }),
      ads_ativos: b.ads_ativos || 0, ultima_coleta_em: b.ultima_coleta_em || null, erro: b.erro || '' }, extra || {});
    return x;
  }
  function listarBibliotecas(f) {
    f = f || {};
    const st = {};
    for (const r of q(`SELECT ab.biblioteca_id bib, COUNT(DISTINCT a.criativo_id) cr, MIN(a.inicio_veiculacao) ini FROM spy_anuncio_bib ab
      JOIN spy_anuncio a ON a.ad_archive_id=ab.ad_archive_id WHERE ab.ativo=1 GROUP BY ab.biblioteca_id`).all()) st[r.bib] = r;
    const agoraMs = agora();
    let l = q('SELECT * FROM spy_biblioteca WHERE empresa=? ORDER BY ouro DESC, ads_ativos DESC, criado_em').all(EMP).map(b => bibPub(b, {
      criativos: (st[b.id] || {}).cr || 0, mais_antigo_dias: (st[b.id] || {}).ini ? Math.floor((agoraMs - st[b.id].ini * 1000) / DIA) : null,
      serie: serieDe(b.id, f.dias ? f.dias + 1 : 31) }));
    if (f.nicho_id !== undefined) l = l.filter(b => (b.nicho_id || '') === (f.nicho_id || ''));
    if (f.ouro !== undefined) l = l.filter(b => b.ouro === !!f.ouro);
    if (f.status) l = l.filter(b => b.status === f.status);
    return l;
  }
  // anúncios no ar desta biblioteca cujo criativo ainda não tem vídeo (o link nunca veio, ou venceu)
  function midiasFaltando(bibId) {
    return q(`SELECT a.ad_archive_id FROM spy_anuncio_bib ab JOIN spy_anuncio a ON a.ad_archive_id=ab.ad_archive_id JOIN spy_criativo c ON c.id=a.criativo_id
      WHERE ab.biblioteca_id=? AND ab.ativo=1 AND (c.midia_status='sem_link' OR (c.midia_status='erro' AND c.midia_erro LIKE '%venceu%'))`).all(bibId).map(r => r.ad_archive_id);
  }
  // ── Busca do vídeo pelo id do anúncio (spy-navegador.js): um anúncio por criativo sem vídeo, um de cada vez ──
  const busca = { rodando: false, bib: null, total: 0, feitos: 0, achados: 0, erro: '', bloqueado_em: Number(cfgLer('busca_bloqueada_em')) || 0, fim_em: 0 };
  const bibsNaBusca = new Set();
  function paraBuscar(bibId, forcar) {
    return q(`SELECT c.id cid, (SELECT a.ad_archive_id FROM spy_anuncio a JOIN spy_anuncio_bib ab ON ab.ad_archive_id=a.ad_archive_id
        WHERE a.criativo_id=c.id AND ab.biblioteca_id=? AND ab.ativo=1 ORDER BY a.visto_ultima_vez_em DESC, a.ad_archive_id LIMIT 1) ad
      FROM spy_criativo c WHERE c.mesclado_em IS NULL AND (c.midia_status='sem_link' OR (c.midia_status='erro' AND c.midia_erro LIKE '%venceu%'))
      AND (? OR c.midia_tentativas < 3)`).all(bibId, forcar ? 1 : 0).filter(r => r.ad);
  }
  // o link chegou: grava no anúncio, junta pelo mesmo arquivo e manda baixar
  function aplicarLink(adId, r) {
    const a = q('SELECT * FROM spy_anuncio WHERE ad_archive_id=?').get(String(adId));
    if (!a) return null;
    let cid = resolver(a.criativo_id);
    const url = r && r.video && hostPermitido(r.video) ? r.video : (r && r.imagem && hostPermitido(r.imagem) ? r.imagem : '');
    if (!url) {
      q("UPDATE spy_criativo SET midia_tentativas=midia_tentativas+1, midia_erro=? WHERE id=? AND midia_status IN ('sem_link','erro')").run(String((r && r.erro) || 'o vídeo não apareceu').slice(0, 200), cid);
      return null;
    }
    const tipo = url === r.video ? 'video' : 'imagem';
    return tx(() => {
      q("UPDATE spy_anuncio SET midia_url=?, thumb_url=COALESCE(NULLIF(?,''), thumb_url), tipo=? WHERE ad_archive_id=?").run(url, r.capa && hostPermitido(r.capa) ? r.capa : (tipo === 'imagem' ? url : ''), tipo, a.ad_archive_id);
      const chave = (tipo === 'video' ? 'v:' : 'i:') + (nomeArquivo(url) || sha256(url).slice(0, 24));
      const ja = q('SELECT criativo_id FROM spy_chave WHERE chave=?').get(chave);
      if (ja && resolver(ja.criativo_id) !== cid) { const outro = resolver(ja.criativo_id); mesclar(cid, outro, agora()); cid = outro; }
      else q('INSERT OR IGNORE INTO spy_chave (chave, criativo_id) VALUES (?,?)').run(chave, cid);
      const c = q('SELECT midia_status FROM spy_criativo WHERE id=?').get(cid);
      if (c && c.midia_status !== 'ok') q("UPDATE spy_criativo SET tipo=?, midia_status='pendente', midia_erro=NULL, midia_tentativas=0 WHERE id=?").run(tipo, cid);
      return c && c.midia_status === 'ok' ? null : cid;
    });
  }
  // dispara a busca em segundo plano (depois de cada coleta e pelo botão "Baixar vídeos"); uma de cada vez
  function buscarVideos(bibId, forcar) {
    if (!o.buscador || !o.buscador.disponivel()) return { ok: false, motivo: 'O navegador do servidor não está instalado.' };
    if (forcar) q(`UPDATE spy_criativo SET midia_tentativas=0 WHERE midia_status IN ('sem_link','erro') AND id IN (SELECT a.criativo_id FROM spy_anuncio a
      JOIN spy_anuncio_bib ab ON ab.ad_archive_id=a.ad_archive_id WHERE ab.biblioteca_id=?)`).run(bibId);
    const aBuscar = paraBuscar(bibId, forcar).length;
    bibsNaBusca.add(bibId);
    if (!busca.rodando) {
      busca.rodando = true;
      (async () => {
        try {
          while (bibsNaBusca.size) {
            const bib = bibsNaBusca.values().next().value;
            bibsNaBusca.delete(bib);
            const l = paraBuscar(bib, forcar).slice(0, o.limiteBusca || 150);
            Object.assign(busca, { bib, total: l.length, feitos: 0, achados: 0, erro: '' });
            if (!l.length) continue;
            const r = await o.buscador.buscar(l.map(x => x.ad), async (adId, res) => {
              busca.feitos++;
              const cid = aplicarLink(adId, res);
              if (cid) { busca.achados++; enfileirar([cid]); }
            });
            if (r.bloqueado) { busca.bloqueado_em = agora(); cfgGravar('busca_bloqueada_em', busca.bloqueado_em); busca.erro = r.erro; bibsNaBusca.clear(); }
            else if (r.erro) busca.erro = r.erro;
            else if (r.achados) { busca.bloqueado_em = 0; cfgGravar('busca_bloqueada_em', 0); }
          }
        } catch (e) { busca.erro = e.message; console.error('[SPY] busca de vídeos:', e.message); }
        finally { busca.rodando = false; busca.fim_em = agora(); }
      })();
    }
    return { ok: true, a_buscar: aBuscar };
  }
  const estadoBusca = () => Object.assign({ disponivel: !!(o.buscador && o.buscador.disponivel()) }, busca);
  // Coleta registrada antes de 18/11 sem o link juntava os anúncios pela copy (a mesma copy roda com vídeos diferentes).
  // Separa uma vez: o 1º anúncio fica no criativo, cada um dos outros ganha o seu, com as mesmas etiquetas e família.
  // v2: a v1 só olhava tipo 'texto', mas a coleta real mandou midia.tipo 'video' sem link (criativo 'video' + 'sem_midia').
  function dividirPorCopy() {
    if (cfgLer('dividido_por_copy_v2')) return 0;
    let n = 0;
    tx(() => {
      for (const c of q("SELECT * FROM spy_criativo WHERE mesclado_em IS NULL AND midia_status='sem_midia'").all()) {
        const ads = q('SELECT ad_archive_id, midia_url FROM spy_anuncio WHERE criativo_id=? ORDER BY inicio_veiculacao, ad_archive_id').all(c.id);
        if (!ads.length || ads.some(a => a.midia_url)) continue;
        const ets = q("SELECT * FROM spy_etiqueta WHERE alvo_tipo='spy_criativo' AND alvo_id=?").all(c.id);
        q("UPDATE spy_criativo SET tipo='video', midia_status='sem_link' WHERE id=?").run(c.id);
        q('INSERT OR IGNORE INTO spy_chave (chave, criativo_id) VALUES (?,?)').run('a:' + ads[0].ad_archive_id, c.id);
        for (const a of ads.slice(1)) {
          const id = novoId('cr_'), t = agora();
          q(`INSERT INTO spy_criativo (id, tipo, midia_status, familia_id, partes, partes_origem, nao_modelar, nao_modelar_motivo, nao_modelar_origem, nao_modelar_por,
            primeiro_visto_em, ultimo_visto_em, criado_em, atualizado_em) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(id, 'video', 'sem_link', c.familia_id, c.partes, c.partes_origem,
            c.nao_modelar, c.nao_modelar_motivo, c.nao_modelar_origem, c.nao_modelar_por, c.primeiro_visto_em, c.ultimo_visto_em, t, t);
          for (const e of ets) q('INSERT OR IGNORE INTO spy_etiqueta (id, empresa, alvo_tipo, alvo_id, campo, valor, parte, origem, confianca, por, atualizado_em) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
            .run(novoId('et_'), e.empresa, e.alvo_tipo, id, e.campo, e.valor, e.parte, e.origem, e.confianca, e.por, e.atualizado_em);
          q('UPDATE spy_anuncio SET criativo_id=? WHERE ad_archive_id=?').run(id, a.ad_archive_id);
          q('INSERT OR IGNORE INTO spy_chave (chave, criativo_id) VALUES (?,?)').run('a:' + a.ad_archive_id, id);
          recalcular(id, agora());
          n++;
        }
        recalcular(c.id, agora());
      }
    });
    cfgGravar('dividido_por_copy_v2', new Date(agora()).toISOString());
    return n;
  }
  function adsConhecidos(bibId) { return q('SELECT ad_archive_id FROM spy_anuncio_bib WHERE biblioteca_id=? AND ativo=1').all(bibId).map(r => r.ad_archive_id); }

  // ── Criativos ──
  function resolver(id) { let x = id, n = 0; while (x && n++ < 20) { const r = q('SELECT mesclado_em FROM spy_criativo WHERE id=?').get(x); if (!r || !r.mesclado_em) return x; x = r.mesclado_em; } return x; }
  function criativoDe(ad, agoraMs) {
    const chaves = [ad.chaveMidia].concat(ad.collation_id ? ['col:' + ad.collation_id] : []);
    let id = null;
    for (const c of chaves) { const r = q('SELECT criativo_id FROM spy_chave WHERE chave=?').get(c); if (r) { id = resolver(r.criativo_id); break; } }
    if (!id) {
      id = novoId('cr_');
      q(`INSERT INTO spy_criativo (id, tipo, midia_status, primeiro_visto_em, ultimo_visto_em, criado_em, atualizado_em) VALUES (?,?,?,?,?,?,?)`)
        .run(id, ad.tipo, ad.midia ? 'pendente' : ad.tipo === 'texto' ? 'sem_midia' : 'sem_link', agoraMs, agoraMs, agoraMs, agoraMs);
    }
    for (const c of chaves) q('INSERT OR IGNORE INTO spy_chave (chave, criativo_id) VALUES (?,?)').run(c, id);
    return id;
  }
  // novo: entrou no ar nos últimos 7 dias (data de início do anúncio mais antigo dele; sem data, a 1ª vez que vimos)
  function statusDe(c, agoraMs) {
    if (!c.anuncios_ativos) return 'parou';
    if (c.tendencia === 'subiu') return 'escalando';
    const ini = c.inicio_mais_antigo ? c.inicio_mais_antigo * 1000 : c.primeiro_visto_em;
    if (ini && agoraMs - ini <= 7 * DIA) return 'novo';
    return 'estavel';
  }
  function recalcular(id, agoraMs) {
    const r = q(`SELECT COUNT(*) total, COALESCE(SUM(CASE WHEN ativo=1 THEN quantidade ELSE 0 END),0) ativos, MIN(inicio_veiculacao) ini, MIN(visto_primeira_vez_em) pv,
      MAX(visto_ultima_vez_em) uv, MAX(fim_veiculacao) fim FROM spy_anuncio WHERE criativo_id=?`).get(id);
    const c = q('SELECT tendencia FROM spy_criativo WHERE id=?').get(id) || {};
    const st = statusDe({ anuncios_ativos: r.ativos, tendencia: c.tendencia, inicio_mais_antigo: r.ini, primeiro_visto_em: r.pv }, agoraMs);
    q(`UPDATE spy_criativo SET anuncios_total=?, anuncios_ativos=?, inicio_mais_antigo=?, primeiro_visto_em=MIN(COALESCE(primeiro_visto_em, ?), ?),
      ultimo_visto_em=?, fim_mais_recente=?, status=?, atualizado_em=? WHERE id=?`).run(r.total, r.ativos, r.ini, r.pv || agoraMs, r.pv || agoraMs, r.uv, r.ativos ? null : r.fim, st, agoraMs, id);
  }
  function mesclar(de, para, agoraMs) {
    if (!de || !para || de === para) return;
    tx(() => {
      q('UPDATE spy_anuncio SET criativo_id=? WHERE criativo_id=?').run(para, de);
      q('UPDATE spy_chave SET criativo_id=? WHERE criativo_id=?').run(para, de);
      // etiquetas: a corrigida por gente sempre vale; a do Claude só entra onde não tem nada
      for (const e of q("SELECT * FROM spy_etiqueta WHERE alvo_tipo='spy_criativo' AND alvo_id=?").all(de)) {
        const ja = q("SELECT * FROM spy_etiqueta WHERE empresa=? AND alvo_tipo='spy_criativo' AND alvo_id=? AND campo=? AND parte=?").get(e.empresa, para, e.campo, e.parte);
        if (!ja) q('UPDATE spy_etiqueta SET alvo_id=? WHERE id=?').run(para, e.id);
        else if (e.origem === 'thiago' && ja.origem !== 'thiago') q('UPDATE spy_etiqueta SET valor=?, origem=?, confianca=?, por=?, atualizado_em=? WHERE id=?').run(e.valor, e.origem, e.confianca, e.por, e.atualizado_em, ja.id);
      }
      if (!q('SELECT 1 FROM spy_transcricao WHERE criativo_id=?').get(para)) q('UPDATE spy_transcricao SET criativo_id=? WHERE criativo_id=?').run(para, de);
      const a = q('SELECT * FROM spy_criativo WHERE id=?').get(de), b = q('SELECT * FROM spy_criativo WHERE id=?').get(para);
      if (a && b) {
        q(`UPDATE spy_criativo SET familia_id=COALESCE(familia_id, ?), partes=COALESCE(partes, ?), partes_origem=COALESCE(partes_origem, ?),
          primeiro_visto_em=MIN(COALESCE(primeiro_visto_em, ?), COALESCE(?, primeiro_visto_em)) WHERE id=?`).run(a.familia_id, a.partes, a.partes_origem, a.primeiro_visto_em, a.primeiro_visto_em, para);
        if (a.nao_modelar_origem === 'thiago' || (a.nao_modelar && !b.nao_modelar_origem)) q('UPDATE spy_criativo SET nao_modelar=?, nao_modelar_motivo=?, nao_modelar_origem=?, nao_modelar_por=? WHERE id=?').run(a.nao_modelar, a.nao_modelar_motivo, a.nao_modelar_origem, a.nao_modelar_por, para);
      }
      q("UPDATE spy_criativo SET mesclado_em=?, status='mesclado', atualizado_em=? WHERE id=?").run(para, agoraMs, de);
      // as fotos do dia passam a contar os dois como um só
      for (const s of q('SELECT id, anuncios_por_criativo FROM spy_snapshot WHERE anuncios_por_criativo LIKE ?').all('%"' + de + '"%')) {
        const m = json(s.anuncios_por_criativo) || {};
        if (m[de] == null) continue;
        m[para] = (m[para] || 0) + m[de]; delete m[de];
        q('UPDATE spy_snapshot SET anuncios_por_criativo=?, criativos_ativos=? WHERE id=?').run(JSON.stringify(m), Object.keys(m).length, s.id);
      }
      recalcular(para, agoraMs);
    });
  }

  // ── Coleta: chega do Claude pelo MCP ──
  function fotoAnterior(bibId, dia) {
    const s = q('SELECT * FROM spy_snapshot WHERE biblioteca_id=? AND data<? ORDER BY data DESC LIMIT 1').get(bibId, dia);
    if (!s) return null;
    const m = {};
    for (const [cid, n] of Object.entries(json(s.anuncios_por_criativo) || {})) { const r = resolver(cid); m[r] = (m[r] || 0) + n; }
    return { data: s.data, ads: s.ads_ativos, mapa: m };
  }
  // d: { dia?, total_ativos?, completa?, ativos_ids?, anuncios: [...] }
  //   anuncios: o que o Claude leu (detalhe completo); ativos_ids: todos os ids que estavam no ar hoje, inclusive os já conhecidos
  //   "saiu do ar" só vale com a lista completa: completa:true, ou a soma de anúncios chegou no total_ativos
  function registrarColeta(bibId, d, por) {
    const b = bibRow(bibId);
    if (!b) throw erroHttp('Biblioteca não encontrada: ' + bibId, 404);
    d = d || {};
    const hojeReal = diaBR(agora());
    const dia = d.dia && /^\d{4}-\d{2}-\d{2}$/.test(String(d.dia)) ? String(d.dia) : hojeReal;
    if (dia > hojeReal) throw erroHttp('O dia da coleta está no futuro: ' + dia);
    const ultimaFoto = q('SELECT MAX(data) d FROM spy_snapshot WHERE biblioteca_id=?').get(b.id).d;
    if (ultimaFoto && dia < ultimaFoto) throw erroHttp('Já existe coleta de ' + ultimaFoto + ' nesta biblioteca: não dá pra registrar um dia anterior (' + dia + ').');
    // a hora da coleta: agora, ou meio-dia do dia informado quando é de um dia que já passou
    const t0 = dia === hojeReal ? agora() : Date.parse(dia + 'T15:00:00Z');
    const anuncios = (Array.isArray(d.anuncios) ? d.anuncios : []).map(lerAnuncioMcp).filter(a => a.ad_archive_id);
    const ativos = new Set(anuncios.map(a => a.ad_archive_id).concat((Array.isArray(d.ativos_ids) ? d.ativos_ids : []).map(x => String(x).replace(/\D/g, '')).filter(Boolean)));
    if (!ativos.size) throw erroHttp('A coleta veio vazia: mande os anúncios em anuncios (e, se quiser, todos os ids no ar em ativos_ids).');
    return tx(() => {
      const antes = new Set(q('SELECT ad_archive_id FROM spy_anuncio_bib WHERE biblioteca_id=? AND ativo=1').all(b.id).map(r => r.ad_archive_id));
      const tocados = new Set(), novosAds = [], semDados = [];
      const porId = new Map(anuncios.map(a => [a.ad_archive_id, a]));
      for (const id of ativos) {
        const a = porId.get(id);
        const ja = q('SELECT criativo_id FROM spy_anuncio WHERE ad_archive_id=?').get(id);
        if (!a && !ja) { semDados.push(id); continue; }
        let cid;
        if (a) {
          cid = ja && ja.criativo_id ? resolver(ja.criativo_id) : criativoDe(a, t0);
          if (!ja) novosAds.push(id);
          q(`INSERT INTO spy_anuncio (ad_archive_id, page_id, page_name, copy, titulo, cta_tipo, cta_texto, link_destino, dominio, legenda, inicio_veiculacao,
              fim_veiculacao, ativo, quantidade, visto_primeira_vez_em, visto_ultima_vez_em, criativo_id, plataformas, pais, collation_id, tipo, midia_url, thumb_url, bruto_json)
              VALUES (?,?,?,?,?,?,?,?,?,?,?,NULL,1,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(ad_archive_id) DO UPDATE SET page_id=COALESCE(NULLIF(excluded.page_id,''), page_id), page_name=COALESCE(NULLIF(excluded.page_name,''), page_name),
              copy=COALESCE(NULLIF(excluded.copy,''), copy), titulo=COALESCE(NULLIF(excluded.titulo,''), titulo), cta_tipo=COALESCE(NULLIF(excluded.cta_tipo,''), cta_tipo),
              cta_texto=COALESCE(NULLIF(excluded.cta_texto,''), cta_texto), link_destino=COALESCE(NULLIF(excluded.link_destino,''), link_destino),
              dominio=COALESCE(NULLIF(excluded.dominio,''), dominio), legenda=COALESCE(NULLIF(excluded.legenda,''), legenda),
              inicio_veiculacao=COALESCE(excluded.inicio_veiculacao, inicio_veiculacao), fim_veiculacao=NULL, ativo=1, quantidade=excluded.quantidade,
              visto_ultima_vez_em=excluded.visto_ultima_vez_em, plataformas=excluded.plataformas, midia_url=COALESCE(NULLIF(excluded.midia_url,''), midia_url),
              thumb_url=COALESCE(NULLIF(excluded.thumb_url,''), thumb_url), bruto_json=excluded.bruto_json`)
            .run(id, a.page_id, a.page_name, a.copy, a.titulo, a.cta_tipo, a.cta_texto, a.link_destino, a.dominio, a.legenda, a.inicio, a.quantidade,
              t0, t0, cid, JSON.stringify(a.plataformas), b.pais, a.collation_id, a.tipo, a.midia, a.thumb, JSON.stringify((d.anuncios || []).find(x => String(x && (x.ad_archive_id || x.id) || '').replace(/\D/g, '') === id) || {}));
        } else {
          cid = resolver(ja.criativo_id);
          q('UPDATE spy_anuncio SET ativo=1, fim_veiculacao=NULL, visto_ultima_vez_em=? WHERE ad_archive_id=?').run(t0, id);
        }
        q(`INSERT INTO spy_anuncio_bib (ad_archive_id, biblioteca_id, ativo, visto_primeira_vez_em, visto_ultima_vez_em) VALUES (?,?,1,?,?)
          ON CONFLICT(ad_archive_id, biblioteca_id) DO UPDATE SET ativo=1, visto_ultima_vez_em=excluded.visto_ultima_vez_em`).run(id, b.id, t0, t0);
        tocados.add(cid);
      }
      const somaAtivos = () => (q(`SELECT COALESCE(SUM(a.quantidade),0) n FROM spy_anuncio a WHERE a.ad_archive_id IN (SELECT value FROM json_each(?))`).get(JSON.stringify([...ativos])) || {}).n || 0;
      const total = d.total_ativos != null && isFinite(Number(d.total_ativos)) ? Math.max(0, Math.round(Number(d.total_ativos))) : null;
      const completa = d.completa === true || (d.completa !== false && total != null && somaAtivos() >= total);
      const parados = [];
      if (completa) {
        for (const adId of antes) {
          if (ativos.has(adId)) continue;
          q('UPDATE spy_anuncio_bib SET ativo=0 WHERE ad_archive_id=? AND biblioteca_id=?').run(adId, b.id);
          q('UPDATE spy_anuncio SET ativo=0, fim_veiculacao=COALESCE(fim_veiculacao, ?) WHERE ad_archive_id=?').run(Math.floor(t0 / 1000), adId);
          const r = q('SELECT criativo_id FROM spy_anuncio WHERE ad_archive_id=?').get(adId);
          if (r && r.criativo_id) tocados.add(resolver(r.criativo_id));
          parados.push(adId);
        }
      }
      // foto do dia e tendência de cada criativo contra a foto anterior
      const mapa = {};
      for (const r of q(`SELECT a.criativo_id cid, SUM(a.quantidade) n FROM spy_anuncio_bib ab JOIN spy_anuncio a ON a.ad_archive_id=ab.ad_archive_id
        WHERE ab.biblioteca_id=? AND ab.ativo=1 GROUP BY a.criativo_id`).all(b.id)) { const cid = resolver(r.cid); mapa[cid] = (mapa[cid] || 0) + r.n; }
      const ant = fotoAnterior(b.id, dia);
      const mudancas = [];
      for (const cid of tocados) {
        const agoraN = mapa[cid] || 0, antesN = ant ? (ant.mapa[cid] != null ? ant.mapa[cid] : null) : null;
        const tend = antesN == null ? null : agoraN > antesN ? 'subiu' : agoraN < antesN ? 'caiu' : 'igual';
        q('UPDATE spy_criativo SET tendencia=?, anuncios_antes=? WHERE id=?').run(tend, antesN, cid);
        if (antesN != null && antesN !== agoraN) mudancas.push({ criativo_id: cid, antes: antesN, agora: agoraN });
      }
      for (const cid of tocados) recalcular(cid, t0);
      const criativosNovos = ant ? Object.keys(mapa).filter(c => ant.mapa[c] == null) : Object.keys(mapa).filter(c => (q('SELECT status FROM spy_criativo WHERE id=?').get(c) || {}).status === 'novo');
      const criativosParados = ant ? Object.keys(ant.mapa).filter(c => ant.mapa[c] > 0 && !mapa[c]) : [];
      const adsAtivos = total != null ? total : Object.values(mapa).reduce((s, n) => s + n, 0);
      q(`INSERT INTO spy_snapshot (biblioteca_id, data, ads_ativos, criativos_ativos, novos, parados, anuncios_por_criativo, criado_em) VALUES (?,?,?,?,?,?,?,?)
        ON CONFLICT(biblioteca_id, data) DO UPDATE SET ads_ativos=excluded.ads_ativos, criativos_ativos=excluded.criativos_ativos, novos=excluded.novos,
        parados=excluded.parados, anuncios_por_criativo=excluded.anuncios_por_criativo, criado_em=excluded.criado_em`)
        .run(b.id, dia, adsAtivos, Object.keys(mapa).length, criativosNovos.length, criativosParados.length, JSON.stringify(mapa), t0);
      q('INSERT INTO spy_coleta (id, biblioteca_id, dia, recebida_em, anuncios, total_ativos, novos, parados, completa, por) VALUES (?,?,?,?,?,?,?,?,?,?)')
        .run(novoId('col_'), b.id, dia, agora(), ativos.size, total, novosAds.length, parados.length, completa ? 1 : 0, String(por || ''));
      const ehUltima = !ultimaFoto || dia >= ultimaFoto;
      if (ehUltima) q("UPDATE spy_biblioteca SET ads_ativos=?, ultima_coleta_em=?, status=CASE WHEN status IN ('sugerida','ignorada') THEN status ELSE 'coletada' END, erro=?, atualizado_em=? WHERE id=?")
        .run(adsAtivos, t0, completa ? '' : 'A última coleta não leu a lista inteira: ninguém foi marcado como fora do ar nela.', agora(), b.id);
      const paginas = {};
      anuncios.forEach(a => { const p = paginas[a.page_id] || (paginas[a.page_id] = { page_id: a.page_id, page_name: a.page_name, anuncios: 0 }); p.anuncios += a.quantidade; });
      return {
        biblioteca_id: b.id, dia, anuncios_ativos: adsAtivos, anuncios_recebidos: ativos.size, anuncios_novos: novosAds.length, anuncios_parados: parados.length,
        criativos_ativos: Object.keys(mapa).length, criativos_novos: criativosNovos, criativos_parados: criativosParados,
        escalando: mudancas.filter(m => m.agora > m.antes), mudancas, foto_anterior: ant ? ant.data : null, ads_antes: ant ? ant.ads : null,
        completa, aviso: completa ? '' : 'A lista não veio completa (mande completa:true quando ler até o fim, ou total_ativos): ninguém foi marcado como fora do ar desta vez.',
        sem_dados: semDados, aviso_sem_dados: semDados.length ? 'Estes ids não são conhecidos: mande o anúncio inteiro em anuncios.' : undefined,
        paginas_meta: Object.values(paginas).sort((x, y) => y.anuncios - x.anuncios)
      };
    });
  }

  // ── Mídia: baixar, tirar a impressão digital, juntar os iguais, guardar e transcrever ──
  const midia = o.midia;
  // temporários fora do volume: o disco do Railway encheu uma vez e parou as vendas
  const tmpDir = o.tmpDir || path.join(require('os').tmpdir(), 'spy_tmp-' + process.pid);
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); fs.mkdirSync(tmpDir, { recursive: true }); } catch (e) {}
  function hostPermitido(u) {
    try {
      const x = new URL(u), h = x.hostname.toLowerCase();
      if (o.baixarQualquer && (h === '127.0.0.1' || h === 'localhost')) return true;
      return x.protocol === 'https:' && /(^|\.)(fbcdn\.net|facebook\.com|cdninstagram\.com|fbsbx\.com)$/.test(h);
    } catch (e) { return false; }
  }
  async function baixar(u, destino, max) {
    if (!hostPermitido(u)) throw new Error('endereço de mídia fora do Facebook: ' + (hostDe(u) || 'inválido'));
    const r = await fetch(u, { signal: AbortSignal.timeout(180000), redirect: 'follow' });
    if (!r.ok) throw new Error(r.status === 403 || r.status === 410 ? 'o link do Facebook venceu: a próxima coleta traz um novo' : 'o Facebook respondeu ' + r.status);
    if (!hostPermitido(r.url || u)) throw new Error('o link levou pra fora do Facebook');
    const lim = max || 150 * 1024 * 1024;   // o arquivo passa pela memória na hora de guardar
    if (Number(r.headers.get('content-length')) > lim) throw new Error('arquivo grande demais');
    const ws = fs.createWriteStream(destino);
    let tam = 0;
    const leitor = r.body.getReader();
    try {
      for (;;) {
        const { done, value } = await leitor.read();
        if (done) break;
        tam += value.length;
        if (tam > lim) throw new Error('arquivo grande demais');
        if (!ws.write(Buffer.from(value))) await new Promise(ok => ws.once('drain', ok));
      }
    } finally { await new Promise(ok => ws.end(ok)); }
    if (!tam) throw new Error('o Facebook mandou um arquivo vazio');
    return tam;
  }
  function hashArquivo(arq) {
    return new Promise((ok, falha) => { const h = crypto.createHash('sha256'); fs.createReadStream(arq).on('data', x => h.update(x)).on('end', () => ok(h.digest('hex'))).on('error', falha); });
  }
  // idioma pelo nicho da biblioteca (pt no BR, en no Nutra US); sem nicho, pelo país da biblioteca
  function idiomaDe(cid) {
    const r = q(`SELECT n.pais np, b.pais bp FROM spy_anuncio a JOIN spy_anuncio_bib ab ON ab.ad_archive_id=a.ad_archive_id JOIN spy_biblioteca b ON b.id=ab.biblioteca_id
      LEFT JOIN spy_nicho n ON n.id=b.nicho_id WHERE a.criativo_id=? ORDER BY a.visto_ultima_vez_em DESC LIMIT 1`).get(cid);
    const pais = (r && (r.np || r.bp)) || 'BR';
    return IDIOMA_DO_PAIS[pais] || '';
  }
  async function transcrever(cid, arqLocal) {
    const tr = o.transcritor && o.transcritor();
    if (!tr) { q("UPDATE spy_criativo SET transcricao_status='aguardando', transcricao_erro=? WHERE id=?").run('Falta a chave da AssemblyAI (ASSEMBLYAI_API_KEY no Railway).', cid); return; }
    const c = q('SELECT * FROM spy_criativo WHERE id=?').get(cid);
    if (!c || c.tipo !== 'video' || c.midia_status !== 'ok') return;
    // uma transcrição por vídeo (impressão digital): repetido não gasta a cota de novo
    if (q('SELECT 1 FROM spy_transcricao WHERE criativo_id=?').get(cid)) { q("UPDATE spy_criativo SET transcricao_status='ok' WHERE id=?").run(cid); return; }
    q("UPDATE spy_criativo SET transcricao_status='rodando', transcricao_erro=NULL WHERE id=?").run(cid);
    let tmpV = '';
    try {
      // só o áudio sobe (mono, 48 kbps), direto do arquivo, nunca por link público
      let origem = arqLocal;
      if (!origem) {
        const buf = await midia.buffer(c.arquivo);
        if (!buf) throw new Error('o vídeo guardado não foi encontrado');
        tmpV = path.join(tmpDir, cid + '-tr.mp4'); fs.writeFileSync(tmpV, buf); origem = tmpV;
      }
      const a = await ff(['-i', origem, '-vn', '-ac', '1', '-ar', '16000', '-c:a', 'aac', '-b:a', '48k', '-f', 'adts', 'pipe:1'], { ms: 120000, max: 60 * 1024 * 1024 });
      const buf = a.out.length > 1000 ? a.out : fs.readFileSync(origem);
      const t = await tr.transcrever(buf, idiomaDe(cid), o.esperaTranscricaoMs);
      q('INSERT INTO spy_transcricao (id, criativo_id, provedor, idioma, texto, segmentos, criado_em) VALUES (?,?,?,?,?,?,?)')
        .run(novoId('tr_'), cid, tr.nome, t.idioma, t.texto, JSON.stringify(t.segmentos), agora());
      q("UPDATE spy_criativo SET transcricao_status='ok', transcricao_erro=NULL WHERE id=?").run(cid);
    } catch (e) {
      q('UPDATE spy_criativo SET transcricao_status=?, transcricao_erro=? WHERE id=?').run(e.aguardar ? 'aguardando' : 'erro', String(e.message).slice(0, 300), cid);
    } finally { if (tmpV) { try { fs.unlinkSync(tmpV); } catch (e) {} } }
  }
  async function processar(cid0, opc) {
    opc = opc || {};
    const cid = resolver(cid0);
    const c = q('SELECT * FROM spy_criativo WHERE id=?').get(cid);
    if (!c) throw new Error('Criativo não encontrado: ' + cid0);
    const querTranscricao = opc.transcrever !== false && c.tipo === 'video';
    const temTranscricao = () => !!q('SELECT 1 FROM spy_transcricao WHERE criativo_id=?').get(cid);
    if (c.midia_status === 'ok') {
      if (querTranscricao && !temTranscricao() && c.transcricao_status !== 'rodando') await transcrever(cid);
      return cid;
    }
    if (c.midia_status === 'sem_midia' || c.midia_status === 'sem_link') return cid;   // sem link: quem busca é o navegador (buscarVideos)
    if (!midia) { q("UPDATE spy_criativo SET midia_status='aguardando', midia_erro=? WHERE id=?").run('O armazenamento dos vídeos (Cloudflare R2) não está ligado neste servidor.', cid); return cid; }
    if (!FFMPEG) { q("UPDATE spy_criativo SET midia_status='erro', midia_erro=? WHERE id=?").run('ffmpeg não está instalado neste servidor', cid); return cid; }
    const ad = q("SELECT * FROM spy_anuncio WHERE criativo_id=? AND midia_url<>'' ORDER BY visto_ultima_vez_em DESC LIMIT 1").get(cid);
    if (!ad) { q('UPDATE spy_criativo SET midia_status=? WHERE id=?').run(c.tipo === 'texto' ? 'sem_midia' : 'sem_link', cid); return cid; }
    const ext = c.tipo === 'video' ? 'mp4' : (/\.png(\?|$)/i.test(ad.midia_url) ? 'png' : /\.webp(\?|$)/i.test(ad.midia_url) ? 'webp' : 'jpg');
    const tmp = path.join(tmpDir, cid + '.' + ext), tmpThumb = path.join(tmpDir, cid + '-t.jpg');
    q("UPDATE spy_criativo SET midia_status='baixando', midia_tentativas=midia_tentativas+1 WHERE id=?").run(cid);
    try {
      if (linkVenceu(ad.midia_url, agora())) throw new Error('o link do Facebook venceu: a próxima coleta traz um novo');
      const tam = await baixar(ad.midia_url, tmp);
      const dig = await hashArquivo(tmp);
      // 1) arquivo idêntico a um que já temos: guardado uma vez só
      const igual = q("SELECT id FROM spy_criativo WHERE impressao_digital=? AND id<>? AND mesclado_em IS NULL AND midia_status='ok'").get(dig, cid);
      if (igual) { mesclar(cid, igual.id, agora()); q('INSERT OR IGNORE INTO spy_chave (chave, criativo_id) VALUES (?,?)').run('sha:' + dig, igual.id); return processar(igual.id, opc); }
      // 2) o mesmo vídeo recodificado (outra página subiu de novo)
      const an = c.tipo === 'video' ? await analisarVideo(tmp) : await analisarImagem(tmp);
      const faixa = Math.max(0.6, an.duracao * 0.02);
      const cands = q(`SELECT id, duracao_s, quadros, audio FROM spy_criativo WHERE tipo=? AND id<>? AND mesclado_em IS NULL AND midia_status='ok'
        AND duracao_s BETWEEN ? AND ?`).all(c.tipo, cid, an.duracao - faixa, an.duracao + faixa);
      for (const x of cands) {
        if (mesmoVideo(an, { duracao: x.duracao_s, quadros: json(x.quadros), audio: x.audio })) { mesclar(cid, x.id, agora()); return processar(x.id, opc); }
      }
      // 3) é novo: guarda o arquivo e a capa, pelo hash (o mesmo arquivo nunca sobe duas vezes)
      const chaveArq = (c.tipo === 'video' ? 'v/' : 'i/') + dig + '.' + ext;
      if (!(await midia.existe(chaveArq))) await midia.guardar(chaveArq, tmp);
      let chaveThumb = c.tipo === 'video' ? '' : chaveArq;
      if (c.tipo === 'video') {
        try {
          if (ad.thumb_url && !linkVenceu(ad.thumb_url, agora())) await baixar(ad.thumb_url, tmpThumb, 20 * 1024 * 1024);
          else throw new Error('sem capa');
        } catch (e) {
          await ff(['-y', '-ss', String(Math.min(1, an.duracao / 3).toFixed(2)), '-i', tmp, '-frames:v', '1', '-vf', 'scale=480:-2', '-q:v', '4', tmpThumb], { ms: 30000 });
        }
        if (fs.existsSync(tmpThumb) && fs.statSync(tmpThumb).size) {
          const tb = fs.readFileSync(tmpThumb);
          chaveThumb = 'i/' + sha256(tb) + '.jpg';
          if (!(await midia.existe(chaveThumb))) await midia.guardar(chaveThumb, tb);
        }
      }
      q(`UPDATE spy_criativo SET impressao_digital=?, quadros=?, audio=?, duracao_s=?, largura=?, altura=?, arquivo=?, thumb=?, tamanho=?,
        midia_status='ok', midia_erro=NULL, atualizado_em=? WHERE id=?`)
        .run(dig, JSON.stringify(an.quadros), an.audio, an.duracao, an.largura, an.altura, chaveArq, chaveThumb, tam, agora(), cid);
      q('INSERT OR IGNORE INTO spy_chave (chave, criativo_id) VALUES (?,?)').run('sha:' + dig, cid);
      if (querTranscricao && !temTranscricao()) await transcrever(cid, tmp);
      return cid;
    } catch (e) {
      q("UPDATE spy_criativo SET midia_status='erro', midia_erro=? WHERE id=?").run(String(e.message).slice(0, 300), cid);
      return cid;
    } finally {
      for (const f of [tmp, tmpThumb]) { try { fs.unlinkSync(f); } catch (e) {} }
    }
  }
  // fila: dois por vez, cada criativo uma vez; quem chama pode esperar o dele
  const fila = [], naFila = new Map();
  let rodando = 0;
  function enfileirar(ids, opc) {
    const promessas = [];
    for (const id of ids) {
      if (!naFila.has(id)) {
        let ok; const p = new Promise(r => { ok = r; });
        naFila.set(id, { p, ok, opc: opc || {} });
        fila.push(id);
      }
      promessas.push(naFila.get(id).p);
    }
    bombear();
    return Promise.all(promessas);
  }
  function bombear() {
    while (rodando < 2 && fila.length) {
      const id = fila.shift(), item = naFila.get(id);
      rodando++;
      processar(id, item.opc).catch(e => { console.error('[SPY] processar ' + id + ':', e.message); return id; })
        .then(r => { rodando--; naFila.delete(id); item.ok(r || id); bombear(); });
    }
  }
  function pendentesDaBiblioteca(bibId, tudo) {
    const comChave = !!(o.transcritor && o.transcritor());
    return q(`SELECT DISTINCT c.id FROM spy_criativo c JOIN spy_anuncio a ON a.criativo_id=c.id JOIN spy_anuncio_bib ab ON ab.ad_archive_id=a.ad_archive_id
      WHERE ab.biblioteca_id=? AND c.mesclado_em IS NULL AND (c.midia_status IN ('pendente','aguardando') OR (c.midia_status='erro' AND (c.midia_tentativas<3 OR ?))
      OR (c.midia_status='ok' AND c.tipo='video' AND (c.transcricao_status IS NULL OR (? AND c.transcricao_status IN ('aguardando','erro')))))`).all(bibId, tudo ? 1 : 0, comChave ? 1 : 0).map(r => r.id);
  }

  // ── Etiquetas (por empresa; spy_criativo hoje, meu_modulo depois) ──
  const FECHADOS = { angulo: SpyLink.ANGULOS, formato: SpyLink.FORMATOS };
  function validarEtiqueta(e) {
    const campo = String(e.campo || '').trim(), parte = String(e.parte || 'todo').trim(), valor = e.valor == null ? '' : String(e.valor).trim().slice(0, 300);
    if (!SpyLink.CAMPOS.includes(campo)) return 'campo desconhecido: ' + campo + ' (use ' + SpyLink.CAMPOS.join(', ') + ')';
    if (!SpyLink.PARTES.includes(parte)) return 'parte desconhecida: ' + parte + ' (use ' + SpyLink.PARTES.join(', ') + ')';
    if (valor && FECHADOS[campo] && !FECHADOS[campo].includes(valor)) return campo + ' "' + valor + '" não é um dos valores fechados: ' + FECHADOS[campo].join(', ');
    return { campo, parte, valor, confianca: e.confianca == null ? null : Math.max(0, Math.min(1, Number(e.confianca) || 0)) };
  }
  // origem 'claude' nunca passa por cima da correção de uma pessoa (origem 'thiago', com o nome em "por")
  function gravarEtiqueta(alvoTipo, alvoId, e, origem, por) {
    const ja = q('SELECT * FROM spy_etiqueta WHERE empresa=? AND alvo_tipo=? AND alvo_id=? AND campo=? AND parte=?').get(EMP, alvoTipo, alvoId, e.campo, e.parte);
    if (origem === 'claude' && ja && ja.origem === 'thiago') return 'protegida';
    if (origem === 'claude' && !e.valor) return 'vazia';
    if (ja) q('UPDATE spy_etiqueta SET valor=?, origem=?, confianca=?, por=?, atualizado_em=? WHERE id=?').run(e.valor, origem, origem === 'thiago' ? null : e.confianca, por || '', agora(), ja.id);
    else q('INSERT INTO spy_etiqueta (id, empresa, alvo_tipo, alvo_id, campo, valor, parte, origem, confianca, por, atualizado_em) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
      .run(novoId('et_'), EMP, alvoTipo, alvoId, e.campo, e.valor, e.parte, origem, origem === 'thiago' ? null : e.confianca, por || '', agora());
    return 'gravada';
  }
  function etiquetasDe(cid) {
    const r = {};
    for (const e of q("SELECT campo, valor, parte, origem, confianca, por, atualizado_em FROM spy_etiqueta WHERE empresa=? AND alvo_tipo='spy_criativo' AND alvo_id=?").all(EMP, cid)) {
      (r[e.campo] || (r[e.campo] = [])).push(e);
    }
    return r;
  }
  function familiaPorNome(nome, corpo) {
    const n = String(nome || '').trim().slice(0, 120);
    if (!n) return null;
    const ja = q('SELECT * FROM spy_familia').all().find(f => nrm(f.nome) === nrm(n));
    if (ja) { if (corpo && !ja.corpo_base) q('UPDATE spy_familia SET corpo_base=? WHERE id=?').run(String(corpo).slice(0, 20000), ja.id); return ja.id; }
    const id = novoId('fa_');
    q('INSERT INTO spy_familia (id, nome, corpo_base, criado_em) VALUES (?,?,?,?)').run(id, n, corpo ? String(corpo).slice(0, 20000) : null, agora());
    return id;
  }
  function validarPartes(p) {
    if (!Array.isArray(p)) return null;
    const l = p.map(x => ({ parte: String(x && x.parte || ''), inicio_s: Number(x && x.inicio_s), fim_s: Number(x && x.fim_s) }))
      .filter(x => ['gancho', 'corpo', 'cta'].includes(x.parte) && isFinite(x.inicio_s) && isFinite(x.fim_s) && x.fim_s > x.inicio_s && x.inicio_s >= 0);
    return l.length ? l.sort((a, b) => a.inicio_s - b.inicio_s) : null;
  }
  function salvarDoClaude(a) {
    const cid = resolver(String(a.criativo_id || ''));
    const c = q('SELECT * FROM spy_criativo WHERE id=?').get(cid);
    if (!c) throw new Error('Criativo não encontrado: ' + a.criativo_id);
    const out = { criativo_id: cid, gravadas: [], protegidas: [], erros: [] };
    if (cid !== a.criativo_id) out.aviso = a.criativo_id + ' foi juntado a ' + cid + ' (é o mesmo vídeo).';
    tx(() => {
      for (const e of (Array.isArray(a.etiquetas) ? a.etiquetas : [])) {
        const v = validarEtiqueta(e || {});
        if (typeof v === 'string') { out.erros.push(v); continue; }
        const r = gravarEtiqueta('spy_criativo', cid, v, 'claude', 'Claude');
        if (r === 'protegida') out.protegidas.push(v.campo + (v.parte !== 'todo' ? ' (' + v.parte + ')' : ''));
        else if (r === 'gravada') out.gravadas.push(v.campo + (v.parte !== 'todo' ? ' (' + v.parte + ')' : ''));
      }
      if (a.partes !== undefined) {
        const p = validarPartes(a.partes);
        if (!p) out.erros.push('partes: mande uma lista de {parte: gancho|corpo|cta, inicio_s, fim_s}');
        else if (c.partes_origem === 'thiago') out.protegidas.push('partes');
        else { q("UPDATE spy_criativo SET partes=?, partes_origem='claude' WHERE id=?").run(JSON.stringify(p), cid); out.gravadas.push('partes'); }
      }
      if (a.familia) {
        const nome = typeof a.familia === 'string' ? a.familia : a.familia.nome;
        const fid = familiaPorNome(nome, typeof a.familia === 'object' ? a.familia.corpo_base : '');
        if (fid) { q('UPDATE spy_criativo SET familia_id=? WHERE id=?').run(fid, cid); out.gravadas.push('familia'); }
      }
      if (a.nao_modelar !== undefined) {
        if (c.nao_modelar_origem === 'thiago') out.protegidas.push('nao_modelar');
        else { q("UPDATE spy_criativo SET nao_modelar=?, nao_modelar_motivo=?, nao_modelar_origem='claude', nao_modelar_por='Claude' WHERE id=?").run(a.nao_modelar ? 1 : 0, a.nao_modelar ? String(a.motivo || '').slice(0, 300) : null, cid); out.gravadas.push('nao_modelar'); }
      }
      q('UPDATE spy_criativo SET atualizado_em=? WHERE id=?').run(agora(), cid);
    });
    return out;
  }
  // a pessoa corrige na tela: só os campos que ela mudou ficam protegidos da rotina, com o nome dela
  function salvarDaTela(cid0, d, por) {
    const cid = resolver(cid0);
    if (!q('SELECT 1 FROM spy_criativo WHERE id=?').get(cid)) throw erroHttp('Criativo não encontrado.', 404);
    const erros = [];
    tx(() => {
      for (const [campo, valor] of Object.entries(d.campos || {})) {
        const v = validarEtiqueta({ campo, valor, parte: 'todo' });
        if (typeof v === 'string') { erros.push(v); continue; }
        gravarEtiqueta('spy_criativo', cid, v, 'thiago', por);
      }
      if (erros.length) throw erroHttp(erros.join(' · '));
      if (d.nao_modelar !== undefined) q("UPDATE spy_criativo SET nao_modelar=?, nao_modelar_motivo=?, nao_modelar_origem='thiago', nao_modelar_por=? WHERE id=?").run(d.nao_modelar ? 1 : 0, String(d.nao_modelar_motivo || '').slice(0, 300) || null, String(por || ''), cid);
    });
    return cid;
  }

  // ── Funis vigiados: o Claude abre a página no Chrome e manda os campos; aqui guarda a versão do dia e a diferença ──
  function registrarFunil(d, por) {
    d = d || {};
    const dominio = SpyLink.limparDominio(d.dominio || hostDe(d.url) || '');
    if (!SpyLink.ehDominio(dominio)) throw erroHttp('Mande o domínio do funil (ex.: concursa-paginas.vercel.app).');
    const dia = d.dia && /^\d{4}-\d{2}-\d{2}$/.test(String(d.dia)) ? String(d.dia) : diaBR(agora());
    const campos = {};
    for (const k of CAMPOS_FUNIL) if (d.campos && d.campos[k] != null && String(d.campos[k]).trim()) campos[k] = String(d.campos[k]).trim().slice(0, 1000);
    const bib = d.biblioteca_id ? bibRow(d.biblioteca_id) : null;
    const t = agora();
    return tx(() => {
      let f = q('SELECT * FROM spy_funil WHERE empresa=? AND dominio=?').get(EMP, dominio);
      if (!f) {
        const id = novoId('fu_');
        q('INSERT INTO spy_funil (id, empresa, biblioteca_id, dominio, url_atual, tipo, criado_em, atualizado_em) VALUES (?,?,?,?,?,?,?,?)')
          .run(id, EMP, bib ? bib.id : null, dominio, String(d.url || '').slice(0, 2000), String(d.tipo || '').slice(0, 40), t, t);
        f = q('SELECT * FROM spy_funil WHERE id=?').get(id);
      } else {
        q('UPDATE spy_funil SET biblioteca_id=COALESCE(?, biblioteca_id), url_atual=COALESCE(NULLIF(?,\'\'), url_atual), tipo=COALESCE(NULLIF(?,\'\'), tipo), atualizado_em=? WHERE id=?')
          .run(bib ? bib.id : null, String(d.url || '').slice(0, 2000), String(d.tipo || '').slice(0, 40), t, f.id);
      }
      const ant = q('SELECT * FROM spy_funil_versao WHERE funil_id=? AND dia<? ORDER BY dia DESC LIMIT 1').get(f.id, dia);
      const antC = ant ? (json(ant.campos) || {}) : null;
      const diff = [];
      if (antC) {
        const foraAntes = !!ant.fora_do_ar, foraAgora = !!d.fora_do_ar;
        if (foraAntes !== foraAgora) diff.push({ campo: 'fora_do_ar', antes: foraAntes ? 'fora do ar' : 'no ar', depois: foraAgora ? 'fora do ar' : 'no ar' });
        if (ant.url && d.url && ant.url !== String(d.url)) diff.push({ campo: 'url', antes: ant.url, depois: String(d.url) });
        for (const k of CAMPOS_FUNIL) if ((antC[k] || '') !== (campos[k] || '') && (campos[k] || antC[k])) diff.push({ campo: k, antes: antC[k] || '', depois: campos[k] || '' });
      }
      q(`INSERT INTO spy_funil_versao (id, funil_id, dia, capturado_em, url, campos, texto, leitura, fora_do_ar, diff, por) VALUES (?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(funil_id, dia) DO UPDATE SET capturado_em=excluded.capturado_em, url=excluded.url, campos=excluded.campos, texto=COALESCE(NULLIF(excluded.texto,''), texto),
        leitura=COALESCE(NULLIF(excluded.leitura,''), leitura), fora_do_ar=excluded.fora_do_ar, diff=excluded.diff, por=excluded.por`)
        .run(novoId('fv_'), f.id, dia, t, String(d.url || '').slice(0, 2000), JSON.stringify(campos), String(d.texto || '').slice(0, 200000), String(d.leitura || '').slice(0, 2000),
          d.fora_do_ar ? 1 : 0, JSON.stringify(diff), String(por || ''));
      return { funil_id: f.id, dominio, dia, primeira_versao: !ant, versao_anterior: ant ? ant.dia : null, mudou: diff.length > 0, diff };
    });
  }
  function funis() {
    return q('SELECT * FROM spy_funil WHERE empresa=? ORDER BY atualizado_em DESC').all(EMP).map(f => {
      const vs = q('SELECT dia, capturado_em, url, campos, leitura, fora_do_ar, diff, texto FROM spy_funil_versao WHERE funil_id=? ORDER BY dia').all(f.id)
        .map(v => ({ dia: v.dia, em: v.capturado_em, url: v.url, campos: json(v.campos) || {}, leitura: v.leitura || '', fora_do_ar: !!v.fora_do_ar, diff: json(v.diff) || [], tem_texto: !!v.texto }));
      const b = f.biblioteca_id ? bibRow(f.biblioteca_id) : null;
      return { id: f.id, dominio: f.dominio, url: f.url_atual, tipo: f.tipo || '', biblioteca: b ? { id: b.id, nome: b.nome } : null, versoes: vs };
    });
  }

  // ── Rodadas (log da rotina diária) ──
  function registrarRodada(d, por) {
    d = d || {};
    const id = novoId('ro_'), t = agora();
    const alertas = (Array.isArray(d.alertas) ? d.alertas : []).slice(0, 30).map(a => typeof a === 'string' ? { titulo: a } : { titulo: String(a.titulo || '').slice(0, 200), texto: String(a.texto || '').slice(0, 1000), tipo: String(a.tipo || '').slice(0, 40) }).filter(a => a.titulo);
    const erros = (Array.isArray(d.erros) ? d.erros : []).slice(0, 50).map(x => String(x).slice(0, 500));
    q('INSERT INTO spy_rodada (id, empresa, iniciada_em, terminada_em, numeros, resumo_texto, alertas, erros, criado_em, por) VALUES (?,?,?,?,?,?,?,?,?,?)')
      .run(id, EMP, lerData(d.iniciada_em) ? lerData(d.iniciada_em) * 1000 : t, lerData(d.terminada_em) ? lerData(d.terminada_em) * 1000 : t,
        JSON.stringify(d.numeros || {}), String(d.resumo_texto || '').slice(0, 5000), JSON.stringify(alertas), JSON.stringify(erros), t, String(por || ''));
    return { id, alertas, erros };
  }
  function rodadas(n) {
    return q('SELECT * FROM spy_rodada WHERE empresa=? ORDER BY criado_em DESC LIMIT ?').all(EMP, n || 30)
      .map(r => ({ id: r.id, iniciada_em: r.iniciada_em, terminada_em: r.terminada_em, numeros: json(r.numeros) || {}, resumo: r.resumo_texto || '', alertas: json(r.alertas) || [], erros: json(r.erros) || [], por: r.por || '' }));
  }

  // ── Leitura pra tela e pro MCP ──
  const diasDe = (c, agoraMs) => {
    const ini = c.inicio_mais_antigo ? c.inicio_mais_antigo * 1000 : c.primeiro_visto_em;
    if (!ini) return null;
    const fim = c.anuncios_ativos ? agoraMs : (c.fim_mais_recente ? c.fim_mais_recente * 1000 : c.ultimo_visto_em || agoraMs);
    return Math.max(0, Math.floor((fim - ini) / DIA));
  };
  function cartao(c, agoraMs, adsNaBib) {
    const ult = q('SELECT copy, page_name, link_destino, dominio, titulo FROM spy_anuncio WHERE criativo_id=? ORDER BY ativo DESC, visto_ultima_vez_em DESC LIMIT 1').get(c.id) || {};
    const fam = c.familia_id ? q('SELECT id, nome FROM spy_familia WHERE id=?').get(c.familia_id) : null;
    const paginas = q('SELECT DISTINCT page_name FROM spy_anuncio WHERE criativo_id=? AND ativo=1').all(c.id).map(r => r.page_name).filter(Boolean);
    const tr = q('SELECT segmentos FROM spy_transcricao WHERE criativo_id=? ORDER BY criado_em DESC LIMIT 1').get(c.id);
    const seg = tr ? (json(tr.segmentos) || [])[0] : null;
    return { id: c.id, tipo: c.tipo, status: statusDe(c, agoraMs), anuncios_ativos: adsNaBib != null ? adsNaBib : c.anuncios_ativos, anuncios_ativos_total: c.anuncios_ativos,
      anuncios_antes: c.anuncios_antes, anuncios_total: c.anuncios_total, dias_no_ar: diasDe(c, agoraMs),
      inicio: c.inicio_mais_antigo ? new Date(c.inicio_mais_antigo * 1000).toISOString().slice(0, 10) : null,
      copy: ult.copy || '', titulo: ult.titulo || '', fala: seg ? seg.texto : '', pagina: ult.page_name || '', paginas, destino: ult.link_destino || '', dominio: ult.dominio || '',
      familia: fam ? { id: fam.id, nome: fam.nome } : null, thumb: c.thumb || '', arquivo: c.arquivo || '', duracao_s: c.duracao_s,
      midia_status: c.midia_status, midia_erro: c.midia_erro, transcricao_status: c.transcricao_status, transcricao_erro: c.transcricao_erro,
      nao_modelar: !!c.nao_modelar, nao_modelar_motivo: c.nao_modelar_motivo || '', nao_modelar_origem: c.nao_modelar_origem || '', nao_modelar_por: c.nao_modelar_por || '',
      etiquetas: etiquetasDe(c.id) };
  }
  function detalheBiblioteca(bibId) {
    const b = bibRow(bibId);
    if (!b) return null;
    const agoraMs = agora();
    const porCr = {};
    for (const r of q(`SELECT a.criativo_id cid, SUM(CASE WHEN ab.ativo=1 THEN a.quantidade ELSE 0 END) n FROM spy_anuncio_bib ab JOIN spy_anuncio a ON a.ad_archive_id=ab.ad_archive_id
      WHERE ab.biblioteca_id=? GROUP BY a.criativo_id`).all(bibId)) { const c = resolver(r.cid); porCr[c] = (porCr[c] || 0) + (r.n || 0); }
    const criativos = Object.keys(porCr).map(id => q('SELECT * FROM spy_criativo WHERE id=?').get(id)).filter(Boolean).map(c => cartao(c, agoraMs, porCr[c.id]));
    const ativos = criativos.filter(c => c.anuncios_ativos > 0);
    const dom = {};
    for (const r of q(`SELECT a.dominio d, SUM(a.quantidade) n FROM spy_anuncio_bib ab JOIN spy_anuncio a ON a.ad_archive_id=ab.ad_archive_id
      WHERE ab.biblioteca_id=? AND ab.ativo=1 AND a.dominio<>'' GROUP BY a.dominio ORDER BY n DESC`).all(bibId)) dom[r.d] = r.n;
    const paginas = q(`SELECT a.page_name nome, SUM(a.quantidade) n FROM spy_anuncio_bib ab JOIN spy_anuncio a ON a.ad_archive_id=ab.ad_archive_id
      WHERE ab.biblioteca_id=? AND ab.ativo=1 GROUP BY a.page_name ORDER BY n DESC`).all(bibId);
    const fam = new Set(ativos.map(c => c.familia && c.familia.id).filter(Boolean));
    const domTop = Object.keys(dom)[0];
    const funil = domTop ? q('SELECT id FROM spy_funil WHERE empresa=? AND dominio=?').get(EMP, domTop) : null;
    const proc = { total: criativos.filter(c => c.tipo !== 'texto').length, guardados: criativos.filter(c => c.midia_status === 'ok').length,
      transcritos: criativos.filter(c => c.transcricao_status === 'ok').length,
      aguardando_transcricao: criativos.filter(c => c.transcricao_status === 'aguardando').length,
      pendentes: criativos.filter(c => ['pendente', 'baixando'].includes(c.midia_status) || c.transcricao_status === 'rodando' || (c.midia_status === 'ok' && c.tipo === 'video' && !c.transcricao_status)).length,
      erros: criativos.filter(c => c.midia_status === 'erro').length, aguardando_armazenamento: criativos.filter(c => c.midia_status === 'aguardando').length,
      aguardando_link: criativos.filter(c => c.midia_status === 'sem_link' && c.anuncios_ativos > 0).length };
    // aba Anúncios: todos os anúncios da biblioteca, com o criativo de cada um
    const anuncios = q(`SELECT a.ad_archive_id id, a.page_name pagina, substr(a.copy,1,160) copy, a.inicio_veiculacao ini, a.fim_veiculacao fim, ab.ativo, a.quantidade, a.criativo_id cid
      FROM spy_anuncio_bib ab JOIN spy_anuncio a ON a.ad_archive_id=ab.ad_archive_id WHERE ab.biblioteca_id=? ORDER BY ab.ativo DESC, a.inicio_veiculacao DESC, a.ad_archive_id LIMIT 3000`).all(bibId)
      .map(x => ({ id: x.id, pagina: x.pagina, copy: x.copy, inicio: x.ini ? new Date(x.ini * 1000).toISOString().slice(0, 10) : null, fim: x.fim ? new Date(x.fim * 1000).toISOString().slice(0, 10) : null,
        ativo: !!x.ativo, quantidade: x.quantidade, criativo_id: resolver(x.cid) }));
    return { biblioteca: bibPub(b), kpis: { ads_ativos: b.ads_ativos || 0, criativos: ativos.length, familias: fam.size,
      mais_antigo_dias: ativos.length ? Math.max.apply(null, ativos.map(c => c.dias_no_ar || 0)) : null },
      serie: serieDe(bibId, 31), dominios: dom, paginas, funil_id: funil ? funil.id : null, processamento: proc, criativos, anuncios,
      busca: Object.assign(estadoBusca(), { desta: busca.bib === bibId }) };
  }
  function detalheCriativo(cid0) {
    const agoraMs = agora(), cid = resolver(cid0);
    const c = q('SELECT * FROM spy_criativo WHERE id=?').get(cid);
    if (!c) return null;
    const anuncios = q(`SELECT ad_archive_id, page_id, page_name, copy, titulo, cta_tipo, cta_texto, link_destino, dominio, inicio_veiculacao, fim_veiculacao, ativo, quantidade,
      visto_primeira_vez_em, visto_ultima_vez_em, plataformas FROM spy_anuncio WHERE criativo_id=? ORDER BY ativo DESC, inicio_veiculacao`).all(cid)
      .map(a => Object.assign(a, { plataformas: json(a.plataformas) || [] }));
    const tr = q('SELECT provedor, idioma, texto, segmentos, criado_em FROM spy_transcricao WHERE criativo_id=? ORDER BY criado_em DESC LIMIT 1').get(cid);
    const bibs = q(`SELECT DISTINCT b.id, b.nome FROM spy_anuncio_bib ab JOIN spy_anuncio a ON a.ad_archive_id=ab.ad_archive_id JOIN spy_biblioteca b ON b.id=ab.biblioteca_id
      WHERE a.criativo_id=? AND b.empresa=?`).all(cid, EMP);
    const irmaos = c.familia_id ? q('SELECT * FROM spy_criativo WHERE familia_id=? AND id<>? AND mesclado_em IS NULL').all(c.familia_id, cid).map(x => cartao(x, agoraMs)) : [];
    return Object.assign(cartao(c, agoraMs), { pedido: cid0, juntado: cid !== cid0, largura: c.largura, altura: c.altura, tamanho: c.tamanho,
      partes: json(c.partes) || [], partes_origem: c.partes_origem || '',
      transcricao: tr ? { provedor: tr.provedor, idioma: tr.idioma, texto: tr.texto, segmentos: json(tr.segmentos) || [], em: tr.criado_em } : null,
      anuncios, bibliotecas: bibs, irmaos });
  }
  // Busca na fala: por palavra (ainda não por sentido) nas transcrições e na copy
  function buscar(f) {
    const termos = [...new Set(String(f.texto || '').toLowerCase().split(/\s+/).map(x => x.replace(/[^\p{L}\p{N}]/gu, '')).filter(x => x.length >= 3))].slice(0, 8);
    if (!termos.length) return { termos, resultados: [] };
    const agoraMs = agora(), out = [];
    const bate = t => { const s = nrm(t); return termos.some(x => s.includes(nrm(x))); };
    const meus = new Set(q('SELECT DISTINCT a.criativo_id cid FROM spy_anuncio a JOIN spy_anuncio_bib ab ON ab.ad_archive_id=a.ad_archive_id JOIN spy_biblioteca b ON b.id=ab.biblioteca_id WHERE b.empresa=?').all(EMP).map(r => resolver(r.cid)));
    for (const t of q('SELECT criativo_id, segmentos FROM spy_transcricao').all()) {
      const cid = resolver(t.criativo_id);
      if (!meus.has(cid)) continue;
      const c = q('SELECT * FROM spy_criativo WHERE id=?').get(cid);
      if (!c || (!f.incluir_parados && !c.anuncios_ativos)) continue;
      const partes = json(c.partes) || [];
      for (const s of (json(t.segmentos) || [])) {
        if (!bate(s.texto)) continue;
        const meio = (s.inicio_s + s.fim_s) / 2, p = partes.find(x => meio >= x.inicio_s && meio < x.fim_s);
        const parte = p ? p.parte : '';
        if (f.parte && f.parte !== 'todas' && parte !== f.parte) continue;
        out.push({ onde: 'fala', parte, inicio_s: s.inicio_s, trecho: s.texto, criativo: cartao(c, agoraMs) });
      }
    }
    if (!f.parte || f.parte === 'todas') {
      const vistos = new Set(out.map(x => x.criativo.id));
      for (const cid of meus) {
        if (vistos.has(cid)) continue;
        const c = q('SELECT * FROM spy_criativo WHERE id=? AND mesclado_em IS NULL').get(cid);
        if (!c || (!f.incluir_parados && !c.anuncios_ativos)) continue;
        const a = q('SELECT copy FROM spy_anuncio WHERE criativo_id=? AND copy<>\'\' ORDER BY ativo DESC LIMIT 1').get(cid);
        if (a && bate(a.copy)) out.push({ onde: 'copy', parte: '', inicio_s: null, trecho: a.copy.slice(0, 400), criativo: cartao(c, agoraMs) });
      }
    }
    return { termos, resultados: out.slice(0, 200) };
  }
  // Mercado: quantos criativos e concorrentes usam cada ângulo ou formato (o lado "Eu" entra quando os anúncios da TMX forem etiquetados)
  function mercado(f) {
    const dim = f.dim === 'formato' ? 'formato' : 'angulo';
    const agoraMs = agora(), linhas = {};
    const rows = q(`SELECT e.valor v, e.alvo_id cid FROM spy_etiqueta e WHERE e.empresa=? AND e.alvo_tipo='spy_criativo' AND e.campo=? AND e.valor<>''
      AND e.parte=(SELECT CASE WHEN EXISTS(SELECT 1 FROM spy_etiqueta x WHERE x.empresa=e.empresa AND x.alvo_tipo=e.alvo_tipo AND x.alvo_id=e.alvo_id AND x.campo=e.campo AND x.parte='todo') THEN 'todo' ELSE e.parte END)`).all(EMP, dim);
    for (const r of rows) {
      const cid = resolver(r.cid), c = q('SELECT * FROM spy_criativo WHERE id=?').get(cid);
      if (!c || !c.anuncios_total) continue;
      const bibs = q(`SELECT DISTINCT b.id, b.nicho_id FROM spy_anuncio_bib ab JOIN spy_anuncio a ON a.ad_archive_id=ab.ad_archive_id JOIN spy_biblioteca b ON b.id=ab.biblioteca_id
        WHERE a.criativo_id=? AND b.empresa=?`).all(cid, EMP);
      if (f.nicho_id && !bibs.some(b => b.nicho_id === f.nicho_id)) continue;
      const l = linhas[r.v] || (linhas[r.v] = { valor: r.v, criativos: new Set(), ativos: 0, concorrentes: new Set(), mais_antigo: 0 });
      l.criativos.add(cid); if (c.anuncios_ativos) l.ativos++;
      bibs.forEach(b => l.concorrentes.add(b.id));
      l.mais_antigo = Math.max(l.mais_antigo, diasDe(c, agoraMs) || 0);
    }
    const lista = (dim === 'formato' ? SpyLink.FORMATOS : SpyLink.ANGULOS).map(v => linhas[v] || { valor: v, criativos: new Set(), ativos: 0, concorrentes: new Set(), mais_antigo: 0 });
    return { dim, linhas: lista.map(l => ({ valor: l.valor, criativos: l.criativos.size, ativos: l.ativos, concorrentes: l.concorrentes.size, mais_antigo_dias: l.mais_antigo })),
      etiquetados: new Set(rows.map(r => resolver(r.cid))).size };
  }
  function kpis() {
    const meus = `SELECT DISTINCT a.criativo_id FROM spy_anuncio a JOIN spy_anuncio_bib ab ON ab.ad_archive_id=a.ad_archive_id JOIN spy_biblioteca b ON b.id=ab.biblioteca_id WHERE b.empresa=?`;
    const c = q(`SELECT COUNT(*) n, SUM(transcricao_status='ok') tr, SUM(transcricao_status='aguardando') ag, SUM(midia_status='aguardando') arm FROM spy_criativo WHERE mesclado_em IS NULL AND id IN (${meus})`).get(EMP);
    const ult = q('SELECT MAX(ultima_coleta_em) u FROM spy_biblioteca WHERE empresa=?').get(EMP);
    return { criativos: c.n || 0, transcritos: c.tr || 0, aguardando_transcricao: c.ag || 0, aguardando_armazenamento: c.arm || 0, ultima_coleta_em: ult.u || null };
  }

  return { db, q, EMP, cfgLer, cfgGravar, nichos, salvarNicho, regras, salvarRegras, bibRow, bibPub, criarBiblioteca, mudarBiblioteca, listarBibliotecas, adsConhecidos,
    registrarColeta, enfileirar, processar, pendentesDaBiblioteca, salvarDoClaude, salvarDaTela, detalheBiblioteca, detalheCriativo, registrarFunil, funis,
    registrarRodada, rodadas, buscar, mercado, kpis, resolver, statusDe, midiasFaltando, buscarVideos, estadoBusca, dividirPorCopy, aplicarLink, fila: () => ({ fila: fila.length, rodando }), agora };
}

// ══════════════════════════════════════════════
// Base inicial (seção 11 da especificação, com as decisões do Thiago em 18/11): começa do zero, as 110 bibliotecas do Spy
// Automático antigo NÃO entram. Navarro vai pro nicho Investimentos; ABRAhub fica "A definir".
// ══════════════════════════════════════════════
const NICHOS_BASE = [
  { id: 'nic-concurso', nome: 'Concurso', icone: '📚', pais: 'BR', ativo: true, min_anuncios: 10, palavras: ['concurso público', 'edital concurso', 'aprovação em concurso', 'IA para concurseiros', 'como estudar para concurso', 'questões da banca', 'concurseiro', 'passar em concurso público', 'concurso polícia', 'concurso PRF', 'apostila concurso', 'mapa mental concurso'] },
  { id: 'nic-fitness-gluteo', nome: 'Fitness · glúteo', icone: '🍑', pais: 'BR', ativo: true, min_anuncios: 10, palavras: ['treino de glúteo', 'bumbum', 'glúteo em casa', 'desafio glúteo'] },
  { id: 'nic-saude', nome: 'Saúde', icone: '🩺', pais: 'BR', ativo: true, min_anuncios: 10, palavras: ['emagrecer depois dos 40', 'barriga', 'dor nas articulações', 'médico revela'] },
  { id: 'nic-renda-extra', nome: 'Renda Extra', icone: '💰', pais: 'BR', ativo: false, min_anuncios: 10, palavras: ['renda extra', 'ganhar dinheiro em casa', 'afiliado tiktok shop'] },
  { id: 'nic-nutra-memoria', nome: 'Nutra US · memória', icone: '🧠', pais: 'US', ativo: true, min_anuncios: 20, palavras: ['honey trick memory loss', 'tap for recipe memory', 'brain fog trick', 'biblical honey memory trick'] },
  { id: 'nic-investimentos', nome: 'Investimentos', icone: '📈', pais: 'BR', ativo: true, min_anuncios: 10, palavras: [] }
];
const BIBS_BASE = [
  { nome: 'Evandro Guedes · Concursa IA', tipo: 'dominio', referencia: 'concursa-paginas.vercel.app', nicho: 'nic-concurso', ouro: true },
  { nome: 'Gabriel Navarro', tipo: 'pagina', referencia: '1140174149181447', nicho: 'nic-investimentos', ouro: true },
  { nome: 'Gustavo Nogueira · Aprovação Ágil', tipo: 'pagina', referencia: '315151789216919', nicho: 'nic-concurso', ouro: true },
  { nome: 'Método Gafanhoto', tipo: 'dominio', referencia: 'metodogafanhoto.com', nicho: 'nic-concurso', ouro: true },
  { nome: 'Enfermagem Resumida', tipo: 'pagina', referencia: '101093207914538', nicho: 'nic-concurso', ouro: true },
  { nome: 'Murilo Herbst', tipo: 'pagina', referencia: '2252051948396731', nicho: 'nic-fitness-gluteo', ouro: true },
  { nome: 'Truque do Bumbum · Elisa', tipo: 'dominio', referencia: 'truquedobumbum.com.br', nicho: 'nic-fitness-gluteo', ouro: true },
  { nome: 'Dr. Marcelo Roxo', tipo: 'pagina', referencia: '101330309320410', nicho: 'nic-saude', ouro: true },
  { nome: 'ABRAhub', tipo: 'pagina', referencia: '925935230607764', nicho: '', ouro: false, motivo: 'nicho a definir' }
];
function semente(N) {
  if (N.cfgLer('semente_v2')) return 0;
  NICHOS_BASE.forEach((n, i) => { if (!N.q('SELECT 1 FROM spy_nicho WHERE id=?').get(n.id)) N.salvarNicho(Object.assign({}, n, { ordem: i })); });
  let n = 0;
  for (const b of BIBS_BASE) {
    const r = N.criarBiblioteca({ tipo: b.tipo, referencia: b.referencia, pais: 'BR', nome: b.nome, nicho_id: b.nicho, ouro: b.ouro, motivo: b.motivo || '' }, 'Base inicial');
    if (!r.existente) n++;
  }
  N.cfgGravar('semente_v2', new Date().toISOString());
  return n;
}

// ══════════════════════════════════════════════
// Ferramentas do MCP (só na TMX). A rotina das 08:40 e o chat do Claude usam o mesmo caminho.
// ══════════════════════════════════════════════
const FERRAMENTAS = [
  { name: 'spy_ler_regras', soTmx: true,
    description: 'Spy de anúncios: o que a rotina deve olhar. Nichos ativos com país, palavras-chave e mínimo de anúncios pra virar biblioteca, as regras de alerta, o horário da rotina e as bibliotecas ouro (verificadas todo dia), com o link de cada uma na Biblioteca de Anúncios. Devolve JSON.',
    inputSchema: { type: 'object', properties: {} } },
  { name: 'spy_listar_bibliotecas', soTmx: true,
    description: 'Spy: as bibliotecas cadastradas (página, domínio ou palavra) com status, ouro, nicho, anúncios ativos, última coleta, o link pra abrir no Chrome e os ad_archive_id já conhecidos (no ar). Use antes de coletar: mande o anúncio inteiro só dos ids novos. Devolve JSON.',
    inputSchema: { type: 'object', properties: {
      nicho_id: { type: 'string' }, ouro: { type: 'boolean', description: 'true: só as ouro' },
      status: { type: 'string', enum: ['na_fila', 'coletada', 'erro', 'sugerida', 'ignorada'] } } } },
  { name: 'spy_salvar_biblioteca', soTmx: true,
    description: 'Spy: cadastra uma biblioteca (pelo link da Biblioteca de Anúncios, ou tipo + referencia + pais) ou muda uma existente (com id): nome, nicho, ouro, status. Se a mesma já existe (tipo + referência + país), devolve a existente. Devolve JSON.',
    inputSchema: { type: 'object', properties: {
      id: { type: 'string', description: 'Para mudar uma existente' },
      link: { type: 'string', description: 'Link da Biblioteca de Anúncios (view_all_page_id= ou q=)' },
      tipo: { type: 'string', enum: ['pagina', 'dominio', 'palavra'] }, referencia: { type: 'string', description: 'Id da página, domínio ou palavra' },
      pais: { type: 'string', description: 'Padrão BR' }, nome: { type: 'string' }, nicho_id: { type: 'string', description: 'Vazio = A definir' },
      ouro: { type: 'boolean', description: 'Ouro = coletada todo dia' }, status: { type: 'string', enum: ['na_fila', 'sugerida', 'ignorada'] } } } },
  { name: 'spy_salvar_nicho', soTmx: true,
    description: 'Spy: cria ou muda um nicho (com id, ou pelo nome): nome, país, palavras-chave (substitui a lista), mínimo de anúncios pra virar biblioteca, ativo. Devolve JSON.',
    inputSchema: { type: 'object', properties: {
      id: { type: 'string' }, nome: { type: 'string' }, pais: { type: 'string' }, ativo: { type: 'boolean' },
      min_anuncios: { type: 'number' }, palavras: { type: 'array', items: { type: 'string' } } } } },
  { name: 'spy_salvar_regras', soTmx: true,
    description: 'Spy: muda as regras de alerta e o horário da rotina. Devolve JSON com as regras.',
    inputSchema: { type: 'object', properties: {
      avisar_criativo_novo_em_ouro: { type: 'boolean' }, biblioteca_nova_min_anuncios: { type: 'number' },
      multiplicador_escala: { type: 'number', description: 'Avisa quando os anúncios de um criativo multiplicam por isso em 7 dias' },
      horario_rotina: { type: 'string', description: 'HH:MM, horário de Fortaleza' } } } },
  { name: 'spy_registrar_coleta', soTmx: true,
    description: 'Spy: grava o que você leu na Biblioteca de Anúncios de UMA biblioteca, num dia. O servidor grava ou atualiza os anúncios, marca como fora do ar os que sumiram (só se a lista estiver completa), tira a foto do dia e devolve o resumo (novos, parados, escalando). Mande em anuncios o anúncio inteiro dos ids novos (os já conhecidos podem ir só em ativos_ids). Não precisa do link do vídeo: o servidor busca sozinho, pelo id de cada anúncio, baixa, junta os vídeos iguais num criativo só e transcreve. Idempotente: repetir no mesmo dia refaz a foto do dia. Devolve JSON.',
    inputSchema: { type: 'object', properties: {
      biblioteca_id: { type: 'string' },
      dia: { type: 'string', description: 'AAAA-MM-DD, padrão hoje (Brasília)' },
      total_ativos: { type: 'number', description: 'O total de anúncios ativos que a Biblioteca mostra' },
      completa: { type: 'boolean', description: 'true quando você rolou a lista até o fim' },
      ativos_ids: { type: 'array', items: { type: 'string' }, description: 'Todos os ad_archive_id no ar hoje, inclusive os já conhecidos' },
      anuncios: { type: 'array', description: 'Anúncios lidos', items: { type: 'object', properties: {
        ad_archive_id: { type: 'string' }, page_id: { type: 'string' }, page_name: { type: 'string' }, copy: { type: 'string' }, titulo: { type: 'string' },
        cta: { type: 'string', description: 'Texto do botão' }, link_destino: { type: 'string' }, inicio_veiculacao: { type: 'string', description: 'AAAA-MM-DD' },
        plataformas: { type: 'array', items: { type: 'string' } }, quantidade: { type: 'number', description: '"N anúncios usam esse criativo e texto"; padrão 1' },
        midia: { type: 'object', properties: { tipo: { type: 'string', enum: ['video', 'imagem', 'carrossel', 'texto'] }, url_video: { type: 'string' }, url_imagem: { type: 'string' }, url_capa: { type: 'string' } } } },
        required: ['ad_archive_id'] } } }, required: ['biblioteca_id'] } },
  { name: 'spy_listar_criativos', soTmx: true,
    description: 'Spy: os criativos de uma biblioteca (vídeos iguais contam uma vez), com status (novo, escalando, estavel, parou), anúncios ativos, dias no ar, família, etiquetas, se já tem vídeo e transcrição. Com transcricao:true traz as falas com o tempo, pra você etiquetar e cortar. Devolve JSON.',
    inputSchema: { type: 'object', properties: {
      biblioteca_id: { type: 'string' }, status: { type: 'string', enum: ['novo', 'escalando', 'estavel', 'parou'] },
      sem_etiqueta: { type: 'boolean', description: 'true: só os que ainda não têm ângulo' }, transcricao: { type: 'boolean' },
      limite: { type: 'number', description: 'Padrão 50' } }, required: ['biblioteca_id'] } },
  { name: 'spy_processar_midia', soTmx: true,
    description: 'Spy: AÇÃO NO SERVIDOR. Baixa de novo, junta e transcreve os criativos pedidos (a coleta já faz isso sozinha; use pra quem ficou com erro ou aguardando). Espera até uns 100 segundos e devolve o status e a transcrição de cada um. Devolve JSON.',
    inputSchema: { type: 'object', properties: { criativo_ids: { type: 'array', items: { type: 'string' }, description: 'Até 20' } }, required: ['criativo_ids'] } },
  { name: 'spy_sugerir_biblioteca', soTmx: true,
    description: 'Spy: cria uma biblioteca com status "sugerida" (aparece pro Thiago aceitar ou ignorar). Use pra anunciante achado por palavra-chave que passou do mínimo do nicho e ainda não está cadastrado. Não duplica. Devolve JSON.',
    inputSchema: { type: 'object', properties: {
      nicho_id: { type: 'string' }, tipo: { type: 'string', enum: ['pagina', 'dominio', 'palavra'] }, referencia: { type: 'string' }, nome: { type: 'string' },
      motivo: { type: 'string' }, ads_ativos: { type: 'number' }, pais: { type: 'string' } }, required: ['tipo', 'referencia', 'nome'] } },
  { name: 'spy_salvar_criativo', soTmx: true,
    description: 'Spy: grava o que você estudou de um criativo: etiquetas, os cortes de gancho, corpo e CTA, a família e o "não modelar". Nunca passa por cima do que alguém da equipe corrigiu na tela (volta em protegidas). Ângulo aceita só: ' + SpyLink.ANGULOS.join(', ') + '. Formato aceita só: ' + SpyLink.FORMATOS.join(', ') + '. Devolve JSON.',
    inputSchema: { type: 'object', properties: {
      criativo_id: { type: 'string' },
      etiquetas: { type: 'array', description: 'Lista de {campo, valor, parte?, confianca?}. campo: ' + SpyLink.CAMPOS.join(', ') + '. parte: gancho, corpo, cta ou todo (padrão todo).',
        items: { type: 'object', properties: { campo: { type: 'string' }, valor: { type: 'string' }, parte: { type: 'string' }, confianca: { type: 'number' } }, required: ['campo', 'valor'] } },
      partes: { type: 'array', description: 'Cortes: lista de {parte: gancho|corpo|cta, inicio_s, fim_s}',
        items: { type: 'object', properties: { parte: { type: 'string' }, inicio_s: { type: 'number' }, fim_s: { type: 'number' } } } },
      familia: { type: 'string', description: 'Nome da família (mesmo corpo, ganchos diferentes); cria se não existir' },
      nao_modelar: { type: 'boolean' }, motivo: { type: 'string' } }, required: ['criativo_id'] } },
  { name: 'spy_registrar_funil', soTmx: true,
    description: 'Spy: grava a foto do dia da página de destino de um concorrente (você abre no Chrome e lê). O servidor guarda a versão e devolve o que mudou desde a anterior. campos: ' + CAMPOS_FUNIL.join(', ') + '. Idempotente por domínio + dia. Devolve JSON.',
    inputSchema: { type: 'object', properties: {
      dominio: { type: 'string' }, url: { type: 'string', description: 'Endereço final, depois dos redirecionamentos' }, biblioteca_id: { type: 'string' },
      dia: { type: 'string', description: 'AAAA-MM-DD, padrão hoje' }, tipo: { type: 'string', description: 'vsl, live, imersao, quiz, advertorial, checkout_direto, outro' },
      campos: { type: 'object', properties: Object.fromEntries(CAMPOS_FUNIL.map(k => [k, { type: 'string' }])) },
      texto: { type: 'string', description: 'O texto da página' }, leitura: { type: 'string', description: 'Sua leitura curta da mudança' },
      fora_do_ar: { type: 'boolean' } }, required: ['dominio'] } },
  { name: 'spy_registrar_rodada', soTmx: true,
    description: 'Spy: grava o resumo da rotina do dia (números, resumo e erros) e manda os alertas pro Thiago no app. Devolve JSON.',
    inputSchema: { type: 'object', properties: {
      iniciada_em: { type: 'string' }, terminada_em: { type: 'string' },
      numeros: { type: 'object', description: 'nichos, palavras_buscadas, bibliotecas_verificadas, anuncios_novos, criativos_novos, parados, sugestoes, funis_mudaram' },
      resumo_texto: { type: 'string', description: 'O resumo do dia e as 3 coisas mais importantes pro Thiago olhar' },
      alertas: { type: 'array', items: { type: 'object', properties: { titulo: { type: 'string' }, texto: { type: 'string' }, tipo: { type: 'string' } } } },
      erros: { type: 'array', items: { type: 'string' } } } } }
];

module.exports = function montarSpy(d) {
  const { app, authUsuario, SOU_TMX, DATA_DIR, hosp } = d;
  const ferramentasMcp = FERRAMENTAS;
  if (!SOU_TMX) {
    // numa empresa o Spy não existe (decisão do Thiago em 18/11); a Ad Library antiga continua como era
    app.all(/^\/api\/spy\/(painel|bibliotecas|criativos|midia|funis|busca|mercado|config|nichos|regras)(\/|$)/, (req, res) => res.status(404).json({ error: 'O Spy de anúncios fica só na TMX.' }));
    return { ferramentasMcp, mcp: async () => { throw new Error('O Spy de anúncios fica só na TMX.'); } };
  }
  const agora = d.agora || (() => Date.now());
  const ehDono = d.ehDono || (() => false);
  const usaR2 = !!(hosp && hosp.ligada && hosp.ligada() && hosp.midiaGuardar) && process.env.SPY_MIDIA !== 'disco';
  // nunca no volume do Railway: sem o R2 em produção, o vídeo espera o armazenamento ser ligado
  const midia = usaR2 ? midiaR2(hosp) : (fs.existsSync('/data') ? null : midiaDisco(path.join(DATA_DIR, 'spy_midia')));
  // o navegador que busca o vídeo pelo id do anúncio (SPY_BUSCADOR=desligado tira; nos testes entra um de mentira)
  const buscador = d.buscador !== undefined ? d.buscador : (process.env.SPY_BUSCADOR === 'desligado' ? null : require('./spy-navegador')());
  const N = criarNucleo({ dir: DATA_DIR, agora, midia, empresa: 'tmx', buscador,
    baixarQualquer: !!so_teste('SPY_MIDIA_LIVRE_TESTE'),
    transcritor: () => process.env.ASSEMBLYAI_API_KEY ? transcritorAssembly(process.env.ASSEMBLYAI_API_KEY, so_teste('ASSEMBLYAI_BASE_TESTE') || 'https://api.assemblyai.com') : null });
  console.log('[SPY] pronto · vídeos em ' + (midia ? midia.nome : 'NENHUM (R2 desligado)') + ' · ffmpeg ' + (FFMPEG ? 'ok' : 'FALTANDO') + ' · AssemblyAI ' + (process.env.ASSEMBLYAI_API_KEY ? 'ok' : 'sem chave'));
  try { const n = semente(N); if (n) console.log('[SPY] base inicial: ' + n + ' bibliotecas e os nichos.'); } catch (e) { console.error('[SPY] base inicial falhou:', e.message); }
  try { const n = N.dividirPorCopy(); if (n) console.log('[SPY] ' + n + ' anúncios que estavam juntos só pela copy viraram criativos próprios.'); } catch (e) { console.error('[SPY] divisão por copy falhou:', e.message); }

  const config = () => ({ assemblyai: !!process.env.ASSEMBLYAI_API_KEY, ffmpeg: !!FFMPEG, midia: midia ? midia.nome : 'nenhum', fila: N.fila(), busca: N.estadoBusca() });
  // depois de cada coleta: baixa o que já tem link e manda o navegador buscar o vídeo dos que não têm
  function aposColeta(bibId) { const p = N.pendentesDaBiblioteca(bibId); if (p.length) N.enfileirar(p); const b = midia ? N.buscarVideos(bibId) : { a_buscar: 0 }; return { na_fila: p.length, a_buscar: b.a_buscar || 0 }; }
  const quem = req => (req.user && req.user.nome) || '';
  const resp = (res, fn) => { try { res.json(Object.assign({ ok: true }, fn())); } catch (e) { res.status(e.http || 400).json({ error: e.message }); } };
  // ⚙ Configurações (nichos, regras e rotina): só a conta do Thiago (decisão dele em 18/11). O MCP continua podendo: o token é dele.
  const soDono = (req, res, next) => authUsuario(req, res, () => ehDono(req) ? next() : res.status(403).json({ error: 'As configurações do Spy são só da conta do Thiago.' }));

  // ══ Rotas da tela (toda a equipe da TMX) ══
  app.get('/api/spy/painel', authUsuario, (req, res) => resp(res, () => ({ config: config(), dono: !!ehDono(req), nichos: N.nichos(),
    bibliotecas: N.listarBibliotecas(), kpis: N.kpis() })));
  app.post('/api/spy/bibliotecas', authUsuario, (req, res) => resp(res, () => {
    const c = req.body || {};
    const r = N.criarBiblioteca({ link: c.link, nome: c.nome, nicho_id: c.nicho_id, ouro: c.ouro !== false }, quem(req));
    return { existente: r.existente, biblioteca: N.bibPub(r.biblioteca) };
  }));
  app.post('/api/spy/bibliotecas/:id', authUsuario, (req, res) => resp(res, () => {
    const c = req.body || {}, m = {};
    ['nome', 'nicho_id', 'ouro', 'status'].forEach(k => { if (c[k] !== undefined) m[k] = c[k]; });
    return { biblioteca: N.bibPub(N.mudarBiblioteca(req.params.id, m)) };
  }));
  app.get('/api/spy/bibliotecas/:id', authUsuario, (req, res) => {
    const det = N.detalheBiblioteca(req.params.id);
    if (!det) return res.status(404).json({ error: 'Biblioteca não encontrada.' });
    res.json(Object.assign({ ok: true, config: config() }, det));
  });
  // botão "Baixar vídeos": baixa o que tem link e busca no Facebook o vídeo de quem não tem
  app.post('/api/spy/bibliotecas/:id/processar', authUsuario, (req, res) => {
    if (!N.bibRow(req.params.id)) return res.status(404).json({ error: 'Biblioteca não encontrada.' });
    const p = N.pendentesDaBiblioteca(req.params.id, true);
    N.q("UPDATE spy_criativo SET midia_tentativas=0 WHERE midia_status='erro' AND id IN (SELECT value FROM json_each(?))").run(JSON.stringify(p));
    if (p.length) N.enfileirar(p);
    const b = midia ? N.buscarVideos(req.params.id, true) : { ok: false, motivo: 'O armazenamento dos vídeos não está ligado.' };
    res.json({ ok: true, na_fila: p.length, a_buscar: b.a_buscar || 0, motivo: b.ok ? '' : b.motivo });
  });
  app.get('/api/spy/criativos/:id', authUsuario, (req, res) => {
    const c = N.detalheCriativo(req.params.id);
    if (!c) return res.status(404).json({ error: 'Criativo não encontrado.' });
    res.json({ ok: true, criativo: c });
  });
  app.post('/api/spy/criativos/:id/etiquetas', authUsuario, (req, res) => resp(res, () => ({ criativo: N.detalheCriativo(N.salvarDaTela(req.params.id, req.body || {}, quem(req))) })));
  app.post('/api/spy/criativos/:id/processar', authUsuario, (req, res) => {
    const cid = N.resolver(req.params.id), c = N.detalheCriativo(cid);
    if (!c) return res.status(404).json({ error: 'Criativo não encontrado.' });
    N.q("UPDATE spy_criativo SET midia_tentativas=0 WHERE id=? AND midia_status='erro'").run(cid);
    // sem link (ou link vencido): o navegador busca de novo no Facebook
    if (midia && (c.midia_status === 'sem_link' || (c.midia_status === 'erro' && /venceu/.test(c.midia_erro || '')))) c.bibliotecas.forEach(b => N.buscarVideos(b.id, true));
    else N.enfileirar([cid]);
    res.json({ ok: true });
  });
  app.get('/api/spy/funis', authUsuario, (req, res) => resp(res, () => ({ funis: N.funis(), vigiar: json(N.cfgLer('vigiar')) || null })));
  app.post('/api/spy/funis/vigiar', authUsuario, (req, res) => resp(res, () => {
    const v = {}; Object.entries((req.body || {}).vigiar || {}).forEach(([k, x]) => { if (CAMPOS_FUNIL.concat(['url', 'fora_do_ar']).includes(k)) v[k] = !!x; });
    N.cfgGravar('vigiar', JSON.stringify(v)); return { vigiar: v };
  }));
  app.get('/api/spy/busca', authUsuario, (req, res) => resp(res, () => N.buscar({ texto: req.query.q, parte: req.query.parte, incluir_parados: req.query.parados === '1' })));
  app.get('/api/spy/mercado', authUsuario, (req, res) => resp(res, () => N.mercado({ dim: req.query.dim, nicho_id: req.query.nicho || '' })));
  // ══ Configurações: só o Thiago ══
  app.get('/api/spy/config', soDono, (req, res) => resp(res, () => ({ nichos: N.nichos(), regras: N.regras(), rodadas: N.rodadas(30),
    sugeridas: N.listarBibliotecas({ status: 'sugerida' }), ouro: N.listarBibliotecas({ ouro: true }).length })));
  app.post('/api/spy/nichos', soDono, (req, res) => resp(res, () => ({ nicho: N.salvarNicho(req.body || {}) })));
  app.post('/api/spy/regras', soDono, (req, res) => resp(res, () => ({ regras: N.salvarRegras(req.body || {}) })));
  // mídia guardada: endereço = sha256 do arquivo (não dá pra adivinhar) e aberto, pro <video> e o <img> funcionarem
  app.get('/api/spy/midia/:pasta/:arq', async (req, res) => {
    const { pasta, arq } = req.params;
    if (!midia || !/^[vi]$/.test(pasta) || !/^[a-f0-9]{64}\.(mp4|jpg|png|webp)$/.test(arq)) return res.status(404).end();
    let faixa = null;
    const m = String(req.headers.range || '').match(/^bytes=(\d*)-(\d*)$/);
    if (m && (m[1] || m[2])) faixa = m[1] ? { ini: +m[1], fim: m[2] ? +m[2] : null } : { ult: +m[2] };
    try {
      const r = await midia.ler(pasta + '/' + arq, faixa);
      if (!r) return res.status(404).end();
      if (r.invalida) { res.setHeader('Content-Range', 'bytes */' + r.tam); return res.status(416).end(); }
      res.setHeader('Content-Type', TIPOS[arq.split('.').pop()]);
      res.setHeader('Accept-Ranges', 'bytes');
      res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
      res.setHeader('Content-Length', String(r.fim - r.ini + 1));
      if (r.parcial) { res.status(206); res.setHeader('Content-Range', 'bytes ' + r.ini + '-' + r.fim + '/' + r.tam); }
      r.corpo.on('error', () => { try { res.destroy(); } catch (e) {} });
      r.corpo.pipe(res);
    } catch (e) { console.error('[SPY] mídia:', e.message); if (!res.headersSent) res.status(502).end(); }
  });

  // ══ MCP ══
  const J = o => JSON.stringify(o);
  async function mcp(nome, a, tk) {
    a = a || {};
    const por = 'Claude · token ' + ((tk && tk.nome) || '');
    const comConhecidos = b => Object.assign({}, b, { anuncios_conhecidos: N.adsConhecidos(b.id) });
    if (nome === 'spy_ler_regras') return J({ nichos: N.nichos().filter(n => n.ativo), nichos_pausados: N.nichos().filter(n => !n.ativo).map(n => ({ id: n.id, nome: n.nome })),
      regras: N.regras(), bibliotecas_ouro: N.listarBibliotecas({ ouro: true }).map(b => ({ id: b.id, nome: b.nome, tipo: b.tipo, referencia: b.referencia, pais: b.pais, nicho_id: b.nicho_id, link: b.link, ads_ativos: b.ads_ativos, ultima_coleta_em: b.ultima_coleta_em })) });
    if (nome === 'spy_listar_bibliotecas') {
      const f = {}; if (a.nicho_id !== undefined) f.nicho_id = a.nicho_id; if (a.ouro !== undefined) f.ouro = a.ouro; if (a.status) f.status = a.status;
      const l = N.listarBibliotecas(f).map(b => { delete b.serie; return comConhecidos(b); });
      return J({ total: l.length, bibliotecas: l });
    }
    if (nome === 'spy_salvar_biblioteca') {
      if (a.id) { const m = {}; ['nome', 'nicho_id', 'ouro', 'status'].forEach(k => { if (a[k] !== undefined) m[k] = a[k]; }); return J({ biblioteca: N.bibPub(N.mudarBiblioteca(a.id, m)) }); }
      const r = N.criarBiblioteca({ link: a.link, tipo: a.tipo, referencia: a.referencia, pais: a.pais, nome: a.nome, nicho_id: a.nicho_id, ouro: a.ouro === true, status: a.status }, por);
      return J({ criada: !r.existente, ja_existia: r.existente, biblioteca: N.bibPub(r.biblioteca) });
    }
    if (nome === 'spy_salvar_nicho') return J({ nicho: N.salvarNicho(a) });
    if (nome === 'spy_salvar_regras') return J({ regras: N.salvarRegras(a) });
    if (nome === 'spy_registrar_coleta') {
      const r = N.registrarColeta(String(a.biblioteca_id || ''), a, por);
      const ap = aposColeta(r.biblioteca_id);
      r.videos_na_fila = ap.na_fila; r.videos_a_buscar = ap.a_buscar;
      if (ap.a_buscar) r.aviso_videos = 'O servidor vai buscar no Facebook, um por um, o vídeo de ' + ap.a_buscar + ' criativo(s) sem vídeo. Não precisa mandar link.';
      if (!midia) r.aviso_midia = 'O armazenamento dos vídeos (R2) não está ligado: os anúncios foram gravados, os vídeos esperam.';
      return J(r);
    }
    if (nome === 'spy_listar_criativos') {
      const det = N.detalheBiblioteca(String(a.biblioteca_id || ''));
      if (!det) throw new Error('biblioteca não encontrada');
      let l = det.criativos;
      if (a.status) l = l.filter(c => c.status === a.status);
      if (a.sem_etiqueta) l = l.filter(c => !c.etiquetas.angulo);
      l.sort((x, y) => y.anuncios_ativos - x.anuncios_ativos || (y.dias_no_ar || 0) - (x.dias_no_ar || 0));
      const lim = Math.min(Math.max(Number(a.limite) || 50, 1), 200);
      return J({ biblioteca: det.biblioteca.nome, total: l.length, criativos: l.slice(0, lim).map(c => {
        const x = { id: c.id, tipo: c.tipo, status: c.status, anuncios_ativos: c.anuncios_ativos, dias_no_ar: c.dias_no_ar, inicio: c.inicio, pagina: c.pagina, copy: c.copy.slice(0, 600),
          destino: c.dominio, familia: c.familia && c.familia.nome, tem_video: c.midia_status === 'ok', transcricao: c.transcricao_status || 'pendente', nao_modelar: c.nao_modelar,
          etiquetas: Object.fromEntries(Object.entries(c.etiquetas).map(([k, v]) => [k, v.map(e => ({ valor: e.valor, parte: e.parte, origem: e.origem === 'thiago' ? 'corrigido por ' + (e.por || 'alguém') : 'claude' }))])) };
        if (a.transcricao) { const dc = N.detalheCriativo(c.id); x.duracao_s = dc.duracao_s; x.falas = dc.transcricao ? dc.transcricao.segmentos : null; x.partes = dc.partes; }
        return x; }) });
    }
    if (nome === 'spy_processar_midia') {
      const ids = (Array.isArray(a.criativo_ids) ? a.criativo_ids : []).map(String).filter(Boolean).slice(0, 20);
      if (!ids.length) throw new Error('mande criativo_ids');
      ids.forEach(id => N.q("UPDATE spy_criativo SET midia_tentativas=0 WHERE id=? AND midia_status='erro'").run(N.resolver(id)));
      await Promise.race([N.enfileirar(ids.map(N.resolver)), new Promise(r => setTimeout(r, d.esperaMcpMs || 100000))]);
      return J({ criativos: ids.map(id => {
        const c = N.detalheCriativo(id);
        if (!c) return { criativo_id: id, erro: 'não encontrado' };
        return { criativo_id: id, juntado_em: c.juntado ? c.id : undefined, midia_status: c.midia_status, midia_erro: c.midia_erro || undefined, duracao_s: c.duracao_s,
          transcricao_status: c.transcricao_status, transcricao_erro: c.transcricao_erro || undefined,
          transcricao: c.transcricao ? { provedor: c.transcricao.provedor, idioma: c.transcricao.idioma, segmentos: c.transcricao.segmentos } : null };
      }), ainda_na_fila: N.fila() });
    }
    if (nome === 'spy_sugerir_biblioteca') {
      const r = N.criarBiblioteca({ tipo: a.tipo, referencia: a.referencia, pais: a.pais, nome: a.nome, nicho_id: a.nicho_id, ouro: false, origem: 'sugerida_pela_rotina',
        status: 'sugerida', motivo: a.motivo, ads_ativos: a.ads_ativos }, por);
      return J({ criada: !r.existente, ja_existia: r.existente, biblioteca: N.bibPub(r.biblioteca) });
    }
    if (nome === 'spy_salvar_criativo') return J(N.salvarDoClaude(a));
    if (nome === 'spy_registrar_funil') return J(N.registrarFunil(a, por));
    if (nome === 'spy_registrar_rodada') {
      const r = N.registrarRodada(a, por);
      let enviados = 0;
      if (d.avisar) for (const al of r.alertas) { try { d.avisar('Spy: ' + al.titulo, al.texto || ''); enviados++; } catch (e) {} }
      return J({ rodada_id: r.id, alertas_enviados: enviados });
    }
    return null;
  }

  return { ferramentasMcp, mcp, nucleo: N };
};
module.exports.criarNucleo = criarNucleo;
module.exports.lerAnuncioMcp = lerAnuncioMcp;
module.exports.mesmoVideo = mesmoVideo;
module.exports.analisarVideo = analisarVideo;
module.exports.midiaDisco = midiaDisco;
module.exports.transcritorAssembly = transcritorAssembly;
module.exports.semente = semente;
module.exports.FERRAMENTAS = FERRAMENTAS;
module.exports.FFMPEG = FFMPEG;
module.exports.criarBuscador = require('./spy-navegador');
