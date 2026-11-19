// Spy de anúncios (18/11/2026), pelo servidor de verdade. A coleta chega pelo MCP (o Claude lê a Biblioteca de Anúncios
// no Chrome); o servidor baixa o vídeo pelo link, guarda, transcreve e mostra. Confere: a base inicial, a equipe cadastrando
// biblioteca e corrigindo etiqueta (com o nome de quem corrigiu), ⚙ Configurações só da conta do Thiago (403 pros outros),
// as 13 ferramentas spy_* (a folha de quadros do spy_ver_criativo incluída), o alerta da rodada no sininho dele e o vídeo tocando em pedaços (Range).
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn, execFileSync } = require('child_process');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const FF = require('../spy.js').FFMPEG;

const RAIZ = path.join(__dirname, '..');
const espera = ms => new Promise(r => setTimeout(r, ms));
const ate = async (cond, ms, oQue, log) => { const fim = Date.now() + ms; for (;;) { try { if (await cond()) return; } catch (e) {} if (Date.now() > fim) throw new Error('demorou demais: ' + oQue + '\n' + (log ? log().slice(-1500) : '')); await espera(200); } };

let falso, srv, dir, base, baseFalso, log = '', dono, lucas, api;
function servicoFalso(req, res) {
  const u = new URL(req.url, baseFalso);
  const ok = o => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
  if (u.pathname.startsWith('/cdn/')) { res.writeHead(200); return res.end(fs.readFileSync(path.join(dir, 'cdn', path.basename(u.pathname)))); }
  if (u.pathname === '/v2/upload') { req.resume(); req.on('end', () => ok({ upload_url: baseFalso + '/up' })); return; }
  if (u.pathname === '/v2/transcript') { req.resume(); req.on('end', () => ok({ id: 'tt', status: 'queued' })); return; }
  if (u.pathname === '/v2/transcript/tt') return ok({ id: 'tt', status: 'completed', text: 'Oi. Tchau.', language_code: 'pt' });
  if (u.pathname === '/v2/transcript/tt/sentences') return ok({ sentences: [{ text: 'Oi.', start: 0, end: 900 }, { text: 'Tchau.', start: 900, end: 2000 }] });
  res.writeHead(404); res.end();
}
async function chamar(metodo, c, { token, corpo } = {}) {
  const headers = {}; if (token) headers.Authorization = 'Bearer ' + token; if (corpo !== undefined) headers['Content-Type'] = 'application/json';
  const r = await fetch(base + c, { method: metodo, headers, body: corpo !== undefined ? JSON.stringify(corpo) : undefined });
  let dados = null; const txt = await r.text(); try { dados = JSON.parse(txt); } catch (e) { dados = txt; }
  return { status: r.status, dados };
}
const mcp = async (method, params) => (await chamar('POST', '/mcp?token=' + api, { corpo: { jsonrpc: '2.0', id: 1, method, params } })).dados;
const ferramenta = async (name, args) => { const r = await mcp('tools/call', { name, arguments: args }); return r.result.isError ? { erro: r.result.content[0].text } : JSON.parse(r.result.content[0].text); };
const anuncio = (id, pagina, inicio) => ({ ad_archive_id: id, page_id: '111', page_name: pagina, copy: 'Essa IA analisa seu edital ' + id, cta: 'Saiba mais',
  link_destino: 'https://concursa-paginas.vercel.app/lote-00/', inicio_veiculacao: inicio, plataformas: ['facebook'], midia: { tipo: 'video', url_video: baseFalso + '/cdn/a.mp4?oe=FFFFFFFF' } });

before(async () => {
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-spysrv-'));
  fs.mkdirSync(path.join(dir, 'cdn'));
  execFileSync(FF, ['-hide_banner', '-loglevel', 'error', '-y', '-f', 'lavfi', '-i', 'mandelbrot=size=240x426:rate=25', '-f', 'lavfi', '-i', 'sine=frequency=300:duration=3', '-t', '3', '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-c:a', 'aac', path.join(dir, 'cdn', 'a.mp4')]);
  falso = await new Promise(r => { const s = http.createServer(servicoFalso).listen(0, '127.0.0.1', () => r(s)); });
  baseFalso = 'http://127.0.0.1:' + falso.address().port;
  const porta = 59000 + Math.floor(Math.random() * 900);
  base = 'http://127.0.0.1:' + porta;
  srv = spawn(process.execPath, [path.join(RAIZ, 'server.js')], { cwd: RAIZ, env: { PATH: process.env.PATH, HOME: process.env.HOME, PORT: String(porta), TMX_DATA_DIR: path.join(dir, 'tmx'),
    ASSEMBLYAI_API_KEY: 'aai-falsa', ASSEMBLYAI_BASE_TESTE: baseFalso, SPY_MIDIA_LIVRE_TESTE: '1', SPY_BUSCADOR: 'desligado' } });
  srv.stdout.on('data', b => { log += b; }); srv.stderr.on('data', b => { log += b; });
  await ate(async () => (await fetch(base + '/api/ping')).ok, 20000, 'servidor subir', () => log);
  await ate(() => /sessões derrubadas/.test(log), 40000, 'a rotina das sessões rodar', () => log);
  dono = (await chamar('POST', '/api/auth/login', { corpo: { email: 'thiago@axcend.com', senha: 'axcend2026' } })).dados.token;
  lucas = (await chamar('POST', '/api/auth/login', { corpo: { email: 'spy@axcend.com', senha: 'axcend2026' } })).dados.token;
  api = (await chamar('POST', '/api/tokens/generate', { token: dono, corpo: { nome: 'Rotina do Spy' } })).dados.token;
});
after(async () => {
  if (srv && srv.exitCode === null) { srv.kill('SIGTERM'); await Promise.race([new Promise(r => srv.once('exit', r)), espera(10000)]); }
  if (falso) falso.close();
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});

test('sem login não abre; mídia com nome inventado não existe', async () => {
  assert.strictEqual((await chamar('GET', '/api/spy/painel')).status, 401);
  assert.strictEqual((await chamar('GET', '/api/spy/midia/v/abc.mp4')).status, 404);
  assert.strictEqual((await chamar('GET', '/api/spy/midia/v/..%2F..%2Fdb.json')).status, 404);
});

let evandro;
test('a equipe vê as bibliotecas da base e cadastra; ⚙ Configurações só pra conta do Thiago', async () => {
  const p = (await chamar('GET', '/api/spy/painel', { token: lucas })).dados;
  assert.strictEqual(p.dono, false);
  assert.strictEqual(p.bibliotecas.length, 9, 'começa do zero: as 9 da especificação, sem as 110 do Spy Automático');
  assert.strictEqual(p.bibliotecas.find(b => b.nome === 'Gabriel Navarro').nicho_id, 'nic-investimentos');
  assert.strictEqual(p.config.midia, 'disco', 'sem a hospedagem e fora do Railway, os vídeos vão pra pasta local');
  evandro = p.bibliotecas.find(b => b.referencia === 'concursa-paginas.vercel.app');
  const nova = await chamar('POST', '/api/spy/bibliotecas', { token: lucas, corpo: { link: 'https://www.facebook.com/ads/library/?view_all_page_id=999888777666&country=BR', nome: 'Concorrente X', nicho_id: 'nic-concurso' } });
  assert.strictEqual(nova.status, 200);
  assert.deepStrictEqual([nova.dados.biblioteca.tipo, nova.dados.biblioteca.ouro], ['pagina', true]);
  assert.strictEqual((await chamar('POST', '/api/spy/bibliotecas', { token: lucas, corpo: { link: 'concursa-paginas.vercel.app' } })).dados.existente, true);
  for (const [m, c] of [['GET', '/api/spy/config'], ['POST', '/api/spy/nichos'], ['POST', '/api/spy/regras']]) {
    assert.strictEqual((await chamar(m, c, { token: lucas, corpo: m === 'POST' ? { nome: 'X' } : undefined })).status, 403, c);
  }
  assert.strictEqual((await chamar('GET', '/api/spy/painel', { token: dono })).dados.dono, true);
  assert.strictEqual((await chamar('POST', '/api/spy/regras', { token: dono, corpo: { horario_rotina: '07:40' } })).dados.regras.horario_rotina, '07:40');
  assert.strictEqual((await chamar('GET', '/api/spy/config', { token: dono })).status, 200);
});

let criativoId;
test('MCP: a coleta entra, o vídeo fica guardado, toca em pedaços e é transcrito', async () => {
  const nomes = (await mcp('tools/list')).result.tools.map(t => t.name).filter(n => n.startsWith('spy_'));
  assert.deepStrictEqual(nomes.sort(), ['spy_ler_regras', 'spy_listar_bibliotecas', 'spy_listar_criativos', 'spy_processar_midia', 'spy_registrar_coleta', 'spy_registrar_funil',
    'spy_registrar_rodada', 'spy_salvar_biblioteca', 'spy_salvar_criativo', 'spy_salvar_nicho', 'spy_salvar_regras', 'spy_sugerir_biblioteca', 'spy_ver_criativo']);
  const regras = await ferramenta('spy_ler_regras', {});
  assert.strictEqual(regras.regras.horario_rotina, '07:40');
  assert.ok(regras.bibliotecas_ouro.some(b => b.id === evandro.id && /q=concursa-paginas/.test(b.link)));
  const col = await ferramenta('spy_registrar_coleta', { biblioteca_id: evandro.id, total_ativos: 2, anuncios: [anuncio('5001', 'Concursa EG', '2026-10-09'), anuncio('5002', 'EG RAIZ 2', '2026-10-21')] });
  assert.deepStrictEqual([col.anuncios_ativos, col.anuncios_novos, col.completa, col.videos_na_fila], [2, 2, true, 1]);
  const lst = await ferramenta('spy_listar_bibliotecas', { ouro: true });
  assert.deepStrictEqual(lst.bibliotecas.find(b => b.id === evandro.id).anuncios_conhecidos.sort(), ['5001', '5002']);
  await ate(async () => (await chamar('GET', '/api/spy/bibliotecas/' + evandro.id, { token: lucas })).dados.processamento.transcritos === 1, 30000, 'o vídeo ser guardado e transcrito', () => log);
  const d = (await chamar('GET', '/api/spy/bibliotecas/' + evandro.id, { token: lucas })).dados;
  assert.strictEqual(d.criativos.length, 1, 'o mesmo vídeo em dois anúncios é um criativo só');
  criativoId = d.criativos[0].id;
  const c = (await chamar('GET', '/api/spy/criativos/' + criativoId, { token: lucas })).dados.criativo;
  assert.deepStrictEqual(c.transcricao.segmentos, [{ inicio_s: 0, fim_s: 0.9, texto: 'Oi.' }, { inicio_s: 0.9, fim_s: 2, texto: 'Tchau.' }]);
  const tam = fs.statSync(path.join(dir, 'cdn', 'a.mp4')).size;
  const inteiro = await fetch(base + '/api/spy/midia/' + c.arquivo);
  assert.deepStrictEqual([inteiro.status, inteiro.headers.get('content-type'), Number(inteiro.headers.get('content-length'))], [200, 'video/mp4', tam]);
  const pedaco = await fetch(base + '/api/spy/midia/' + c.arquivo, { headers: { Range: 'bytes=100-199' } });
  assert.deepStrictEqual([pedaco.status, pedaco.headers.get('content-range')], [206, 'bytes 100-199/' + tam]);
  assert.deepStrictEqual(Buffer.from(await pedaco.arrayBuffer()), fs.readFileSync(path.join(dir, 'cdn', 'a.mp4')).subarray(100, 200));
  assert.strictEqual((await fetch(base + '/api/spy/midia/' + c.arquivo, { headers: { Range: 'bytes=' + (tam + 5) + '-' } })).status, 416);
  const pm = await ferramenta('spy_processar_midia', { criativo_ids: [criativoId] });
  assert.strictEqual(pm.criativos[0].transcricao.segmentos.length, 2);
});

// largura × altura de um JPEG (marcador SOF)
function tamanhoJpeg(b) {
  for (let i = 2; i < b.length - 9;) {
    if (b[i] !== 0xFF) { i++; continue; }
    const m = b[i + 1], len = b.readUInt16BE(i + 2);
    if (m >= 0xC0 && m <= 0xC3) return [b.readUInt16BE(i + 7), b.readUInt16BE(i + 5)];
    i += 2 + len;
  }
  return null;
}
test('MCP mostra os 8 quadros do vídeo numa imagem, pro Claude classificar o formato (19/11)', async () => {
  const fila = await ferramenta('spy_listar_criativos', { biblioteca_id: evandro.id, sem_formato: true });
  assert.deepStrictEqual(fila.criativos.map(c => c.id), [criativoId], 'tem o vídeo e ainda não tem formato');
  const r = (await mcp('tools/call', { name: 'spy_ver_criativo', arguments: { criativo_id: criativoId } })).result;
  assert.ok(!r.isError, JSON.stringify(r).slice(0, 300));
  assert.deepStrictEqual(r.content.map(c => c.type), ['image', 'text']);
  assert.strictEqual(r.content[0].mimeType, 'image/jpeg');
  const img = Buffer.from(r.content[0].data, 'base64');
  assert.deepStrictEqual([img[0], img[1]], [0xFF, 0xD8]);
  assert.deepStrictEqual(tamanhoJpeg(img), [896, 800], 'vídeo vertical: 4×2 quadros de 224×400');
  const info = JSON.parse(r.content[1].text);
  assert.strictEqual(info.tela, 'vertical');
  assert.match(info.quadros, /8 quadros.*0\.1, 0\.4, 0\.8, 1\.1, 1\.5, 1\.9, 2\.3, 2\.7/);
  assert.strictEqual(info.falas.length, 2);
  assert.deepStrictEqual(info.formatos_aceitos.slice(0, 2), ['Rosto / teleprompter', 'Caixinha de pergunta']);
  // feita uma vez: a segunda vem da folha guardada, igual
  const guardadas = fs.readdirSync(path.join(dir, 'tmx', 'spy_midia')).filter(f => /^q_.*-8\.jpg$/.test(f));
  assert.strictEqual(guardadas.length, 1);
  const r2 = (await mcp('tools/call', { name: 'spy_ver_criativo', arguments: { criativo_id: criativoId } })).result;
  assert.strictEqual(r2.content[0].data, r.content[0].data);
  const nada = (await mcp('tools/call', { name: 'spy_ver_criativo', arguments: { criativo_id: 'cr_naoexiste' } })).result;
  assert.ok(nada.isError);
});

test('MCP grava etiqueta; a correção de alguém da equipe fica protegida e com o nome', async () => {
  const s1 = await ferramenta('spy_salvar_criativo', { criativo_id: criativoId, etiquetas: [{ campo: 'angulo', valor: 'Notícia' }, { campo: 'formato', valor: 'Rosto / teleprompter' }], familia: 'B · Live privada' });
  assert.deepStrictEqual(s1.erros, []);
  const tela = await chamar('POST', '/api/spy/criativos/' + criativoId + '/etiquetas', { token: lucas, corpo: { campos: { angulo: 'Prova' } } });
  assert.strictEqual(tela.status, 200);
  assert.deepStrictEqual([tela.dados.criativo.etiquetas.angulo[0].origem, tela.dados.criativo.etiquetas.angulo[0].por], ['thiago', 'Lucas']);
  assert.strictEqual(tela.dados.criativo.etiquetas.formato[0].origem, 'claude');
  assert.strictEqual((await chamar('POST', '/api/spy/criativos/' + criativoId + '/etiquetas', { token: lucas, corpo: { campos: { angulo: 'Medo' } } })).status, 400);
  assert.deepStrictEqual((await ferramenta('spy_salvar_criativo', { criativo_id: criativoId, etiquetas: [{ campo: 'angulo', valor: 'Fofoca' }] })).protegidas, ['angulo']);
  const lc = await ferramenta('spy_listar_criativos', { biblioteca_id: evandro.id, transcricao: true });
  assert.deepStrictEqual(lc.criativos[0].etiquetas.angulo, [{ valor: 'Prova', parte: 'todo', origem: 'corrigido por Lucas' }]);
  assert.strictEqual(lc.criativos[0].falas.length, 2);
});

test('MCP configura (biblioteca, nicho, sugestão), registra funil e rodada; o alerta chega só no sininho do Thiago', async () => {
  const nicho = await ferramenta('spy_salvar_nicho', { nome: 'Odontologia', pais: 'BR', palavras: ['clareamento dental'] });
  assert.deepStrictEqual(nicho.nicho.palavras, ['clareamento dental']);
  const bib = await ferramenta('spy_salvar_biblioteca', { tipo: 'dominio', referencia: 'sorriso.com.br', nome: 'Sorriso', nicho_id: nicho.nicho.id, ouro: true });
  assert.strictEqual(bib.criada, true);
  assert.strictEqual((await ferramenta('spy_salvar_biblioteca', { id: bib.biblioteca.id, ouro: false })).biblioteca.ouro, false);
  const sug = await ferramenta('spy_sugerir_biblioteca', { tipo: 'dominio', referencia: 'pmminas.com', nome: 'PMMinas', nicho_id: 'nic-concurso', motivo: '40 anúncios em edital' });
  assert.deepStrictEqual([sug.criada, sug.biblioteca.status], [true, 'sugerida']);
  assert.strictEqual((await ferramenta('spy_sugerir_biblioteca', { tipo: 'dominio', referencia: 'pmminas.com', nome: 'De novo' })).ja_existia, true);
  const f = await ferramenta('spy_registrar_funil', { dominio: 'concursa-paginas.vercel.app', url: 'https://concursa-paginas.vercel.app/lote-00/', biblioteca_id: evandro.id, campos: { preco: 'R$ 37 à vista' } });
  assert.strictEqual(f.primeira_versao, true);
  assert.strictEqual((await chamar('GET', '/api/spy/funis', { token: lucas })).dados.funis[0].versoes[0].campos.preco, 'R$ 37 à vista');
  const ro = await ferramenta('spy_registrar_rodada', { numeros: { bibliotecas_verificadas: 1 }, resumo_texto: 'Dia calmo.', alertas: [{ titulo: 'Evandro escalando', texto: 'De 1 pra 4' }] });
  assert.strictEqual(ro.alertas_enviados, 1);
  const st = (await chamar('GET', '/api/store', { token: dono })).dados;
  const notifs = ((st.store || st).sl_notifs || []).filter(n => /Evandro escalando/.test(n.titulo));
  assert.deepStrictEqual(notifs.map(n => n.destId), ['u1']);
  assert.strictEqual((await chamar('GET', '/api/spy/config', { token: dono })).dados.rodadas[0].resumo, 'Dia calmo.');
  const busca = (await chamar('GET', '/api/spy/busca?q=tchau', { token: lucas })).dados;
  assert.strictEqual(busca.resultados[0].inicio_s, 0.9);
  assert.strictEqual((await chamar('GET', '/api/spy/mercado?dim=angulo', { token: lucas })).dados.linhas.find(l => l.valor === 'Prova').criativos, 1);
});

test('coleta sem link: os anúncios entram, a aba Anúncios lista todos, e sem o navegador a tela avisa', async () => {
  const bib = (await ferramenta('spy_salvar_biblioteca', { tipo: 'dominio', referencia: 'semlink.com.br', nome: 'Sem link' })).biblioteca;
  const col = await ferramenta('spy_registrar_coleta', { biblioteca_id: bib.id, completa: true, anuncios: [{ ad_archive_id: '6001', page_name: 'P', copy: 'c', inicio_veiculacao: '2026-11-01' }, { ad_archive_id: '6002', page_name: 'P', copy: 'c' }] });
  assert.deepStrictEqual([col.anuncios_ativos, col.criativos_ativos, col.videos_a_buscar], [2, 2, 0]);
  const d = (await chamar('GET', '/api/spy/bibliotecas/' + bib.id, { token: lucas })).dados;
  assert.deepStrictEqual(d.anuncios.map(a => [a.id, a.ativo]).sort(), [['6001', true], ['6002', true]]);
  // 6001 está no ar desde 01/11 (cumpre a regra dos 7 dias); 6002 veio sem data e com 1 cópia: fica sem o vídeo, abaixo da regra
  assert.deepStrictEqual([d.processamento.aguardando_link, d.processamento.abaixo_da_regra], [1, 1]);
  assert.strictEqual(col.videos_abaixo_da_regra, 1);
  assert.strictEqual(d.busca.disponivel, false);
  const p = (await chamar('POST', '/api/spy/bibliotecas/' + bib.id + '/processar', { token: lucas })).dados;
  assert.match(p.motivo, /navegador/);
});
