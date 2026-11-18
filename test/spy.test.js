// Spy de anúncios (18/11/2026): o núcleo sem o servidor. A coleta chega como o Claude manda pelo MCP (lida no Chrome);
// CDN do Facebook e AssemblyAI de mentira, vídeos de verdade gerados pelo ffmpeg. Cobre o critério de pronto: anúncios com
// página, copy, datas e destino; vídeos iguais (mesmo arquivo ou subido de novo noutra página) viram um criativo só, com o
// nº de anúncios e os dias no ar certos; o vídeo fica guardado; a transcrição tem tempo; etiqueta do Claude x correção de
// alguém da equipe; a coleta do dia seguinte tira a foto e marca novo, escalando e parou. E mais: funil com diferença,
// rodada, busca na fala, mercado e a base inicial.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const Spy = require('../spy.js');
const SpyLink = require('../public/spy-link.js');

const FF = Spy.FFMPEG;
const DIA = 86400000;
const D1 = Date.parse('2026-11-18T15:00:00Z');   // 12h em Brasília
let dir, vids, srv, base, relogio = D1, N, cotaAcabou = false, transcricoes = 0;

function gerar(nome, args) { execFileSync(FF, ['-hide_banner', '-loglevel', 'error', '-y'].concat(args, [path.join(vids, nome)])); }
const PA = ['111', 'Concursa EG'], PB = ['222', 'EG Raiz - I.A'];
function ad(id, p, video, inicio, extra) {
  extra = extra || {};
  return Object.assign({ ad_archive_id: id, page_id: p[0], page_name: p[1], copy: 'Copy do anúncio ' + id + ': essa IA lê o seu edital.', titulo: 'Live hoje', cta: 'Saiba mais',
    link_destino: 'https://concursa-paginas.vercel.app/lote-00/?utm=' + id, inicio_veiculacao: inicio, plataformas: ['facebook', 'instagram'],
    midia: video ? { tipo: 'video', url_video: base + '/cdn/' + video + '?oe=FFFFFFFF', url_capa: base + '/cdn/capa.jpg' } : { tipo: 'imagem', url_imagem: base + '/cdn/' + extra.img } }, extra.mais || {});
}
function falso(req, res) {
  const u = new URL(req.url, base);
  const ok = (o, st) => { res.writeHead(st || 200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
  if (u.pathname.startsWith('/cdn/')) {
    const f = path.join(vids, path.basename(u.pathname));
    if (!fs.existsSync(f)) { res.writeHead(404); return res.end(); }
    res.writeHead(200); return res.end(fs.readFileSync(f));
  }
  if (u.pathname === '/v2/upload') { if (cotaAcabou) { req.resume(); return ok({ error: 'Your account balance is negative' }, 402); } req.resume(); req.on('end', () => ok({ upload_url: base + '/up' })); return; }
  if (u.pathname === '/v2/transcript' && req.method === 'POST') { let c = ''; req.on('data', b => { c += b; }); req.on('end', () => { assert.strictEqual(JSON.parse(c).language_code, 'pt'); transcricoes++; ok({ id: 'tt', status: 'queued' }); }); return; }
  if (u.pathname === '/v2/transcript/tt/sentences') return ok({ sentences: [{ text: 'Olha só isso.', start: 0, end: 1500 }, { text: 'Essa IA lê o edital.', start: 1500, end: 4200 }, { text: 'Clica no botão.', start: 4200, end: 5900 }] });
  if (u.pathname === '/v2/transcript/tt') return ok({ id: 'tt', status: 'completed', text: 'Olha só isso. Essa IA lê o edital. Clica no botão.', language_code: 'pt' });
  res.writeHead(404); res.end();
}

before(async () => {
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-spy-'));
  vids = path.join(dir, 'cdn'); fs.mkdirSync(vids);
  gerar('v1.mp4', ['-f', 'lavfi', '-i', 'mandelbrot=size=360x640:rate=25', '-f', 'lavfi', '-i', 'sine=frequency=330:duration=6', '-af', "volume='if(lt(mod(t,1),0.5),1,0.1)':eval=frame", '-t', '6', '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-c:a', 'aac']);
  // o mesmo vídeo subido de novo noutra página: a Meta recodifica, então o arquivo é outro
  gerar('v1b.mp4', ['-i', path.join(vids, 'v1.mp4'), '-vf', 'scale=270:480', '-c:v', 'libx264', '-crf', '32', '-pix_fmt', 'yuv420p', '-c:a', 'aac', '-b:a', '48k']);
  gerar('v2.mp4', ['-f', 'lavfi', '-i', 'life=size=360x640:rate=25:mold=10:ratio=0.4:seed=7', '-f', 'lavfi', '-i', 'sine=frequency=550:duration=5', '-af', "volume='if(lt(mod(t,0.7),0.3),1,0.1)':eval=frame", '-t', '5', '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-c:a', 'aac']);
  gerar('v3.mp4', ['-f', 'lavfi', '-i', 'testsrc2=size=360x640:rate=25', '-f', 'lavfi', '-i', 'sine=frequency=200:duration=7', '-t', '7', '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-c:a', 'aac']);
  gerar('capa.jpg', ['-f', 'lavfi', '-i', 'color=c=blue:size=180x320', '-frames:v', '1']);
  gerar('img1.jpg', ['-f', 'lavfi', '-i', 'smptebars=size=400x400', '-frames:v', '1']);
  gerar('img2.jpg', ['-f', 'lavfi', '-i', 'rgbtestsrc=size=400x400', '-frames:v', '1']);
  srv = await new Promise(r => { const s = http.createServer(falso).listen(0, '127.0.0.1', () => r(s)); });
  base = 'http://127.0.0.1:' + srv.address().port;
  N = Spy.criarNucleo({ dir, agora: () => relogio, midia: Spy.midiaDisco(path.join(dir, 'spy_midia')), tmpDir: path.join(dir, 'tmp'), baixarQualquer: true,
    transcritor: () => Spy.transcritorAssembly('chave-aai', base) });
});
after(() => { if (srv) srv.close(); try { N.db.close(); } catch (e) {} if (dir) fs.rmSync(dir, { recursive: true, force: true }); });

let BIB;
const esperarFila = async () => { for (let i = 0; i < 400 && (N.fila().fila || N.fila().rodando); i++) await new Promise(r => setTimeout(r, 50)); };
const processarTudo = async () => { await N.enfileirar(N.pendentesDaBiblioteca(BIB)); await esperarFila(); };

test('o link colado vira página, domínio ou palavra', () => {
  const ev = SpyLink.ler('https://www.facebook.com/ads/library/?active_status=active&ad_type=all&country=BR&q=concursa-paginas.vercel.app&search_type=keyword_unordered');
  assert.deepStrictEqual(ev, { tipo: 'dominio', referencia: 'concursa-paginas.vercel.app', pais: 'BR', searchType: 'keyword_unordered' });
  assert.strictEqual(SpyLink.ler('https://www.facebook.com/ads/library/?view_all_page_id=1140174149181447&country=BR').tipo, 'pagina');
  assert.deepStrictEqual(SpyLink.ler('https://www.facebook.com/ads/library/?q=concurso%20p%C3%BAblico&country=BR'), { tipo: 'palavra', referencia: 'concurso público', pais: 'BR', searchType: '' });
  assert.strictEqual(SpyLink.ler('https://www.facebook.com/ads/library/?q=%22METODOGAFANHOTO.COM%22&country=ALL').referencia, 'metodogafanhoto.com');
  assert.strictEqual(SpyLink.ler('www.truquedobumbum.com.br').tipo, 'dominio');
  assert.strictEqual(SpyLink.ler('qualquer coisa'), null);
});

test('base inicial: nichos e as 9 bibliotecas da especificação, Navarro em Investimentos, uma vez só', () => {
  assert.strictEqual(Spy.semente(N), 9);
  assert.strictEqual(Spy.semente(N), 0, 'não repete');
  const nav = N.listarBibliotecas().find(b => b.referencia === '1140174149181447');
  assert.strictEqual(nav.nicho_id, 'nic-investimentos');
  assert.strictEqual(nav.ouro, true);
  assert.strictEqual(N.listarBibliotecas().find(b => b.nome === 'ABRAhub').nicho_id, '', 'ABRAhub fica A definir');
  const inv = N.nichos().find(n => n.id === 'nic-investimentos');
  assert.deepStrictEqual([inv.pais, inv.ativo, inv.palavras.length], ['BR', true, 0]);
  BIB = N.listarBibliotecas().find(b => b.referencia === 'concursa-paginas.vercel.app').id;
  const r = N.criarBiblioteca({ link: 'https://www.facebook.com/ads/library/?q=concursa-paginas.vercel.app&country=BR' }, 'X');
  assert.strictEqual(r.existente, true, 'o mesmo link não cria outra');
});

test('dia 1: a coleta grava página, copy, datas e destino, e junta o mesmo vídeo num criativo só', async () => {
  const r = N.registrarColeta(BIB, { total_ativos: 7, anuncios: [ad('1001', PA, 'v1.mp4', '2026-10-09', { mais: { quantidade: 2 } }), ad('1002', PA, 'v1.mp4', '2026-10-17'),
    ad('1003', PB, 'v1b.mp4', '2026-10-21'), ad('1004', PB, 'v2.mp4', '2026-11-16'), ad('1005', PA, null, '2026-11-01', { img: 'img1.jpg' }), ad('1006', PA, 'v3.mp4', '2026-10-28')] }, 'teste');
  assert.strictEqual(r.completa, true, 'a soma das quantidades bateu o total');
  assert.strictEqual(r.anuncios_ativos, 7);
  assert.strictEqual(r.anuncios_novos, 6);
  const a = N.q('SELECT * FROM spy_anuncio WHERE ad_archive_id=?').get('1001');
  assert.deepStrictEqual([a.page_name, a.dominio, a.quantidade, a.inicio_veiculacao, a.fim_veiculacao], ['Concursa EG', 'concursa-paginas.vercel.app', 2, Date.parse('2026-10-09T12:00:00Z') / 1000, null]);
  assert.match(a.copy, /essa IA lê o seu edital/);
  assert.ok(JSON.parse(a.bruto_json).midia, 'o que o Claude mandou fica guardado');
  assert.strictEqual(N.detalheBiblioteca(BIB).criativos.length, 5, 'antes de baixar, o mesmo arquivo já é um criativo só');
  await processarTudo();
  const det = N.detalheBiblioteca(BIB);
  assert.strictEqual(det.criativos.length, 4, 'o v1b (mesmo vídeo recodificado) foi juntado ao v1');
  const v1 = det.criativos.find(c => c.inicio === '2026-10-09');
  assert.strictEqual(v1.anuncios_ativos, 4, '2 + 1 + 1 anúncios');
  assert.strictEqual(v1.dias_no_ar, 40);
  assert.strictEqual(v1.status, 'estavel');
  assert.deepStrictEqual(v1.paginas.sort(), ['Concursa EG', 'EG Raiz - I.A']);
  assert.deepStrictEqual([det.kpis.ads_ativos, det.kpis.criativos, det.kpis.mais_antigo_dias], [7, 4, 40]);
  assert.strictEqual(det.criativos.find(c => c.inicio === '2026-11-16').status, 'novo');
  const c = N.detalheCriativo(v1.id);
  assert.strictEqual(c.midia_status, 'ok', c.midia_erro);
  assert.match(c.arquivo, /^v\/[a-f0-9]{64}\.mp4$/);
  assert.match(c.thumb, /^i\/[a-f0-9]{64}\.jpg$/);
  assert.ok(fs.existsSync(path.join(dir, 'spy_midia', c.arquivo.replace('/', '_'))));
  assert.deepStrictEqual(c.transcricao.segmentos[1], { inicio_s: 1.5, fim_s: 4.2, texto: 'Essa IA lê o edital.' });
  assert.strictEqual(transcricoes, 3, 'uma transcrição por vídeo único (v1, v2, v3): o repetido não gasta a cota');
  assert.strictEqual(N.q('SELECT COUNT(*) n FROM spy_criativo').get().n, 5, 'o criativo juntado não é apagado');
  assert.strictEqual(N.detalheCriativo(det.criativos.find(x => x.tipo === 'imagem').id).transcricao, null);
  assert.deepStrictEqual(det.serie, [{ dia: '2026-11-18', ads: 7, criativos: 4 }]);
});

test('etiquetas: o Claude sugere, a correção de alguém da equipe fica protegida e com o nome', () => {
  const v1 = N.detalheBiblioteca(BIB).criativos.find(c => c.inicio === '2026-10-09');
  const r = N.salvarDoClaude({ criativo_id: v1.id, etiquetas: [{ campo: 'angulo', valor: 'Segmentação direta', confianca: 0.8 }, { campo: 'dor', valor: 'concurseiro sem método' },
    { campo: 'formato', valor: 'Rosto / teleprompter' }], partes: [{ parte: 'gancho', inicio_s: 0, fim_s: 1.5 }, { parte: 'corpo', inicio_s: 1.5, fim_s: 4.2 }, { parte: 'cta', inicio_s: 4.2, fim_s: 6 }],
    familia: 'A · IA para concurseiros', nao_modelar: true, motivo: 'promessa com número sem prova' });
  assert.deepStrictEqual(r.erros, []);
  assert.match(N.salvarDoClaude({ criativo_id: v1.id, etiquetas: [{ campo: 'angulo', valor: 'Medo' }] }).erros[0], /valores fechados/);
  N.salvarDaTela(v1.id, { campos: { angulo: 'Prova' }, nao_modelar: false }, 'Lucas');
  let c = N.detalheCriativo(v1.id);
  assert.deepStrictEqual([c.etiquetas.angulo[0].valor, c.etiquetas.angulo[0].origem, c.etiquetas.angulo[0].por], ['Prova', 'thiago', 'Lucas']);
  assert.strictEqual(c.etiquetas.dor[0].origem, 'claude', 'o que ninguém mexeu continua sugerido pelo Claude');
  assert.deepStrictEqual([c.nao_modelar, c.nao_modelar_por], [false, 'Lucas']);
  const r2 = N.salvarDoClaude({ criativo_id: v1.id, etiquetas: [{ campo: 'angulo', valor: 'Fofoca' }, { campo: 'dor', valor: 'medo de reprovar' }], nao_modelar: true });
  assert.deepStrictEqual(r2.protegidas.sort(), ['angulo', 'nao_modelar']);
  c = N.detalheCriativo(v1.id);
  assert.deepStrictEqual([c.etiquetas.angulo[0].valor, c.etiquetas.dor[0].valor, c.nao_modelar], ['Prova', 'medo de reprovar', false]);
  assert.strictEqual(c.familia.nome, 'A · IA para concurseiros');
});

test('dia 2: a nova coleta tira a foto e marca novo, escalando e parou; nada é apagado', async () => {
  relogio = D1 + DIA;
  // só os novos vêm inteiros; os já conhecidos vão só pelo id
  const r = N.registrarColeta(BIB, { completa: true, ativos_ids: ['1001', '1002', '1003', '1004'], anuncios: [ad('1007', PA, 'v2.mp4', '2026-11-18'), ad('1008', PA, null, '2026-11-19', { img: 'img2.jpg' })] }, 'teste');
  assert.deepStrictEqual([r.foto_anterior, r.anuncios_novos, r.anuncios_parados], ['2026-11-18', 2, 2]);
  assert.strictEqual(r.escalando.length, 1);
  await processarTudo();
  const det = N.detalheBiblioteca(BIB);
  const por = i => det.criativos.find(c => c.inicio === i);
  assert.deepStrictEqual([por('2026-11-16').status, por('2026-11-16').anuncios_ativos, por('2026-11-16').anuncios_antes], ['escalando', 2, 1]);
  assert.strictEqual(por('2026-11-19').status, 'novo');
  assert.deepStrictEqual([por('2026-10-28').status, por('2026-11-01').status, por('2026-10-09').status], ['parou', 'parou', 'estavel']);
  const parado = N.q('SELECT * FROM spy_anuncio WHERE ad_archive_id=?').get('1006');
  assert.deepStrictEqual([parado.ativo, parado.fim_veiculacao], [0, Math.floor((D1 + DIA) / 1000)]);
  assert.strictEqual(N.q('SELECT COUNT(*) n FROM spy_anuncio').get().n, 8, 'anúncio que saiu continua no acervo');
  assert.deepStrictEqual(det.serie.map(s => [s.dia, s.ads]), [['2026-11-18', 7], ['2026-11-19', 7]]);
  // de novo no mesmo dia: refaz a foto de hoje e compara com a de ontem
  assert.strictEqual(N.registrarColeta(BIB, { completa: true, ativos_ids: ['1001', '1002', '1003', '1004', '1007', '1008'] }, 'teste').foto_anterior, '2026-11-18');
  assert.strictEqual(N.q('SELECT COUNT(*) n FROM spy_snapshot WHERE biblioteca_id=?').get(BIB).n, 2);
  assert.throws(() => N.registrarColeta(BIB, { dia: '2026-11-10', ativos_ids: ['1001'] }), /dia anterior/);
});

test('lista que não veio inteira não marca ninguém como fora do ar; id desconhecido volta pedindo o anúncio', () => {
  relogio = D1 + 2 * DIA;
  const r = N.registrarColeta(BIB, { total_ativos: 50, ativos_ids: ['1001', '9999'] }, 'teste');
  assert.strictEqual(r.completa, false);
  assert.match(r.aviso, /ninguém foi marcado/);
  assert.deepStrictEqual([r.anuncios_parados, r.sem_dados], [0, ['9999']]);
  assert.strictEqual(N.q('SELECT ativo FROM spy_anuncio WHERE ad_archive_id=?').get('1004').ativo, 1);
  assert.match(N.bibRow(BIB).erro, /não leu a lista inteira/);
});

test('sem a chave ou sem cota da AssemblyAI o vídeo fica aguardando, e a coleta não trava', async () => {
  cotaAcabou = true;
  const N2 = Spy.criarNucleo({ dir: fs.mkdtempSync(path.join(dir, 'n2-')), agora: () => relogio, midia: Spy.midiaDisco(path.join(dir, 'm2')), tmpDir: path.join(dir, 'tmp2'), baixarQualquer: true,
    transcritor: () => Spy.transcritorAssembly('chave', base) });
  const b = N2.criarBiblioteca({ tipo: 'dominio', referencia: 'x.com.br' }).biblioteca;
  N2.registrarColeta(b.id, { anuncios: [ad('3001', PA, 'v3.mp4', '2026-11-01')] });
  await N2.enfileirar(N2.pendentesDaBiblioteca(b.id));
  const c = N2.detalheBiblioteca(b.id).criativos[0];
  assert.deepStrictEqual([c.midia_status, c.transcricao_status], ['ok', 'aguardando']);
  cotaAcabou = false;
  await N2.enfileirar(N2.pendentesDaBiblioteca(b.id));
  assert.strictEqual(N2.detalheCriativo(c.id).transcricao_status, 'ok', 'com a cota de volta, transcreve na próxima vez');
  // sem armazenamento (R2 desligado em produção): o anúncio entra, o vídeo espera
  const N3 = Spy.criarNucleo({ dir: fs.mkdtempSync(path.join(dir, 'n3-')), agora: () => relogio, midia: null, tmpDir: path.join(dir, 'tmp3') });
  const b3 = N3.criarBiblioteca({ tipo: 'dominio', referencia: 'y.com.br' }).biblioteca;
  N3.registrarColeta(b3.id, { anuncios: [ad('4001', PA, 'v3.mp4', '2026-11-01')] });
  await N3.enfileirar(N3.pendentesDaBiblioteca(b3.id));
  assert.strictEqual(N3.detalheBiblioteca(b3.id).criativos[0].midia_status, 'aguardando');
  // link de fora do Facebook ou vencido não é baixado
  N3.q("UPDATE spy_anuncio SET midia_url='https://exemplo.com/a.mp4'").run();
  const N4 = Spy.criarNucleo({ dir: fs.mkdtempSync(path.join(dir, 'n4-')), agora: () => relogio, midia: Spy.midiaDisco(path.join(dir, 'm4')), tmpDir: path.join(dir, 'tmp4') });
  const b4 = N4.criarBiblioteca({ tipo: 'dominio', referencia: 'z.com.br' }).biblioteca;
  N4.registrarColeta(b4.id, { anuncios: [ad('5001', PA, 'v3.mp4', '2026-11-01')] });
  const cid = N4.detalheBiblioteca(b4.id).criativos[0].id;
  await N4.enfileirar([cid]);
  assert.match(N4.detalheCriativo(cid).midia_erro, /fora do Facebook/);
  N4.q("UPDATE spy_anuncio SET midia_url='https://video.xx.fbcdn.net/v/t42/a.mp4?oe=00000001'").run();
  N4.q("UPDATE spy_criativo SET midia_status='pendente'").run();
  await N4.enfileirar([cid]);
  assert.match(N4.detalheCriativo(cid).midia_erro, /venceu/);
  [N2, N3, N4].forEach(x => x.db.close());
});

test('funil: guarda a foto do dia e devolve o que mudou', () => {
  relogio = D1;
  const f1 = N.registrarFunil({ dominio: 'concursa-paginas.vercel.app', url: 'https://concursa-paginas.vercel.app/lote-00/', biblioteca_id: BIB,
    campos: { preco: 'R$ 37 à vista', lote: 'Lote 00', checkout: 'Hubla' }, texto: 'página', leitura: 'Primeira foto.' }, 'Claude');
  assert.deepStrictEqual([f1.primeira_versao, f1.mudou], [true, false]);
  relogio = D1 + DIA;
  const f2 = N.registrarFunil({ dominio: 'concursa-paginas.vercel.app', url: 'https://concursa-paginas.vercel.app/lote-01/', campos: { preco: 'R$ 47 à vista', lote: 'Lote 01', checkout: 'Hubla' },
    leitura: 'O lote virou e o preço subiu R$ 10.' }, 'Claude');
  assert.deepStrictEqual(f2.diff.map(d => d.campo).sort(), ['lote', 'preco', 'url']);
  assert.strictEqual(N.registrarFunil({ dominio: 'concursa-paginas.vercel.app', campos: { preco: 'R$ 47 à vista', lote: 'Lote 01', checkout: 'Hubla' } }).versao_anterior, '2026-11-18', 'mesmo dia refaz a versão do dia');
  const fs1 = N.funis();
  assert.strictEqual(fs1.length, 1);
  assert.deepStrictEqual(fs1[0].versoes.map(v => v.dia), ['2026-11-18', '2026-11-19']);
  assert.strictEqual(fs1[0].biblioteca.id, BIB);
  assert.strictEqual(N.detalheBiblioteca(BIB).funil_id, fs1[0].id);
});

test('rodada, busca na fala, mercado, nichos e regras', () => {
  const r = N.registrarRodada({ numeros: { bibliotecas_verificadas: 1, anuncios_novos: 2 }, resumo_texto: 'Resumo.', alertas: [{ titulo: 'Escalando', texto: 'C passou de 1 pra 4' }], erros: ['x falhou'] }, 'Claude');
  assert.strictEqual(r.alertas.length, 1);
  assert.deepStrictEqual(N.rodadas()[0].numeros, { bibliotecas_verificadas: 1, anuncios_novos: 2 });
  const b = N.buscar({ texto: 'edital', parte: 'corpo' });
  assert.ok(b.resultados.length >= 1);
  assert.ok(b.resultados.every(x => x.parte === 'corpo' && x.onde === 'fala'));
  assert.strictEqual(b.resultados[0].inicio_s, 1.5);
  assert.ok(N.buscar({ texto: 'Copy do anúncio', incluir_parados: true }).resultados.some(x => x.onde === 'copy'));
  const m = N.mercado({ dim: 'angulo' });
  assert.strictEqual(m.linhas.find(l => l.valor === 'Prova').criativos, 1);
  assert.strictEqual(m.linhas.length, SpyLink.ANGULOS.length);
  const n = N.salvarNicho({ id: 'nic-investimentos', palavras: ['renda fixa', 'renda fixa', ' tesouro direto '], min_anuncios: 15 });
  assert.deepStrictEqual([n.palavras, n.min_anuncios], [['renda fixa', 'tesouro direto'], 15]);
  assert.strictEqual(N.salvarNicho({ nome: 'Odonto', pais: 'br' }).pais, 'BR');
  assert.throws(() => N.salvarNicho({}), /nome/);
  assert.deepStrictEqual(N.salvarRegras({ multiplicador_escala: 4, horario_rotina: '07:40' }), { avisar_criativo_novo_em_ouro: true, biblioteca_nova_min_anuncios: 30, multiplicador_escala: 4, horario_rotina: '07:40' });
  assert.strictEqual(N.salvarRegras({ horario_rotina: '25:99' }).horario_rotina, '07:40', 'horário inválido não entra');
});
