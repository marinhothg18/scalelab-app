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
  // estes testes cobrem juntar, guardar e transcrever: a regra dos vídeos (dias/cópias/teto) tem teste próprio, aqui baixa todos
  N.salvarRegras({ video_min_dias: 0 });
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
  assert.deepStrictEqual(N.salvarRegras({ multiplicador_escala: 4, horario_rotina: '07:40' }), { avisar_criativo_novo_em_ouro: true, biblioteca_nova_min_anuncios: 30, multiplicador_escala: 4, horario_rotina: '07:40',
    video_min_dias: 0, video_min_copias: 5, video_teto: 10 });
  assert.strictEqual(N.salvarRegras({ horario_rotina: '25:99' }).horario_rotina, '07:40', 'horário inválido não entra');
});

test('sem o link na coleta: cada anúncio vira um criativo, o servidor busca o vídeo pelo id, baixa e junta os iguais', async () => {
  relogio = D1 + 3 * DIA;
  const vid = n => base + '/cdn/' + n + '?oe=FFFFFFFF';
  const achados = { '7001': { video: vid('v2.mp4'), capa: base + '/cdn/capa.jpg' }, '7002': { video: vid('v2.mp4') }, '7003': { video: vid('v3.mp4') }, '7004': { erro: 'o anúncio não apareceu na página' } };
  const pedidos = [];
  const buscador = { disponivel: () => true, async buscar(ids, cb) { pedidos.push(ids.slice()); for (const id of ids) await cb(id, achados[id] || { erro: 'x' }); return { tentados: ids.length }; } };
  const Nb = Spy.criarNucleo({ dir: fs.mkdtempSync(path.join(dir, 'nb-')), agora: () => relogio, midia: Spy.midiaDisco(path.join(dir, 'mb')), tmpDir: path.join(dir, 'tmpb'), baixarQualquer: true,
    transcritor: () => Spy.transcritorAssembly('chave-aai', base), buscador });
  Nb.salvarRegras({ video_min_dias: 0 });   // a regra dos vídeos tem teste próprio
  const b = Nb.criarBiblioteca({ tipo: 'dominio', referencia: 'busca.com.br' }).biblioteca;
  const semLink = (id, p) => ({ ad_archive_id: id, page_id: p[0], page_name: p[1], copy: 'A mesma copy em vídeos diferentes', inicio_veiculacao: '2026-11-10' });
  const r = Nb.registrarColeta(b.id, { completa: true, anuncios: [semLink('7001', PA), semLink('7002', PA), semLink('7003', PB), semLink('7004', PB)] });
  assert.strictEqual(r.criativos_ativos, 4, 'mesma copy não junta: cada anúncio é um criativo até o vídeo chegar');
  assert.ok(Nb.detalheBiblioteca(b.id).criativos.every(c => c.midia_status === 'sem_link'));
  assert.deepStrictEqual(Nb.pendentesDaBiblioteca(b.id), [], 'sem link não entra na fila de download');
  assert.strictEqual(Nb.buscarVideos(b.id).a_buscar, 4);
  for (let i = 0; i < 200 && Nb.estadoBusca().rodando; i++) await new Promise(x => setTimeout(x, 25));
  for (let i = 0; i < 400 && (Nb.fila().fila || Nb.fila().rodando); i++) await new Promise(x => setTimeout(x, 50));
  assert.deepStrictEqual(pedidos, [['7001', '7002', '7003', '7004']], 'um anúncio por criativo, numa busca só');
  const det = Nb.detalheBiblioteca(b.id);
  const comVideo = det.criativos.filter(c => c.midia_status === 'ok');
  assert.strictEqual(comVideo.length, 2, '7001 e 7002 vieram com o mesmo arquivo: viraram um só; 7003 é outro');
  assert.strictEqual(comVideo.find(c => c.anuncios_ativos === 2).arquivo.startsWith('v/'), true);
  const falhou = det.criativos.find(c => c.midia_status === 'sem_link');
  assert.match(falhou.midia_erro, /não apareceu/);
  assert.strictEqual(Nb.estadoBusca().achados, 3);
  // a aba Anúncios: cada anúncio com o criativo dele
  assert.deepStrictEqual(det.anuncios.map(a => a.id).sort(), ['7001', '7002', '7003', '7004']);
  assert.strictEqual(det.anuncios.find(a => a.id === '7001').criativo_id, det.anuncios.find(a => a.id === '7002').criativo_id);
  // falhou 3 vezes: a busca automática desiste; o botão (forçar) tenta de novo
  for (let k = 0; k < 2; k++) { Nb.buscarVideos(b.id); for (let i = 0; i < 200 && Nb.estadoBusca().rodando; i++) await new Promise(x => setTimeout(x, 25)); }
  assert.strictEqual(Nb.buscarVideos(b.id).a_buscar, 0);
  assert.strictEqual(Nb.buscarVideos(b.id, true).a_buscar, 1);
  for (let i = 0; i < 200 && Nb.estadoBusca().rodando; i++) await new Promise(x => setTimeout(x, 25));
  Nb.db.close();
});

test('regra dos vídeos: só baixa quem está no ar há mais tempo ou tem mais cópias, até o teto; o resto fica no acervo sem o vídeo', async () => {
  const D = Date.parse('2026-11-30T15:00:00Z');
  let rel = D;
  const dia = n => new Date(D - n * DIA).toISOString().slice(0, 10);
  const vid = n => base + '/cdn/' + n + '?oe=FFFFFFFF';
  const achados = { '601': { video: vid('v1.mp4') }, '602': { video: vid('v2.mp4') }, '603': { video: vid('v3.mp4') }, '604': { imagem: base + '/cdn/img1.jpg' }, '605': { imagem: base + '/cdn/img2.jpg' } };
  const pedidos = [];
  const buscador = { disponivel: () => true, async buscar(ids, cb) { pedidos.push(ids.slice()); for (const id of ids) await cb(id, achados[id] || { erro: 'o vídeo não apareceu' }); return { tentados: ids.length }; } };
  const Nr = Spy.criarNucleo({ dir: fs.mkdtempSync(path.join(dir, 'nr-')), agora: () => rel, midia: Spy.midiaDisco(path.join(dir, 'mr')), tmpDir: path.join(dir, 'tmpr'), baixarQualquer: true, buscador });
  const esperar = async () => { for (let i = 0; i < 400 && (Nr.estadoBusca().rodando || Nr.fila().fila || Nr.fila().rodando); i++) await new Promise(x => setTimeout(x, 25)); };
  assert.deepStrictEqual([Nr.regras().video_min_dias, Nr.regras().video_min_copias, Nr.regras().video_teto], [7, 5, 10], 'o padrão: 7 dias, 5 cópias, 10 por coleta');
  Nr.salvarRegras({ video_teto: 3 });
  const b = Nr.criarBiblioteca({ tipo: 'dominio', referencia: 'regra.com.br' }).biblioteca;
  const a = (id, ini, qtd) => ({ ad_archive_id: id, page_id: '1', page_name: 'P', copy: 'copy ' + id, inicio_veiculacao: dia(ini), quantidade: qtd || 1 });
  // 601..603 no ar há 30/20/15 dias; 604 só 2 dias mas com 6 cópias; 605 e 606 novos e com poucas cópias (abaixo da regra)
  Nr.registrarColeta(b.id, { completa: true, anuncios: [a('601', 30), a('602', 20), a('603', 15), a('604', 2, 6), a('605', 3), a('606', 1, 2)] });
  const r = Nr.baixarDaBiblioteca(b.id, false);
  assert.deepStrictEqual([r.a_buscar, r.abaixo_da_regra, r.esperando], [3, 2, 1], 'teto 3: os mais antigos no ar primeiro; 604 espera a próxima');
  await esperar();
  assert.deepStrictEqual(pedidos, [['601', '602', '603']]);
  let det = Nr.detalheBiblioteca(b.id);
  const de = id => det.criativos.find(c => c.id === Nr.resolver(Nr.q('SELECT criativo_id FROM spy_anuncio WHERE ad_archive_id=?').get(id).criativo_id));
  assert.strictEqual(['601', '602', '603'].filter(id => de(id).midia_status === 'ok').length, 3);
  assert.deepStrictEqual([de('604').regra_video, de('605').regra_video, de('606').regra_video], ['copias', '', '']);
  assert.deepStrictEqual([det.processamento.aguardando_link, det.processamento.abaixo_da_regra], [1, 2]);
  assert.match(det.regra_video.texto, /7 dias.*5 cópias.*até 3/);
  // a coleta seguinte pega o que cumpre e ficou pro teto
  Nr.baixarDaBiblioteca(b.id, false);
  await esperar();
  assert.deepStrictEqual(pedidos[1], ['604']);
  det = Nr.detalheBiblioteca(b.id);
  assert.strictEqual(de('604').midia_status, 'ok');
  assert.deepStrictEqual(Nr.baixarDaBiblioteca(b.id, true).a_buscar, 0, 'o botão Baixar vídeos também respeita a regra');
  // "Baixar este": passa por cima da regra e busca só ele
  const c5 = de('605').id;
  assert.deepStrictEqual(Nr.pedirVideo(c5).a_buscar, 1);
  await esperar();
  assert.deepStrictEqual(pedidos[2], ['605']);
  assert.strictEqual(Nr.detalheCriativo(c5).midia_status, 'ok');
  // o tempo passa: 606 faz 7 dias no ar e entra sozinho na próxima coleta
  rel = D + 5 * DIA;
  assert.strictEqual(Nr.baixarDaBiblioteca(b.id, false).a_buscar, 0, '6 dias: ainda não');
  rel = D + 6 * DIA;
  assert.strictEqual(Nr.baixarDaBiblioteca(b.id, false).a_buscar, 1);
  await esperar();
  assert.deepStrictEqual(pedidos[3], ['606']);
  // o que o Facebook disse que saiu do ar não volta nem pelo botão
  Nr.q("UPDATE spy_criativo SET midia_tentativas=3, midia_erro='o Facebook diz que este anúncio não está mais na Biblioteca (saiu do ar)' WHERE id=?").run(de('606').id);
  assert.strictEqual(Nr.baixarDaBiblioteca(b.id, true).a_buscar, 0);
  // os números ficam nos limites
  assert.deepStrictEqual((({ video_min_dias, video_min_copias, video_teto }) => [video_min_dias, video_min_copias, video_teto])(Nr.salvarRegras({ video_min_dias: -3, video_min_copias: 'x', video_teto: 0 })), [0, 5, 1]);
  Nr.db.close();
});

test('o Facebook pedindo login: a busca para e avisa', async () => {
  const buscador = { disponivel: () => true, async buscar(ids, cb) { await cb(ids[0], { login: true, erro: 'o Facebook pediu login' }); return { bloqueado: true, erro: 'O Facebook pediu login ao servidor.' }; } };
  const Nl = Spy.criarNucleo({ dir: fs.mkdtempSync(path.join(dir, 'nl-')), agora: () => relogio, midia: Spy.midiaDisco(path.join(dir, 'ml')), tmpDir: path.join(dir, 'tmpl'), buscador });
  const b = Nl.criarBiblioteca({ tipo: 'dominio', referencia: 'login.com.br' }).biblioteca;
  Nl.registrarColeta(b.id, { anuncios: [{ ad_archive_id: '8101', copy: 'x', inicio_veiculacao: '2026-10-01' }] });
  Nl.buscarVideos(b.id);
  for (let i = 0; i < 200 && Nl.estadoBusca().rodando; i++) await new Promise(x => setTimeout(x, 25));
  assert.ok(Nl.estadoBusca().bloqueado_em > 0);
  assert.match(Nl.estadoBusca().erro, /login/);
  assert.strictEqual(Nl.detalheBiblioteca(b.id).busca.bloqueado_em > 0, true);
  Nl.db.close();
});

test('coleta antiga juntada pela copy: separa uma vez, cada anúncio com as etiquetas e a família', () => {
  const Nd = Spy.criarNucleo({ dir: fs.mkdtempSync(path.join(dir, 'nd-')), agora: () => relogio, midia: null, tmpDir: path.join(dir, 'tmpd') });
  const b = Nd.criarBiblioteca({ tipo: 'dominio', referencia: 'antiga.com.br' }).biblioteca;
  // é assim que a versão de 18/11 (0a8c6b7) gravou: sem link, tipo texto, todos no mesmo criativo pela copy
  const velho = id => ({ ad_archive_id: id, page_id: '1', page_name: 'P', copy: 'mesma copy', midia: { tipo: 'texto' } });
  Nd.registrarColeta(b.id, { completa: true, anuncios: [velho('9101'), velho('9102'), velho('9103')] });
  const c0 = Nd.detalheBiblioteca(b.id).criativos;
  assert.strictEqual(c0.length, 1);
  // a coleta real mandou midia.tipo 'video' sem o link: o criativo ficou 'video' + 'sem_midia', e é esse caso que tem que separar
  Nd.q("UPDATE spy_criativo SET tipo='video' WHERE id=?").run(c0[0].id);
  Nd.cfgGravar('dividido_por_copy_v1', 'rodou na 67763c5 sem pegar nada');
  Nd.salvarDoClaude({ criativo_id: c0[0].id, etiquetas: [{ campo: 'angulo', valor: 'Notícia' }], familia: 'B · Live privada' });
  assert.strictEqual(Nd.dividirPorCopy(), 2);
  assert.strictEqual(Nd.dividirPorCopy(), 0, 'uma vez só');
  const cs = Nd.detalheBiblioteca(b.id).criativos;
  assert.strictEqual(cs.length, 3);
  assert.ok(cs.every(c => c.midia_status === 'sem_link' && c.tipo === 'video' && c.familia.nome === 'B · Live privada' && c.etiquetas.angulo[0].valor === 'Notícia' && c.anuncios_ativos === 1));
  assert.deepStrictEqual(Nd.midiasFaltando(b.id).sort(), ['9101', '9102', '9103']);
  assert.strictEqual(Nd.mercado({ dim: 'angulo' }).linhas.find(l => l.valor === 'Notícia').criativos, 3);
  Nd.db.close();
});

test('o navegador de verdade (Chrome) acha o card pelo id numa página que imita a Biblioteca', { skip: !(fs.existsSync('/Applications/Google Chrome.app') || process.env.SPY_CHROMIUM_PATH) && 'sem Chrome nesta máquina' }, async () => {
  const pg = http.createServer((req, res) => {
    const id = new URL(req.url, 'http://x').searchParams.get('id');
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    if (id === '999') return res.end('<!doctype html><body><h1>Entre no Facebook</h1><p>Faça login para continuar</p></body>');
    const card = (i, v) => '<div><div><span>Ativo</span><span>Identificação da biblioteca: ' + i + '</span></div><img src="' + base + '/cdn/capa.jpg" width="40"><video src="' + base + '/cdn/' + v + '" poster="' + base + '/cdn/capa.jpg"></video></div>';
    // como o Facebook: a página traz outros anúncios além do pedido
    res.end('<!doctype html><body><div>' + card('111111111', 'v1.mp4') + card(id, 'v3.mp4') + card('222222222', 'v2.mp4') + '</div></body>');
  });
  await new Promise(r => pg.listen(0, '127.0.0.1', r));
  const bus = Spy.criarBuscador({ base: 'http://127.0.0.1:' + pg.address().port, pausaMs: 0, esperaMs: 3000 });
  const vistos = {};
  const r = await bus.buscar(['5551234', '999', '999'], (id, x) => { vistos[id] = x; });
  pg.close();
  assert.ok(vistos['5551234'], r.erro);
  assert.match(vistos['5551234'].video, /\/cdn\/v3\.mp4$/, 'o vídeo do card pedido, não o primeiro da página');
  assert.match(vistos['5551234'].capa, /capa\.jpg$/);
  assert.strictEqual(vistos['999'].login, true);
  assert.strictEqual(r.bloqueado, true, 'login duas vezes seguidas: para');
  assert.strictEqual(bus.aberto(), false, 'o navegador fechou');
});
