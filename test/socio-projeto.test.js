// Sócio por projeto (09/11/2026): quem tem projetos marcados só recebe e só grava o que é deles.
// Sobe o servidor com dois projetos e confere o corte no servidor, que é o que protege de verdade.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const RAIZ = path.join(__dirname, '..');
const espera = ms => new Promise(r => setTimeout(r, ms));
const ate = async (cond, ms, oQue, log) => { const fim = Date.now() + ms; for (;;) { try { if (await cond()) return; } catch (e) {} if (Date.now() > fim) throw new Error('demorou demais: ' + oQue + '\n' + (log ? log().slice(-1500) : '')); await espera(150); } };
let srv, dir, base, log = '', dono, limitado, livre;
const H = () => 1;

async function chamar(metodo, caminho, { token, corpo } = {}) {
  const headers = {}; if (token) headers.Authorization = 'Bearer ' + token; if (corpo !== undefined) headers['Content-Type'] = 'application/json';
  const r = await fetch(base + caminho, { method: metodo, headers, body: corpo !== undefined ? JSON.stringify(corpo) : undefined });
  let dados = null; try { dados = await r.json(); } catch (e) {}
  return { status: r.status, dados };
}
const entrar = async (email, senha) => (await chamar('POST', '/api/auth/login', { corpo: { email, senha } })).dados.token;
const por = (token, chave, valor) => chamar('PUT', '/api/store/' + chave, { token, corpo: valor });
const AGORA = Date.now();
const item = (id, resto) => Object.assign({ id, _updatedAt: AGORA }, resto);

before(async () => {
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-socioprojeto-'));
  // os dois projetos existem na Utmify: é daí que a Análise de tráfego tira o id de cada um
  fs.writeFileSync(path.join(dir, 'db.json'), JSON.stringify({ store: { sl_integracoes_utmify_mcp: { token: 'token-de-teste', dashboards: [{ id: 'd1', nome: 'CONCURSO', ativo: true }, { id: 'd2', nome: 'RENDA EXTRA', ativo: true }] } }, timestamps: {}, api_tokens: [], api_logs: [] }));
  const porta = 57000 + Math.floor(Math.random() * 2000);
  base = 'http://127.0.0.1:' + porta;
  srv = spawn(process.execPath, [path.join(RAIZ, 'server.js')], { cwd: RAIZ, env: { PATH: process.env.PATH, HOME: process.env.HOME, PORT: String(porta), TMX_DATA_DIR: dir }, stdio: ['ignore', 'pipe', 'pipe'] });
  srv.stdout.on('data', b => { log += b; }); srv.stderr.on('data', b => { log += b; });
  await ate(async () => (await fetch(base + '/api/ping')).ok, 20000, 'servidor subir', () => log);
  await ate(() => /sessões derrubadas/.test(log), 40000, 'a rotina das sessões rodar', () => log);
  dono = await entrar('thiago@axcend.com', 'axcend2026');
  assert.ok(dono, log.slice(-1500));
  await por(dono, 'sl_nichos', [item('n1', { nome: 'CONCURSO' }), item('n2', { nome: 'RENDA EXTRA' })]);
  await por(dono, 'sl_ofertas_v2', [item('o1', { nome: 'PROJETO KALEBE', nichoId: 'n1' }), item('o2', { nome: 'RENDA IZA', nichoId: 'n2' })]);
  await por(dono, 'tasks', [item(1, { titulo: 'do concurso', ofertaId: 'o1', nichoId: 'n1' }), item(2, { titulo: 'da renda', ofertaId: 'o2', nichoId: 'n2' }), item(3, { titulo: 'sem projeto' })]);
  await por(dono, 'criativos', [item(11, { nome: 'c1', ofertaId: 'o1' }), item(12, { nome: 'c2', ofertaId: 'o2' })]);
  await por(dono, 'rituais', [item(21, { nome: 'r1', ofertaId: 'o1' }), item(22, { nome: 'r2' })]);
  await por(dono, 'sl_arq_projetos', [item('a1', { nome: 'PROJETO KALEBE', ofertaId: 'o1' }), item('a2', { nome: 'RENDA IZA', ofertaId: 'o2' })]);
  await por(dono, 'sl_funis', [item('f1', { nome: 'Funil', projeto: 'CONCURSO' }), item('f2', { nome: 'Outro', projeto: 'RENDA EXTRA' })]);
  await por(dono, 'sl_redirecionadores', [item('t1', { slug: 'teste-a', projeto: 'CONCURSO' }), item('t2', { slug: 'teste-b', projeto: 'RENDA EXTRA' })]);
  await por(dono, 'sl_rh_colaboradores', [item('rh1', { nome: 'Fulano', salario: 9000 })]);
  await por(dono, 'sl_notifs', [item('nt1', { destId: 'u-lim', titulo: 'minha' }), item('nt2', { destId: 'u-outro', titulo: 'de outra pessoa' })]);
  const linha = (id, camp, dash, gasto) => item(id, { data: '2026-11-01', fonte: 'utmify', nivel: 'campanha', dashboard: dash, campanhaId: camp, campanha: 'Campanha ' + camp, investimento: gasto, faturamento: 0, lucro: 0, vendas: 0, impressoes: 0, cliques: 0 });
  await por(dono, 'sl_metricas_ads', [linha('m1', '701', 'CONCURSO', 100), linha('m2', '702', 'RENDA EXTRA', 999)]);
  await por(dono, 'sl_usuarios', [
    item('u-lim', { nome: 'Limitada', email: 'lim@tmx.test', senha: 'senha-limitada-1', cargo: 'Sócio', ativo: true, projetos: ['CONCURSO'] }),
    item('u-livre', { nome: 'Livre', email: 'livre@tmx.test', senha: 'senha-livre-1', cargo: 'Sócio', ativo: true })
  ]);
  limitado = await entrar('lim@tmx.test', 'senha-limitada-1');
  livre = await entrar('livre@tmx.test', 'senha-livre-1');
  assert.ok(limitado && livre);
});
after(async () => {
  if (srv && srv.exitCode === null) { srv.kill('SIGTERM'); await Promise.race([new Promise(r => srv.once('exit', r)), espera(10000)]); }
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});
const ids = l => (l || []).map(x => x.id);

test('o que chega para quem tem projeto marcado', async (t) => {
  for (const [nome, ler] of [['carga completa', async () => (await chamar('GET', '/api/store', { token: limitado })).dados], ['atualização', async () => (await chamar('GET', '/api/updates/0', { token: limitado })).dados.data]]) {
    await t.test(nome, async () => {
      const s = await ler();
      assert.deepStrictEqual(ids(s.tasks), [1], 'demanda de outro projeto e sem projeto não saem');
      assert.deepStrictEqual(ids(s.criativos), [11]);
      assert.deepStrictEqual(ids(s.rituais), [21]);
      assert.deepStrictEqual(ids(s.sl_arq_projetos), ['a1']);
      assert.deepStrictEqual(ids(s.sl_funis), ['f1']);
      assert.deepStrictEqual(ids(s.sl_ofertas_v2), ['o1']);
      assert.deepStrictEqual(ids(s.sl_nichos), ['n1']);
      assert.deepStrictEqual(ids(s.sl_notifs), ['nt1']);
      assert.strictEqual(s.sl_rh_colaboradores, undefined, 'RH não sai');
      assert.ok(Array.isArray(s.sl_usuarios) && !JSON.stringify(s.sl_usuarios).includes('senhaHash'));
    });
  }
});

test('o que ela grava fica dentro dos projetos', async (t) => {
  await t.test('edita e cria no projeto dela', async () => {
    const r = await por(limitado, 'tasks', [item(1, { titulo: 'editada', ofertaId: 'o1', _updatedAt: AGORA + 5000 }), item(4, { titulo: 'nova', ofertaId: 'o1', _updatedAt: AGORA + 5000 })]);
    assert.strictEqual(r.status, 200);
    const s = (await chamar('GET', '/api/store', { token: dono })).dados;
    assert.strictEqual(s.tasks.find(x => x.id === 1).titulo, 'editada');
    assert.ok(s.tasks.find(x => x.id === 4));
    assert.ok(s.tasks.find(x => x.id === 2), 'o que ela não recebe continua lá');
  });
  await t.test('não mexe em item de outro projeto', async () => {
    await por(limitado, 'tasks', [item(2, { titulo: 'invadida', ofertaId: 'o1', _updatedAt: AGORA + 9000 })]);
    assert.strictEqual((await chamar('GET', '/api/store', { token: dono })).dados.tasks.find(x => x.id === 2).titulo, 'da renda');
  });
  await t.test('não empurra o item dela para outro projeto', async () => {
    await por(limitado, 'tasks', [item(1, { titulo: 'movida', ofertaId: 'o2', _updatedAt: AGORA + 9000 })]);
    assert.strictEqual((await chamar('GET', '/api/store', { token: dono })).dados.tasks.find(x => x.id === 1).ofertaId, 'o1');
  });
  await t.test('não grava em chave fora da lista nem na lista de projetos', async () => {
    assert.strictEqual((await por(limitado, 'sl_rh_colaboradores', [item('rh2', { nome: 'x' })])).status, 403);
    assert.strictEqual((await por(limitado, 'sl_ofertas_v2', [item('o9', { nome: 'x', nichoId: 'n1' })])).status, 403);
  });
  await t.test('não tira o próprio limite', async () => {
    await por(limitado, 'sl_usuarios', [item('u-lim', { nome: 'Limitada', projetos: [], cargo: 'Diretoria', _updatedAt: AGORA + 9000 })]);
    const u = (await chamar('GET', '/api/store', { token: dono })).dados.sl_usuarios.find(x => x.id === 'u-lim');
    assert.deepStrictEqual(u.projetos, ['CONCURSO']);
    assert.strictEqual(u.cargo, 'Sócio');
  });
  await t.test('lixeira: só o que é dos projetos dela', async () => {
    assert.strictEqual((await chamar('POST', '/api/lixeira/soft-delete', { token: limitado, corpo: { key: 'tasks', itemId: 2 } })).status, 403);
    assert.strictEqual((await chamar('POST', '/api/lixeira/soft-delete', { token: limitado, corpo: { key: 'tasks', itemId: 4, tipo: 'Demanda' } })).status, 200);
    assert.ok(!(await chamar('GET', '/api/store', { token: dono })).dados.tasks.find(x => x.id === 4));
    assert.strictEqual((await chamar('POST', '/api/lixeira/soft-delete', { token: limitado, corpo: { key: 'sl_nichos', itemId: 'n1' } })).status, 403);
  });
});

test('as outras portas', async (t) => {
  await t.test('rota que não está na lista é recusada', async () => {
    for (const [m, c] of [['GET', '/api/recuperacao?dias=7'], ['GET', '/api/assinaturas'], ['GET', '/api/canais'], ['GET', '/api/custos'], ['GET', '/api/venda/123'], ['GET', '/api/pessoa/123'], ['GET', '/api/billing/me'], ['GET', '/api/funil/diagnostico']])
      assert.strictEqual((await chamar(m, c, { token: limitado })).status, 403, c);
  });
  await t.test('funil de outro projeto é recusado, e sem funil também', async () => {
    assert.strictEqual((await chamar('GET', '/api/funil/stats?funil=f2', { token: limitado })).status, 403);
    assert.strictEqual((await chamar('GET', '/api/funil/stats', { token: limitado })).status, 403);
    assert.strictEqual((await chamar('GET', '/api/funil/stats?funil=f1', { token: limitado })).status, 200);
  });
  await t.test('teste A/B de outro projeto é recusado', async () => {
    assert.strictEqual((await chamar('GET', '/api/ab/stats?teste=teste-b', { token: limitado })).status, 403);
  });
  await t.test('vendas e páginas só pelo nome dos projetos dela', async () => {
    assert.strictEqual((await chamar('GET', '/api/projeto/vendas?projeto=RENDA%20EXTRA', { token: limitado })).status, 403);
    assert.strictEqual((await chamar('GET', '/api/paginas?projeto=RENDA%20EXTRA', { token: limitado })).status, 403);
    assert.strictEqual((await chamar('GET', '/api/vendas/por-canal?de=2026-11-01&ate=2026-11-02&projeto=RENDA%20EXTRA', { token: limitado })).status, 403);
  });
  await t.test('Análise de tráfego: só as campanhas do projeto dela', async () => {
    const ver = q => chamar('GET', '/api/metricas/consolidado?de=2026-11-01&ate=2026-11-01' + q, { token: limitado });
    const campanhas = r => r.dados.porCampanha.map(c => c.campanhaId);
    const dela = await ver('&projeto=d1');
    assert.strictEqual(dela.status, 200, JSON.stringify(dela.dados));
    assert.deepStrictEqual(campanhas(dela), ['701']);
    const semEscolher = await ver('');
    assert.strictEqual(semEscolher.status, 200);
    assert.deepStrictEqual(campanhas(semEscolher), ['701'], 'sem dizer o projeto, cai no dela e não em todos');
    assert.strictEqual((await ver('&projeto=d2')).status, 403);
    assert.strictEqual((await ver('&projeto=nao-existe')).status, 403, 'id desconhecido devolveria todos os projetos');
    assert.strictEqual((await chamar('GET', '/api/metricas/campanha?id=702', { token: limitado })).status, 403);
    assert.notStrictEqual((await chamar('GET', '/api/metricas/campanha?id=701', { token: limitado })).status, 403);
    assert.deepStrictEqual(campanhas(await chamar('GET', '/api/metricas/consolidado?de=2026-11-01&ate=2026-11-01', { token: dono })).sort(), ['701', '702'], 'o Dono continua vendo os dois');
  });
  await t.test('financeiro: só o resultado, e nada da empresa', async () => {
    const r = await chamar('GET', '/api/fin/resultado?de=2026-11-01&ate=2026-11-02', { token: limitado });
    assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
    assert.deepStrictEqual(r.dados.rh, { pessoas: 0, comSalario: 0 });
    assert.deepStrictEqual(r.dados.gateways, []);
    assert.ok(!('saldoInicial' in r.dados.cfg));
    for (const c of ['/api/fin/dados', '/api/fin/conexoes', '/api/fin/caixa?de=2026-11-01&ate=2026-11-02'])
      assert.strictEqual((await chamar('GET', c, { token: limitado })).status, 403, c);
  });
  await t.test('Meta e Configurações seguem fechadas', async () => {
    assert.strictEqual((await chamar('GET', '/api/meta/conexao', { token: limitado })).status, 403);
    assert.strictEqual((await chamar('POST', '/api/meta/orcamento', { token: limitado, corpo: { nivel: 'campanha', id: '1', valor: 1 } })).status, 403);
  });
});

test('quem não tem limite não muda nada', async (t) => {
  await t.test('Sócio sem projeto marcado continua vendo tudo, sem o Financeiro', async () => {
    const s = (await chamar('GET', '/api/store', { token: livre })).dados;
    assert.ok(ids(s.tasks).includes(2) && ids(s.tasks).includes(3));
    assert.ok(Array.isArray(s.sl_rh_colaboradores), 'Sócio livre continua vendo o RH');
    assert.strictEqual((await chamar('GET', '/api/fin/resultado?de=2026-11-01&ate=2026-11-02', { token: livre })).status, 403);
    assert.notStrictEqual((await chamar('GET', '/api/recuperacao?dias=7', { token: livre })).status, 403);
  });
  await t.test('o Dono continua vendo tudo', async () => {
    const r = await chamar('GET', '/api/fin/resultado?de=2026-11-01&ate=2026-11-02', { token: dono });
    assert.strictEqual(r.status, 200);
    assert.ok('saldoInicial' in r.dados.cfg);
    assert.ok(ids((await chamar('GET', '/api/store', { token: dono })).dados.tasks).includes(3));
  });
  await t.test('mudar o cargo tira o limite na hora', async () => {
    await por(dono, 'sl_usuarios', [item('u-lim', { nome: 'Limitada', email: 'lim@tmx.test', cargo: 'Copy', ativo: true, projetos: ['CONCURSO'], _updatedAt: Date.now() + 60000 })]);
    assert.ok(ids((await chamar('GET', '/api/store', { token: limitado })).dados.tasks).includes(2));
  });
});
