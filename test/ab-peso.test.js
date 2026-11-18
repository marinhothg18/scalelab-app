// Peso 0 no teste A/B (18/11/2026). "100%" numa variante zera o peso das outras, e a tela avisa "todo o
// tráfego vai pra esta variante". O sorteio fazia "Number(peso) || 1": o 0 virava 1 e o link seguia dividindo
// meio a meio. Confere: peso 0 não recebe ninguém, com todos em 0 o link ainda manda pra alguma variante, os
// números do teste mostram o 0, e o pixel (que sorteia o teste de checkout no navegador) continua válido.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('child_process');
const vm = require('vm');
const fs = require('fs');
const os = require('os');
const path = require('path');

const RAIZ = path.join(__dirname, '..');
const espera = ms => new Promise(r => setTimeout(r, ms));
let dir, srv, base, log = '', dono;
const ate = async (cond, ms, oQue) => { const fim = Date.now() + ms; for (;;) { try { if (await cond()) return; } catch (e) {} if (Date.now() > fim) throw new Error('demorou demais: ' + oQue + '\n' + log.slice(-2000)); await espera(150); } };
const variante = (id, url, peso) => Object.assign({ id, nome: 'Variante ' + id, url }, peso === undefined ? {} : { peso });

before(async () => {
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-ab-peso-'));
  fs.writeFileSync(path.join(dir, 'db.json'), JSON.stringify({ store: { sl_redirecionadores: [
    { id: 'r1', slug: 'escala', nome: 'ESCALA', ativo: true, destinos: [variante('a', 'https://a.exemplo/', 100), variante('b', 'https://b.exemplo/', 0)] },
    { id: 'r2', slug: 'zerado', nome: 'ZERADO', ativo: true, destinos: [variante('a', 'https://a.exemplo/', 0), variante('b', 'https://b.exemplo/', 0)] },
    { id: 'r3', slug: 'antigo', nome: 'ANTIGO', ativo: true, destinos: [variante('a', 'https://a.exemplo/'), variante('b', 'https://b.exemplo/')] }
  ] }, timestamps: {}, api_tokens: [], api_logs: [], sessions: [] }));
  const porta = 41000 + Math.floor(Math.random() * 1500);
  base = 'http://127.0.0.1:' + porta;
  srv = spawn(process.execPath, [path.join(RAIZ, 'server.js')], { cwd: RAIZ, env: { PATH: process.env.PATH, HOME: process.env.HOME, PORT: String(porta), TMX_DATA_DIR: dir }, stdio: ['ignore', 'pipe', 'pipe'] });
  srv.stdout.on('data', b => { log += b; }); srv.stderr.on('data', b => { log += b; });
  await ate(async () => (await fetch(base + '/api/ping')).ok, 20000, 'servidor subir');
  await ate(() => /sessões derrubadas/.test(log), 40000, 'a rotina das sessões rodar');
  const r = await fetch(base + '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'thiago@axcend.com', senha: 'axcend2026' }) });
  dono = (await r.json()).token;
});
after(async () => {
  if (srv && srv.exitCode === null) { srv.kill('SIGTERM'); await Promise.race([new Promise(r => srv.once('exit', r)), espera(10000)]); }
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});
// cada pedido é uma pessoa nova (sem o biscoito de quem já foi sorteado)
async function destinos(slug, n) {
  const vistos = {};
  for (let i = 0; i < n; i++) {
    const r = await fetch(base + '/r/' + slug + '?utm_source=FB', { redirect: 'manual' });
    const host = new URL(r.headers.get('location')).host;
    vistos[host] = (vistos[host] || 0) + 1;
  }
  return vistos;
}

test('100% numa variante: a de peso 0 não recebe ninguém', async () => {
  assert.deepStrictEqual(await destinos('escala', 40), { 'a.exemplo': 40 });
});

test('todas em 0: o link ainda manda pra alguma variante', async () => {
  const v = await destinos('zerado', 30);
  assert.strictEqual((v['a.exemplo'] || 0) + (v['b.exemplo'] || 0), 30);
});

test('variante sem peso continua valendo 1 (teste antigo divide igual)', async () => {
  const v = await destinos('antigo', 60);
  assert.ok(v['a.exemplo'] > 5 && v['b.exemplo'] > 5, JSON.stringify(v));
});

test('os números do teste mostram o peso 0 e a fatia 0%', async () => {
  const r = await fetch(base + '/api/ab/stats?slug=escala&teste=escala', { headers: { Authorization: 'Bearer ' + dono } });
  const d = await r.json();
  assert.strictEqual(r.status, 200, JSON.stringify(d));
  const b = d.variantes.find(x => x.id === 'b');
  assert.deepStrictEqual([b.peso, b.fatiaAlvo], [0, 0]);
});

test('o pixel continua um JavaScript válido', async () => {
  const codigo = await (await fetch(base + '/px.js')).text();
  assert.doesNotThrow(() => new vm.Script(codigo));
});
