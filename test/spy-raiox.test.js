// "O que mais estão fazendo" na biblioteca do Spy (20/11/2026): a conta que vai abaixo do gráfico. Formato e ângulo em %
// dos criativos no ar que têm a etiqueta, o que entrou no ar por dia e por semana (os que saíram também contam no
// histórico), combinações, idade, cópias, famílias e as frases da leitura, que só aparecem quando o número sustenta.
const { test } = require('node:test');
const assert = require('node:assert');
const { raioxDe } = require('../spy.js');

const HOJE = '2026-11-20';   // sexta
let n = 0;
function cr(inicio, extra) {
  extra = extra || {};
  const et = {};
  if (extra.f) et.formato = [{ valor: extra.f, parte: 'todo' }];
  if (extra.a) et.angulo = [{ valor: extra.a, parte: extra.parteA || 'todo' }];
  const dias = Math.round((Date.parse(HOJE) - Date.parse(inicio)) / 86400000);
  return { id: 'c' + (++n), tipo: extra.tipo || 'video', inicio, dias_no_ar: dias, anuncios_ativos: extra.ads != null ? extra.ads : 1, etiquetas: et,
    duracao_s: extra.dur || null, familia: extra.fam ? { id: 'f-' + extra.fam, nome: extra.fam } : null };
}
function biblioteca() {
  const l = [];
  for (let i = 0; i < 20; i++) l.push(cr('2026-10-30', i < 6 ? { f: 'Historinha IA', a: 'História', dur: 100, fam: 'vingança do ex' } : i < 8 ? { f: 'UGC / criadora', a: 'Contrário', dur: 40 } : {}));
  for (let i = 0; i < 15; i++) l.push(cr('2026-10-31', i < 2 ? { f: 'Historinha IA', a: 'Contrário', ads: 6 } : {}));
  for (let i = 0; i < 25; i++) l.push(cr('2026-11-06', i < 1 ? { f: 'Tela dividida', a: 'História', fam: 'guindaste' } : i < 2 ? { a: 'Fofoca', parteA: 'gancho' } : {}));
  for (let i = 0; i < 12; i++) l.push(cr('2026-11-13', i < 3 ? { ads: 3 } : {}));
  l.push(cr('2026-11-18')); l.push(cr('2026-11-19'));
  l.push(cr('2026-11-06', { f: 'Rosto / teleprompter', a: 'Inimigo', ads: 0 }));   // saiu do ar: só no histórico
  l.push(cr('2026-11-06', { tipo: 'texto', f: 'Rosto / teleprompter' }));         // anúncio só de texto: fora da conta
  return l;
}

test('formato e ângulo em % dos criativos no ar que têm a etiqueta', () => {
  const r = raioxDe(biblioteca(), HOJE);
  assert.strictEqual(r.no_ar, 74);
  assert.strictEqual(r.formato.marcados, 11);
  assert.deepStrictEqual(r.formato.linhas.slice(0, 3).map(x => [x.valor, x.criativos, x.pct]), [['Historinha IA', 8, 73], ['UGC / criadora', 2, 18], ['Tela dividida', 1, 9]]);
  assert.strictEqual(r.formato.linhas.find(x => x.valor === 'Historinha IA').dias_medio, 21);
  // todos os formatos da lista aparecem, os sem nenhum no fim e com 0; o do criativo que saiu do ar não conta
  assert.strictEqual(r.formato.linhas.length, 8);
  assert.deepStrictEqual(r.formato.linhas.find(x => x.valor === 'Rosto / teleprompter'), { valor: 'Rosto / teleprompter', criativos: 0, pct: 0, dias_medio: null });
  // a etiqueta de uma parte só (o gancho) também vale
  assert.deepStrictEqual(r.angulo.linhas.slice(0, 3).map(x => [x.valor, x.criativos]), [['História', 7], ['Contrário', 4], ['Fofoca', 1]]);
  assert.strictEqual(r.angulo.marcados, 12);
  assert.deepStrictEqual(r.combos.slice(0, 3).map(x => [x.formato, x.angulo, x.criativos]), [['Historinha IA', 'História', 6], ['UGC / criadora', 'Contrário', 2], ['Historinha IA', 'Contrário', 2]]);
});

test('histórico por dia e por semana (segunda a domingo), com os que já saíram do ar', () => {
  const r = raioxDe(biblioteca(), HOJE);
  assert.deepStrictEqual([r.dias[0].dia, r.dias[r.dias.length - 1].dia, r.dias.length], ['2026-10-30', HOJE, 22]);
  assert.strictEqual(r.dias.find(x => x.dia === '2026-11-06').novos, 26, 'os 25 no ar e o que saiu');
  assert.deepStrictEqual(r.semanas.map(s => [s.de, s.ate, s.novos, s.marcados_formato]), [
    ['2026-10-26', '2026-11-01', 35, 10], ['2026-11-02', '2026-11-08', 26, 2], ['2026-11-09', '2026-11-15', 12, 0], ['2026-11-16', HOJE, 2, 0]]);
  assert.deepStrictEqual(r.semanas[1].formato, { 'Tela dividida': 1, 'Rosto / teleprompter': 1 });
  assert.strictEqual(r.antes, 0);
  // criativo de 2 meses atrás fica em "antes", não numa semana
  assert.strictEqual(raioxDe([cr('2026-09-10')].concat(biblioteca()), HOJE).antes, 1);
});

test('idade, cópias, duração e famílias', () => {
  const r = raioxDe(biblioteca(), HOJE);
  assert.deepStrictEqual(r.idade.map(x => x.n), [2, 0, 12, 40, 20, 0]);
  assert.deepStrictEqual(r.copias.map(x => [x.faixa, x.n]), [['1', 69], ['2–4', 3], ['5–9', 2], ['10+', 0]]);
  assert.deepStrictEqual(r.duracao, { n: 8, media_s: 85 });
  assert.deepStrictEqual([r.familias.total, r.familias.top.map(f => [f.nome, f.criativos])], [2, [['vingança do ex', 6], ['guindaste', 1]]]);
});

test('a leitura rápida diz só o que os números sustentam', () => {
  const r = raioxDe(biblioteca(), HOJE), txt = r.leitura.map(x => x.b + x.t);
  assert.deepStrictEqual(txt, [
    'Historinha IA é o formato que mais aparece: 73% dos que têm formato marcado (8 de 11), quase sempre com o ângulo História (6 vezes).',
    'História é o ângulo mais usado: 58% (7 de 12), seguido de Contrário (33%).',
    'Lançam em ondas de 12 a 35 criativos, a cada 7 dias em média (30–31/10, 06/11, 13/11). Desde 14/11 entraram só 2.',
    '93% rodam com 1 anúncio só: testam em massa. Só 2 criativos têm 5 cópias ou mais: são os que estão empurrando.',
    'Vídeos de 1min25 em média (dos 8 baixados).'
  ]);
  // sem etiqueta e com pouca coisa: nenhuma frase de formato, ângulo, onda ou cópia
  const pouco = raioxDe([cr('2026-11-19'), cr('2026-11-20')], HOJE);
  assert.deepStrictEqual(pouco.leitura, []);
  assert.deepStrictEqual([pouco.formato.marcados, pouco.no_ar, pouco.dias.length], [0, 2, 2]);
  assert.deepStrictEqual(raioxDe([], HOJE).leitura, []);
});
