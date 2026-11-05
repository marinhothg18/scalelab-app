// Extração da faixa de ADs e leitura do nome do anúncio. Rodar: npm test
const test = require('node:test');
const assert = require('node:assert');
const { extrairFaixa, lerCampoFaixa, lerAnuncio } = require('../public/arq-faixa.js');

const faixa = (a, b) => ({ inicio: a, fim: b });

test('faixa: os casos pedidos', () => {
  assert.deepStrictEqual(extrairFaixa('197 ao 206 ads Kalebe'), faixa(197, 206));
  // B foi erro de numeração de uma remessa só: não é número de AD
  assert.strictEqual(extrairFaixa('Remessa 04 - 10 ads novos (B19 a B28)'), null);
  assert.strictEqual(extrairFaixa('AD245.1 - AD216.2 + C153'), null);
  assert.strictEqual(extrairFaixa('REMESSA 10'), null);
});

test('faixa: títulos reais e variações com AD', () => {
  assert.deepStrictEqual(extrairFaixa('197 ao 206 ads Kalebe Dionisio APOSTILAI - 05_10'), faixa(197, 206));
  assert.deepStrictEqual(extrairFaixa('AD197 a AD206'), faixa(197, 206));
  assert.deepStrictEqual(extrairFaixa('AD197 ao AD206 · Apostilai'), faixa(197, 206));
  assert.deepStrictEqual(extrairFaixa('ads 197 até 206'), faixa(197, 206));
  assert.deepStrictEqual(extrairFaixa('AD197-AD206'), faixa(197, 206));
  assert.deepStrictEqual(extrairFaixa('AD 197 - 206 Kalebe'), faixa(197, 206));
  assert.deepStrictEqual(extrairFaixa('REMESSA 10 - 197 ao 206'), faixa(197, 206));
  assert.deepStrictEqual(extrairFaixa('AD216 - roteiro novo'), faixa(216, 216));
});

test('faixa: o que não é faixa fica vazio', () => {
  for (const t of ['', null, 'NOVO PITCH TÁ NO DOCS DE BAIXO', 'REMESSA- 04 KALEBE', 'Lead 01 a 03', 'Aula 1 a 5',
    'R$ 197 a 297', 'Remessa 05 a 10/10', 'de 30 a 60 min', 'AD216.2 - AD245.1', '206 ao 197', '1 a 500', 'Remessa 04 (B19 a B28)']) {
    assert.strictEqual(extrairFaixa(t), null, 'título: ' + t);
  }
});

test('campo do formulário', () => {
  assert.deepStrictEqual(lerCampoFaixa('197 a 206'), faixa(197, 206));
  assert.deepStrictEqual(lerCampoFaixa('197-206'), faixa(197, 206));
  assert.deepStrictEqual(lerCampoFaixa('AD197 a AD206'), faixa(197, 206));
  assert.deepStrictEqual(lerCampoFaixa(' 216 '), faixa(216, 216));
  assert.deepStrictEqual(lerCampoFaixa(''), { vazio: true });
  assert.deepStrictEqual(lerCampoFaixa('abc'), { erro: true });
  assert.deepStrictEqual(lerCampoFaixa('206 a 197'), { erro: true });
  assert.deepStrictEqual(lerCampoFaixa('B19 a B28'), { erro: true });
});

test('anúncio: número simples e hook do próprio AD', () => {
  assert.deepStrictEqual(lerAnuncio('AD216'), [{ papel: 'anuncio', ad: 216 }]);
  assert.deepStrictEqual(lerAnuncio('216'), [{ papel: 'anuncio', ad: 216 }]);
  assert.deepStrictEqual(lerAnuncio(216), [{ papel: 'anuncio', ad: 216 }]);
  for (const [nome, ad, hook] of [['AD216.2', 216, 2], ['216.2', 216, 2], ['AD216.2_2', 216, 2], ['AD212.3_1', 212, 3],
    ['AD232.HK1', 232, 1], ['AD228HK.2', 228, 2], ['AD198HK1', 198, 1], ['AD237.hk2', 237, 2], ['Ad 02.h2', 2, 2]]) {
    assert.deepStrictEqual(lerAnuncio(nome), [{ papel: 'anuncio', ad, hook }], nome);
  }
});

test('anúncio: remontagem separa anúncio novo, hook e corpo', () => {
  assert.deepStrictEqual(lerAnuncio('AD245.1 - AD216.2 + C153'), [
    { papel: 'anuncio', ad: 245, hook: 1 }, { papel: 'hook', ad: 216, hook: 2 }, { papel: 'corpo', ad: 153 }]);
  assert.deepStrictEqual(lerAnuncio('AD248.2 - AD179.1 + AD212.1 + C212'), [
    { papel: 'anuncio', ad: 248, hook: 2 }, { papel: 'hook', ad: 179, hook: 1 }, { papel: 'hook', ad: 212, hook: 1 }, { papel: 'corpo', ad: 212 }]);
  assert.deepStrictEqual(lerAnuncio('AD256.2 - AD64.3 + C44.2'), [
    { papel: 'anuncio', ad: 256, hook: 2 }, { papel: 'hook', ad: 64, hook: 3 }, { papel: 'corpo', ad: 44 }]);
});

test('anúncio: H com hífen é o hook de outro AD', () => {
  const corpoHook = (c, h) => [{ papel: 'corpo', ad: c }, { papel: 'hook', ad: h }];
  assert.deepStrictEqual(lerAnuncio('AD94-H153'), corpoHook(94, 153));
  assert.deepStrictEqual(lerAnuncio('AD153-H94_2'), corpoHook(153, 94));
  assert.deepStrictEqual(lerAnuncio('AD44-H18-V2'), corpoHook(44, 18));
  assert.deepStrictEqual(lerAnuncio('AD18-H2_2'), corpoHook(18, 2));
});

test('anúncio: gravado por conta própria e nome sem número', () => {
  assert.deepStrictEqual(lerAnuncio('AD05-KALEB-RM'), [{ papel: 'semRoteiro', ad: 5 }]);
  assert.deepStrictEqual(lerAnuncio('ADTOP'), []);
  assert.deepStrictEqual(lerAnuncio('REMESSA 10'), []);
  assert.deepStrictEqual(lerAnuncio(''), []);
});
