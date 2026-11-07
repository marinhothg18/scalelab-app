// Módulos arquivados por empresa (07/11/2026, decisão do Thiago: "tá arquivado geral").
// Na TMX vale a lista de sl_modulos_arquivados, como sempre. Fora da TMX os 5 módulos
// (IA, Educacional, Infra, Ajuda, Tour) ficam sempre fora: não aparecem no menu, a página
// não abre nem pra Diretoria, e a seção de arquivar em Configurações some (soTmx).
// Carrega as funções do próprio ScaleLab.html num ambiente simulado (sem navegador).
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const HTML = fs.readFileSync(path.join(__dirname, '..', 'public', 'ScaleLab.html'), 'utf8');
function trecho(de, ate) {
  const i = HTML.indexOf(de), j = HTML.indexOf(ate, i);
  assert.ok(i >= 0 && j > i, 'não achei o trecho que começa em: ' + de);
  return HTML.slice(i, j);
}
const CODIGO = trecho('function tmxEmpresa(){', 'function urlPublica(') + '\n' +
               trecho('var MODULOS_ARQUIVAVEIS = [', '\nfunction _applyNavPermissions(');

function aparelho(guardado) {
  const armazenado = new Map(Object.entries(guardado));
  const elementos = {};
  const el = id => (elementos[id] = elementos[id] || { id, style: { display: '' } });
  const ctx = {
    localStorage: { getItem: k => (armazenado.has(k) ? armazenado.get(k) : null), setItem: (k, v) => armazenado.set(k, String(v)) },
    document: { getElementById: el },
    confirm: () => true,
    currentUser: { id: 'u1', cargo: 'Diretoria' },
    _applyNavPermissions: () => {},
    _esc: s => String(s)
  };
  ctx.g = (k, d) => { try { const v = JSON.parse(ctx.localStorage.getItem(k)); return v == null ? d : v; } catch (e) { return d; } };
  ctx.s = (k, v) => ctx.localStorage.setItem(k, JSON.stringify(v));
  vm.createContext(ctx);
  vm.runInContext(CODIGO, ctx);
  return { ctx, el, armazenado };
}
const TODOS = ['iacopy', 'educacional', 'infra', 'ajuda', 'tour'];

test('TMX: vale a lista de sl_modulos_arquivados, como sempre', () => {
  const { ctx, el } = aparelho({ sl_modulos_arquivados: JSON.stringify(TODOS) });   // aparelho sem marca = TMX
  assert.deepStrictEqual([...ctx._modulosArquivados()], TODOS);
  // reativar na TMX continua funcionando
  ctx.toggleModuloArquivado('iacopy');
  assert.ok(!ctx._modulosArquivados().includes('iacopy'));
  ctx._aplicarModulosArquivados();
  assert.strictEqual(el('nav-iacopy').style.display, '', 'IA volta pro menu da TMX quando reativada');
});

test('empresa nova: os 5 módulos ficam fora mesmo com a lista vazia', () => {
  const { ctx, el, armazenado } = aparelho({ sl_empresa_id: 'e0595691', sl_empresa_base: '/e/e0595691', sl_modulos_arquivados: '[]' });
  assert.deepStrictEqual([...ctx._modulosArquivados()], TODOS);
  ctx._aplicarModulosArquivados();
  for (const nav of ['nav-iacopy', 'nav-educacional', 'nav-infra', 'nav-ajuda', 'nav-tour']) {
    assert.strictEqual(el(nav).style.display, 'none', nav + ' some do menu');
  }
  for (const pagina of ['iacopy', 'educacional', 'infra']) {
    assert.ok(ctx._moduloArquivadoDaPagina(pagina), 'a página ' + pagina + ' conta como arquivada');
  }
  // tentar reativar não muda nada
  ctx.toggleModuloArquivado('iacopy');
  assert.strictEqual(armazenado.get('sl_modulos_arquivados'), '[]');
  assert.deepStrictEqual([...ctx._modulosArquivados()], TODOS);
});

test('a página arquivada não abre fora da TMX nem pra Diretoria, e o Tour não começa sozinho', () => {
  const goTo = trecho('function goTo(id){', '\n}\n');
  assert.match(goTo, /if\(_mArq && \(!_ehDir \|\| !tmxEhTmx\(\)\)\) id = 'dashboard';/);
  const tour = trecho('function iniciarOnboarding(forcar){', '\n}\n');
  assert.match(tour, /if\(!tmxEhTmx\(\)\) return;/);
  // Configurações: a seção Módulos arquivados só aparece na TMX (soTmx). O Acesso por API
  // vale pra empresa também (07/11/2026): cada uma gera os tokens dela, pro MCP e a API dela.
  const secoes = trecho('modulos:     {', '\n');
  assert.match(secoes, /soTmx:true/);
  assert.doesNotMatch(trecho("{ id:'api',", '\n'), /soTmx/);
  assert.match(trecho('function _cfgEhTmx(){', '\n'), /tmxEhTmx\(\)/);
});
