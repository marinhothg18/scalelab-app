// Atributo data-* com aspas a mais quebra a tela sem dar erro de JavaScript:
// '<input data-pp=""'+i+'"' vira data-pp="" e todo campo fica com o mesmo índice.
// Foi assim que o passo Projetos do cadastro passou a guardar só o último nome
// (07/11/2026) e o botão "Entrar como suporte" da Central Admin perdeu o código.
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

test('nenhuma página monta atributo data-* com aspas a mais', () => {
  const dir = path.join(__dirname, '..', 'public');
  const achados = [];
  for (const f of fs.readdirSync(dir).filter(n => n.endsWith('.html'))) {
    fs.readFileSync(path.join(dir, f), 'utf8').split('\n').forEach((linha, i) => {
      if (/data-[a-z0-9-]+=""'\s*\+/.test(linha)) achados.push(f + ':' + (i + 1));
    });
  }
  assert.deepStrictEqual(achados, []);
});
