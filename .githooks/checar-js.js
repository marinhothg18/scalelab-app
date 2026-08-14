// Valida a sintaxe do JavaScript do projeto, inclusive o que vive dentro de
// <script> nos HTML. Usado pelo hook de pre-commit e disponível pra rodar à mão:
//   node .githooks/checar-js.js
const fs = require('fs');
const path = require('path');

const ALVOS_JS = ['server.js'];
const PASTA_HTML = 'public';

let falhas = 0;

function checarJS(arquivo) {
  if (!fs.existsSync(arquivo)) return;
  const r = require('child_process').spawnSync(process.execPath, ['--check', arquivo], { encoding: 'utf8' });
  if (r.status !== 0) {
    falhas++;
    const linha = (r.stderr || '').split('\n').filter(Boolean).slice(0, 4).join('\n   ');
    console.error('✗ ' + arquivo + '\n   ' + linha);
  }
}

function checarHTML(arquivo) {
  const html = fs.readFileSync(arquivo, 'utf8');
  // ignora <script src=...> (código externo) e blocos que não são JavaScript
  const re = /<script(?![^>]*\bsrc=)([^>]*)>([\s\S]*?)<\/script>/g;
  let m, bloco = 0;
  while ((m = re.exec(html))) {
    const attrs = m[1] || '';
    if (/type\s*=\s*["'](?!text\/javascript|application\/javascript)/i.test(attrs)) continue;
    bloco++;
    try {
      new Function(m[2]);
    } catch (e) {
      falhas++;
      // conta as linhas até aqui, pra apontar onde olhar
      const linha = html.slice(0, m.index).split('\n').length;
      console.error('✗ ' + arquivo + ' (bloco ' + bloco + ', a partir da linha ' + linha + ')\n   ' + e.message);
    }
  }
}

ALVOS_JS.forEach(checarJS);
if (fs.existsSync(PASTA_HTML)) {
  fs.readdirSync(PASTA_HTML)
    .filter(f => f.endsWith('.html'))
    .forEach(f => checarHTML(path.join(PASTA_HTML, f)));
}

if (falhas) {
  console.error('\n' + falhas + ' arquivo(s) com JavaScript quebrado.');
  process.exit(1);
}
console.log('✓ JavaScript íntegro');
