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

// O pixel vive dentro de um template literal em server.js e é ENTREGUE como
// arquivo. `node --check server.js` acha aquilo tudo válido — é só uma string.
// Mas a barra invertida some na avaliação: um /\/+$/ escrito com uma barra só
// chega no navegador como //+$/, que é comentário, e o pixel inteiro para de
// carregar. Foi assim que ele foi ao ar quebrado em 19/08. Aqui a gente avalia
// o template e valida o resultado, que é o que a página realmente recebe.
function checarPixelServido() {
  const arquivo = 'server.js';
  if (!fs.existsSync(arquivo)) return;
  const src = fs.readFileSync(arquivo, 'utf8');
  const ini = src.indexOf('const PIXEL_JS = `');
  if (ini < 0) return;
  const fim = src.indexOf('`;', ini);
  if (fim < 0) return;
  let js;
  try {
    js = eval(src.slice(ini + 'const PIXEL_JS = '.length, fim + 1));
  } catch (e) {
    falhas++;
    console.error('✗ PIXEL_JS não montou: ' + e.message);
    return;
  }
  try {
    new Function(js);
  } catch (e) {
    falhas++;
    console.error('✗ o /px.js entregue ao navegador está quebrado\n   ' + e.message +
      '\n   (dentro do template literal a barra invertida precisa ser dobrada: \\\\. e \\\\/)');
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
checarPixelServido();
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
