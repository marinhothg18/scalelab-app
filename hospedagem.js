// Hospedagem própria: domínio de cliente apontado pro sistema (Cloudflare for SaaS) e páginas guardadas
// na Cloudflare. Roda só na portaria: as chaves não chegam aos motores das empresas, que pedem pelo
// canal interno (_atenderMotor) e a empresa de quem pede é sempre a do motor.
//
// Sem CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID e CLOUDFLARE_ZONE_ID nada disso liga: o cliente só vê a
// opção de publicar na própria hospedagem por FTP.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const BUCKET = 'tmx-paginas', SCRIPT = 'tmx-paginas', ARQ_WORKER = path.join(__dirname, 'cloudflare', 'worker.mjs');
const so_teste = v => (process.env[v] && !fs.existsSync('/data')) ? process.env[v] : '';
const DOMINIO_RE = /^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/;
// domínios do próprio sistema nunca viram domínio de cliente
const RESERVADOS = /(^|\.)(centraltmx\.com|paginasnoar\.com|railway\.app)$|^ir\.kalebeaprovado\.online$/;

module.exports = function montarHospedagem({ platPrep }) {
  const cfg = () => ({ token: process.env.CLOUDFLARE_API_TOKEN || '', conta: process.env.CLOUDFLARE_ACCOUNT_ID || '', zona: process.env.CLOUDFLARE_ZONE_ID || '',
    alvo: process.env.HOSPEDAGEM_ALVO || 'paginas.paginasnoar.com', origem: process.env.HOSPEDAGEM_ORIGEM || 'https://app.centraltmx.com' });
  const ligada = () => { const c = cfg(); return !!(c.token && c.conta && c.zona); };
  const apiBase = () => so_teste('CLOUDFLARE_API_BASE') || 'https://api.cloudflare.com/client/v4';
  const adminBase = () => so_teste('HOSPEDAGEM_ADMIN_BASE') || 'https://' + cfg().alvo;
  const segredo = () => crypto.createHash('sha256').update('tmx-hospedagem:' + cfg().token).digest('hex');

  async function cf(metodo, caminho, corpo, opc = {}) {
    const headers = { Authorization: 'Bearer ' + cfg().token };
    let body;
    if (opc.form) body = opc.form; else if (corpo !== undefined) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(corpo); }
    const r = await fetch(apiBase() + caminho, { method: metodo, headers, body, signal: AbortSignal.timeout(opc.ms || 20000) });
    let j = null; try { j = await r.json(); } catch (e) {}
    if (!r.ok || !j || j.success === false) {
      const e0 = j && j.errors && j.errors[0];
      const e = new Error((e0 && e0.message) || ('A Cloudflare respondeu ' + r.status));
      e.codigo = e0 && e0.code; e.status = r.status;
      throw e;
    }
    return j.result;
  }
  async function admin(metodo, acao, qs, corpo, cab) {
    const r = await fetch(adminBase() + '/_tmx-admin/' + acao + (qs ? '?' + qs : ''), { method: metodo,
      headers: Object.assign({ Authorization: 'Bearer ' + segredo() }, cab || {}), body: corpo, signal: AbortSignal.timeout(60000) });
    let j = null; try { j = await r.json(); } catch (e) {}
    if (!r.ok || !j || !j.ok) throw new Error((j && j.erro) || ('O armazenamento respondeu ' + r.status));
    return j;
  }

  const lerCfg = k => { const x = platPrep('SELECT v FROM plataforma_cfg WHERE k=?').get(k); return x ? x.v : ''; };
  const gravarCfg = (k, v) => platPrep('INSERT INTO plataforma_cfg(k, v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v').run(k, v);

  // Instala tudo o que depende da conta: o armazenamento, o programa e a rota. Roda ao ligar o servidor
  // e só manda o programa de novo se ele mudou.
  async function instalar() {
    if (!ligada()) return { ok: false, motivo: 'sem chave' };
    const c = cfg();
    try { await cf('POST', '/accounts/' + c.conta + '/r2/buckets', { name: BUCKET }); }
    catch (e) { if (e.status !== 409 && !/already exists/i.test(e.message)) throw e; }
    const fonte = fs.readFileSync(ARQ_WORKER, 'utf8');
    const marca = crypto.createHash('sha256').update(fonte + '|' + segredo() + '|' + c.alvo + '|' + c.origem).digest('hex');
    if (lerCfg('hosp_worker') !== marca) {
      const form = new FormData();
      form.append('metadata', JSON.stringify({ main_module: 'worker.mjs', compatibility_date: '2026-01-15', bindings: [
        { type: 'r2_bucket', name: 'PAGINAS', bucket_name: BUCKET }, { type: 'secret_text', name: 'SEGREDO', text: segredo() }, { type: 'plain_text', name: 'ALVO', text: c.alvo }, { type: 'plain_text', name: 'ORIGEM', text: c.origem }] }));
      form.append('worker.mjs', new Blob([fonte], { type: 'application/javascript+module' }), 'worker.mjs');
      await cf('PUT', '/accounts/' + c.conta + '/workers/scripts/' + SCRIPT, undefined, { form, ms: 60000 });
      gravarCfg('hosp_worker', marca);
    }
    const rotas = await cf('GET', '/zones/' + c.zona + '/workers/routes');
    if (!(rotas || []).some(r => r.pattern === '*/*' && r.script === SCRIPT)) await cf('POST', '/zones/' + c.zona + '/workers/routes', { pattern: '*/*', script: SCRIPT });
    return { ok: true };
  }

  const dono = host => platPrep('SELECT * FROM dominios_hospedados WHERE host=?').get(host);
  const eDele = (empresa, host) => { const d = dono(host); return !!d && d.empresa === empresa; };
  const limpo = v => String(v || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '').replace(/\.$/, '');
  // a tela só precisa de três estados: esperando o DNS, emitindo o certificado, no ar
  function normal(r) {
    const v = r.ownership_verification || {}, ssl = (r.ssl && r.ssl.status) || '';
    const est = r.status !== 'active' ? 'dns' : ssl === 'active' ? 'ok' : 'ssl';
    const erros = [].concat(r.verification_errors || [], (r.ssl && r.ssl.validation_errors || []).map(x => x.message)).filter(Boolean);
    return { ok: true, id: r.id, est, txt_nome: v.name || '', txt_valor: v.value || '', erro: est === 'ok' ? '' : String(erros[0] || '').slice(0, 200) };
  }
  async function criar(empresa, h) {
    const host = limpo(h);
    if (!DOMINIO_RE.test(host)) return { ok: false, erro: 'Isso não é um domínio. Use algo como lp.suamarca.com.br, com o ponto e a terminação.' };
    if (RESERVADOS.test(host)) return { ok: false, erro: 'Esse domínio é do próprio sistema e não pode ser cadastrado.' };
    if (!ligada()) return { ok: false, erro: 'A hospedagem no TMX ainda não está ligada.' };
    const d = dono(host);
    if (d && d.empresa !== empresa) return { ok: false, erro: 'Esse domínio já está cadastrado em outra conta. Se ele é seu, fale com o suporte.' };
    const c = cfg();
    let r;
    try { r = await cf('POST', '/zones/' + c.zona + '/custom_hostnames', { hostname: host, ssl: { method: 'http', type: 'dv', settings: { min_tls_version: '1.2' } } }); }
    catch (e) {
      if (!/duplicate|already exists/i.test(e.message)) return { ok: false, erro: 'A Cloudflare recusou esse domínio: ' + e.message };
      const l = await cf('GET', '/zones/' + c.zona + '/custom_hostnames?hostname=' + encodeURIComponent(host));
      r = (l || [])[0];
      if (!r) return { ok: false, erro: 'A Cloudflare recusou esse domínio: ' + e.message };
    }
    platPrep('INSERT INTO dominios_hospedados(host, empresa, cf_id, criado) VALUES(?,?,?,?) ON CONFLICT(host) DO UPDATE SET cf_id=excluded.cf_id').run(host, empresa, r.id, Date.now());
    return Object.assign(normal(r), { host, alvo: c.alvo });
  }
  async function status(empresa, h) {
    const host = limpo(h);
    if (!eDele(empresa, host)) return { ok: false, erro: 'Domínio não encontrado.' };
    return normal(await cf('GET', '/zones/' + cfg().zona + '/custom_hostnames/' + dono(host).cf_id));
  }
  async function apagar(empresa, h) {
    const host = limpo(h);
    if (!eDele(empresa, host)) return { ok: true };   // já não existe aqui
    try { await cf('DELETE', '/zones/' + cfg().zona + '/custom_hostnames/' + dono(host).cf_id); }
    catch (e) { if (e.status !== 404) throw e; }
    await admin('DELETE', 'pasta', 'p=' + encodeURIComponent(host + '/'));
    platPrep('DELETE FROM dominios_hospedados WHERE host=?').run(host);
    return { ok: true };
  }
  const chaveOk = c => /^[A-Za-z0-9._\/-]+$/.test(c) && !c.includes('..') && !c.startsWith('/');
  async function gravar(empresa, d) {
    const host = limpo(d.host), chave = String(d.chave || '');
    if (!eDele(empresa, host)) return { ok: false, erro: 'Domínio não encontrado.' };
    // _tmx.json e _icone são escritos só pelos comandos próprios deles
    if (!chaveOk(chave) || chave.startsWith('_')) return { ok: false, erro: 'Endereço de arquivo inválido.' };
    await admin('PUT', 'objeto', 'k=' + encodeURIComponent(host + '/' + chave), Buffer.from(String(d.b64 || ''), 'base64'),
      { 'Content-Type': String(d.tipo || 'application/octet-stream').slice(0, 100), 'X-TMX-Cache': d.longo ? 'public, max-age=31536000, immutable' : 'no-store' });
    return { ok: true };
  }
  async function config(empresa, d) {
    const host = limpo(d.host);
    if (!eDele(empresa, host)) return { ok: false, erro: 'Domínio não encontrado.' };
    const c = d.cfg || {};
    // a origem e o prefixo saem daqui: o motor não escolhe pra onde o domínio dele repassa
    const final = { origem: cfg().origem, base: empresa === 'tmx' ? '' : '/e/' + empresa, testes: c.testes || {}, head: String(c.head || ''), corpo: String(c.corpo || ''), icone: !!c.icone };
    await admin('PUT', 'objeto', 'k=' + encodeURIComponent(host + '/_tmx.json'), JSON.stringify(final), { 'Content-Type': 'application/json' });
    return { ok: true };
  }
  async function icone(empresa, d) {
    const host = limpo(d.host);
    if (!eDele(empresa, host)) return { ok: false, erro: 'Domínio não encontrado.' };
    await admin('PUT', 'objeto', 'k=' + encodeURIComponent(host + '/_icone'), Buffer.from(String(d.b64 || ''), 'base64'), { 'Content-Type': String(d.tipo || 'image/png').slice(0, 60) });
    return { ok: true };
  }
  async function apagarPagina(empresa, d) {
    const host = limpo(d.host), sub = String(d.slug || '');
    if (!eDele(empresa, host)) return { ok: false, erro: 'Domínio não encontrado.' };
    if (!/^[a-z0-9-]+$/.test(sub)) return { ok: false, erro: 'Página inválida.' };
    await admin('DELETE', 'pasta', 'p=' + encodeURIComponent(host + '/' + sub + '/'));
    return { ok: true };
  }

  // o que a empresa pode pedir; quem é a empresa vem do canal, nunca do pedido
  function atender(empresa, cmd, d) {
    if (cmd === 'hosp-info') return { ok: true, ligada: ligada(), alvo: cfg().alvo };
    if (cmd === 'hosp-criar') return criar(empresa, d.host);
    if (cmd === 'hosp-status') return status(empresa, d.host);
    if (cmd === 'hosp-apagar') return apagar(empresa, d.host);
    if (cmd === 'hosp-gravar') return gravar(empresa, d);
    if (cmd === 'hosp-config') return config(empresa, d);
    if (cmd === 'hosp-icone') return icone(empresa, d);
    if (cmd === 'hosp-apagar-pagina') return apagarPagina(empresa, d);
    return { ok: false, erro: 'Pedido desconhecido.' };
  }
  return { atender, instalar, ligada };
};
