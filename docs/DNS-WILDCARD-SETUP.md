# Setup do DNS Wildcard (*.centralaxcend.com)

Pra cada cliente do Axcend ter seu próprio subdomínio (`clienteX.centralaxcend.com`),
você precisa configurar **DNS wildcard** apontando todos os subdomínios pro Railway.

Esse é o **Bloqueador 7/7** do roadmap SaaS.

---

## 📋 Pré-requisitos

- [ ] Domínio `axcend.com` registrado (Registro.br, GoDaddy, Cloudflare, etc.)
- [ ] Acesso ao painel DNS do registrador
- [ ] Conta Railway com o projeto Axcend rodando
- [ ] Plano Railway Hobby ou superior (custom domains exigem isso)

---

## Passo 1 — Adiciona o domínio wildcard no Railway

1. Vai em https://railway.com/dashboard
2. Abre o projeto **scalelab-web** (production)
3. Settings → **Networking** → **Custom Domain**
4. Clica em **+ Add Domain**
5. Cola exatamente: `*.centralaxcend.com`
6. Salva
7. Railway vai te dar uma instrução tipo:
   ```
   CNAME *.centralaxcend.com → kbb1d4hp.up.railway.app
   ```
   **Anote esse target** (vai ser único pro seu projeto).

8. **Adiciona TAMBÉM** o domínio raiz: `axcend.com` (sem wildcard)
9. E `www.centralaxcend.com`

---

## Passo 2 — Configura no painel DNS do domínio

Vai no painel onde você registrou o `axcend.com`.

### Se for **Cloudflare** (recomendado):

1. Login → Selecione `axcend.com`
2. Menu **DNS** → **Records**
3. Adiciona 3 entradas:

| Type | Name | Content | Proxy | TTL |
|---|---|---|---|---|
| CNAME | `*` | `kbb1d4hp.up.railway.app` | 🔘 DNS only | Auto |
| CNAME | `@` | `kbb1d4hp.up.railway.app` | 🔘 DNS only | Auto |
| CNAME | `www` | `kbb1d4hp.up.railway.app` | 🔘 DNS only | Auto |

> ⚠️ **IMPORTANTE:** desative o Proxy (nuvem laranja deve ficar **CINZA**). O Railway gerencia SSL próprio. Com proxy Cloudflare ativo, vai dar erro de loop SSL.

### Se for **Registro.br**:

1. Login → Meus Domínios → `axcend.com` → DNS
2. Adiciona:
   - `*` IN CNAME `kbb1d4hp.up.railway.app.`
   - `@` IN CNAME `kbb1d4hp.up.railway.app.`
   - `www` IN CNAME `kbb1d4hp.up.railway.app.`

### Se for **GoDaddy / Hostinger / outro**:

Mesma estrutura — 3 CNAMEs apontando pro target do Railway.

---

## Passo 3 — Espera propagação (5min a 24h)

DNS pode levar de 5 minutos até 24 horas pra propagar globalmente.

Pra testar antes:
```bash
# No terminal:
dig +short qualquer-coisa.centralaxcend.com
# Deve retornar o IP do Railway

# Ou via web:
# https://dnschecker.org/#CNAME/qualquer-coisa.centralaxcend.com
```

Se aparecer o IP do Railway, tá funcionando! ✅

---

## Passo 4 — Verificação SSL

O Railway emite certificado SSL automático via Let's Encrypt pra wildcard.
Isso pode levar **5-15 min depois que o DNS propagou**.

Pra testar:
```
https://teste.centralaxcend.com
```

- Se carregar com cadeado verde 🔒 → SSL ok!
- Se der erro de certificado → aguarda mais 15 min e tenta de novo.

---

## Passo 5 — Atualiza HOSTS_INTERNO no server.js (opcional)

Se você quiser que o seu painel ADMIN do Axcend continue acessível em `app.centralaxcend.com` (não conflitando com o `*.centralaxcend.com`), garante que está no `HOSTS_INTERNO`:

```javascript
// server.js linha ~21
const HOSTS_INTERNO = new Set([
  'app.centralaxcend.com',
  'centralaxcend.com',
  'axcend.com',         // ← raiz do SaaS é interno (landing)
  'www.centralaxcend.com',     // ← www também
  'app.centralaxcend.com',     // ← se quiser que app.centralaxcend.com seja master
  'localhost:3001',
  'localhost:3000',
  '127.0.0.1:3001'
]);
```

E que `SAAS_ROOT_DOMAIN` está certo (já está):

```javascript
const SAAS_ROOT_DOMAIN = 'axcend.com';
```

---

## Passo 6 — Testa o fluxo completo

1. Acessa `https://axcend.com` → deve mostrar a Landing
2. Clica em "Começar grátis" → vai pra `/signup`
3. Cria conta com slug `meuteste`
4. Após signup, é redirecionado pra `https://meuteste.centralaxcend.com`
5. SSL deve funcionar
6. Painel deve carregar logado como o admin criado
7. Configurações → Meu Plano → deve mostrar plano Trial

---

## Subdomínios reservados

Por segurança, o Axcend bloqueia esses subdomínios pra ninguém usar como slug:

```
app, www, api, admin, painel, master, mail, cname,
static, cdn, assets, help, docs, blog, status,
axcend, central, centralaxcend, root, sys, system,
support, suporte, contato, ajuda, pricing, precos, planos,
signup, login, logout, register, registro, cadastro, home, index
```

Definido em `server.js` → `SLUGS_RESERVADOS_SIGNUP`.

---

## Troubleshooting

### "Site doesn't exist" no subdomínio
- DNS ainda não propagou. Aguarda mais tempo.
- Verifica no https://dnschecker.org se o CNAME apareceu.

### "SSL error" / cadeado vermelho
- Railway ainda não emitiu o certificado wildcard.
- Aguarda 15min e tenta de novo.
- Se persistir, vai em Railway → Settings → Custom Domains → ver se status é "Connected" ou "Verifying".

### Subdomínio carrega mas mostra painel ERRADO (do tenant errado)
- Verifica se o tenant foi criado: API GET `/api/saas/signup/check-slug?slug=meuteste`
- Se `disponivel: true`, o tenant não existe (algo deu errado no signup)
- Verifica logs Railway: `railway logs --deployment`

### Cliente faz login mas vê dados de outro cliente
- BUG sério de tenant isolation. Reporta imediato.
- PR3+PR4 deveriam garantir isolamento. Verifica que `getItemTenant` está filtrando corretamente.

---

## Custos

| Item | Custo aproximado |
|---|---|
| Domínio `axcend.com` | R$ 40/ano (Registro.br) |
| Cloudflare (DNS) | Grátis |
| Railway Hobby | $5/mês (necessário pra custom domain) |
| SSL Wildcard | Grátis (Let's Encrypt via Railway) |

**Total: ~$5/mês + R$ 40/ano**

---

## ✅ Resultado final

Após esse setup, qualquer cliente que se cadastrar via `/signup`:

1. Escolhe slug (ex: `meuteste`)
2. Sistema cria tenant + admin no banco
3. Cliente é redirecionado pra `https://meuteste.centralaxcend.com`
4. Login automático funciona
5. Painel isolado mostra só dados do cliente
6. Outros clientes (`outroteste.centralaxcend.com`) não veem nada desse

Esse é o coração de um SaaS multi-tenant funcionando. 🎉
