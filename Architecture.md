# LogLineOS v8 — Arquitetura prevista (explicação “Readme de linhas”)

## 0) Posição da v8 (o que muda da v7)

* **Core mais puro**: v8 **não** acopla Folding/Diamante; mantém tudo como **extensões neutras** e desligáveis por flag.
* **Ciclo do span ampliado** (neutro): adiciona **Trajectory Linker** + **Trajectory Quality Score** + **Quality Meter** (apenas “candidate”), todos em `.lll`.
* **Plugabilidade forte**: **Apps** (Lab/Powerfarm/Minicontratos/Padaria/Produtora) rodam por **APIs públicas**; nada invade o TCB.
* **DevEx e Observabilidade**: CLI de simulação, métricas canônicas e OpenAPI gerado do `.lll`.

---

## 1) Mapa de componentes (alto nível)

```
┌──────────────────────────────────────────── LogLineOS v8 ───────────────────────────────────────────┐
│ A) Toolchain (.lll)                                 B) Runtime/TCB (Rust mínimo)                    │
│  - Grammar/Parser/Types/IR                           - Loader/Sandbox .lllb                          │
│  - Backends: EVAL | AOT-WASM                         - Hostcalls ABI v1 + Kernels (ledger, ed25519)  │
│  - CLI: loglinec / loglinerun                        - OIDC/JWT (LLST), JWKS, quotas enforcers       │
│                                                                                                      │
│ C) Data Plane (.lll)                                D) API/Comms (gateway fino)                      │
│  - Routers/Validators (ingest)                       - HTTP REST + NDJSON + WS                       │
│  - Span Ledger v1 (append-only)                      - Webhooks in/out                               │
│  - **Trajectory Linker** (genérico)                  - OpenAPI gerado de schemas .lll                │
│  - **Trajectory Quality Score** (genérico)           - Rate-limit/quotas/capabilities                │
│  - **Quality Meter v1.1** (filtra candidato)                                                          │
│                                                                                                      │
│ E) Identity & Security                               F) Observability & Ops                          │
│  - Google OIDC (google-only)                          - Métricas padrões (gateway, ledger, traj, qlt)│
│  - LLID + LLST (JWT curta, rotação)                   - CLI simulação (dry-run)                      │
│  - Policies/Capabilities                              - Auditoria por receipts + exports assinados   │
└──────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Fronteira LLL × Rust**

* **Rust (TCB mínimo)**: loader/sandbox, hostcalls, kernels quentes, OIDC/JWT/keys.
* **.LLL**: roteamento, validação, trajectory linker/quality, policies, quotas, schemas, métricas.

---

## 2) Fluxos canônicos

### 2.1 Ingestão → Ledger → Trajetória → Qualidade (neutro)

```
Client → Gateway (Auth+Quota) → Router → Validators
        → ledger.append → (deriva) Trajectory Linker (open/edge/close)
        → Trajectory Quality Score → Quality Meter v1.1 (emite: diamond_candidate)
        → Métricas + Auditoria
```

### 2.2 Execução de pacotes `.lllb`

```
.lll → loglinec → .lllb assinado → Loader/TCB
     → EVAL (exec direta) ou AOT-WASM (rtlib_wasm → hostcalls)
     → Policies/Capabilities sempre em vigor
```

### 2.3 Identidade (Google-only)

```
OIDC code+PKCE → valida id_token → map sub→LLID → emitir LLST (curto)
Gateway verifica LLST + capabilities → autoriza hostcalls sensíveis
```

---

## 3) Dados e eventos (contratos neutros)

### 3.1 Span canônico

Campos mínimos: `id, tenant, who, did, this, when (RFC3339), confirmed_by[], status`.

### 3.2 Derivados neutros (v8)

```json
// trajectory_edge
{ "type":"trajectory_edge","trajectory_id":"t_...","position":3,"src_span_id":"s_...","this":"...", "tenant":"...", "ts":"..." }

// trajectory_closed
{ "type":"trajectory_closed","trajectory_id":"t_...","reason":"timeout|rule","tenant":"...","ts":"..." }

// trajectory_quality
{ "type":"trajectory_quality","trajectory_id":"t_...","score":78,
  "components":{"mass":31,"persistence":24,"verification":23},"tenant":"...","ts":"..." }

// diamond_candidate  (core não “declara diamante”; só candidato neutro)
{ "type":"diamond_candidate","trajectory_id":"t_...","score":78,"threshold":76,"tenant":"...","ts":"..." }
```

---

## 4) Interfaces e contratos (essenciais)

### 4.1 Manifests `.lllb`

* `abi:"v1"`, `caps_allow:[]`, `hash`, `signing_key_id`, `resources:{routers,validators,policies,schemas}`.

### 4.2 Hostcalls ABI v1 (resumo)

* `ledger.append(bytes) -> receipt_id`
* `kv.get/set`, `env.get`, `ws.send`, `http.request` *(sempre gated por capability)*
* `crypto.verify` (puro)

### 4.3 Gateway

* Auth: `Authorization: Bearer <LLST>`
* Conteúdo: `application/json`, `application/x-ndjson`
* Schemas: gerados do `.lll` (OpenAPI export)

---

## 5) Configuração por política (multi-tenant)

### 5.1 Trajectory Linker

```lll
policy trajectory_linker {
  key_fields: ["this"]
  window: "24h"
  close_timeout: "6h"
  exceptions: ["this:heartbeat-*"]
}
```

### 5.2 Quality Meter

```lll
policy quality_meter {
  weights: { mass: 0.4, persistence: 0.3, verification: 0.3 }
  percentile_target: "p96"     # ≈ 2–4% candidatos
  min_score: 60
}
```

### 5.3 Feature flags por tenant

* `features.trajectory = true|false`
* `features.diamond = true|false`

---

## 6) Segurança (v8)

* **Deny-by-default** em capabilities; LLST curta com rotação `kid`; CORS restrito.
* **Replay/CSRF** mitigados; quotas/timeout; PII redaction.
* **Auditoria forte**: tudo com receipts; exports assinados.
* **TCB mínimo**: qualquer lógica de app reside fora (apps/plug-ins via API).

---

## 7) Observabilidade e SLOs

**Métricas canônicas**

* Gateway: latência, 2xx/4xx/5xx, 401/403, 429.
* Ledger: append P50/P95/P99, backlog, receipts/s.
* Trajetória: ativas, fechadas/h, tempo médio de fecho.
* Qualidade: `trajectory_quality/s`, `diamond_candidate/s`, `%qualificados`.

**SLOs (MVP v8)**

* `append P95 ≤ 15ms` (single-node SSD)
* `auth P95 ≤ 200ms` (JWKS cache)
* `gateway uptime ≥ 99.9%`

**CLI de simulação**

* `ll quality simulate --spans input.ndjson --policy quality/policy.yaml` → escreve `span_simulation_result.logline`.

---

## 8) Extensibilidade e isolamento de apps

* **Apps (Lab/Powerfarm/Minicontratos/Padaria/Produtora)**:

  * vivem **fora do core**, falam com **APIs públicas** e **tokens LLST** de service-account;
  * plug-ins em `.lll` **do lado do app**, jamais dentro do TCB.

* **Core nunca promove “Diamante”**: só emite `diamond_candidate`.

  * Padrões (Learning/Crisis/Innovation), Folding/FTO, ΔS/rewards → **apps**.

---

## 9) Topologias de implantação

* **Dev (Mac mini)**: tudo em um host; storage local.
* **Prod inicial**: 1× Gateway, 1× Runtime/TCB, 1× Storage; escala horizontal no Gateway; kernels como workers.

---

## 10) Roadmap v8 (degustação)

* **M0 – Liga o motor puro**: Parser/IR, Loader/TCB, Hostcalls, Ledger v1, Gateway+Auth, CLI.
* **M1 – Ciclo neutro completo**: Trajectory Linker/Close, Trajectory Quality Score, Quality Meter v1.1, Observabilidade, OpenAPI.
* **M2 – Plugabilidade e hardening**: Webhooks, WS estável, flags multi-tenant, dry-run CLI, snapshots/exportos.

---

## 11) Critérios de aceite (v8)

* Apenas `.lllb/.wasm` **assinados** executam; capabilities por política.
* Ingestão segura → Ledger → Trajetória (edge/close) com receipts.
* **`trajectory_quality`** emitido determinístico; **`diamond_candidate`** só pelo filtro (percentil/limiar).
* Métricas visíveis; exports assinados; runbooks publicados.

---

## 12) Por que a v8 sustenta o “universo cíclico”

* **Base única** para qualquer app (padaria, produtora, etc.): mesmo contrato/ledger/regras/observabilidade.
* **Span como ativo**: ciclo neutro gera **qualidade e estrutura** que **Powerfarm/Lab** podem consumir — sem tocar o core.
* **Narrativa como força**: o core mede e sinaliza; os apps **contam a história** (Folding, Diamante, ΔS) e monetizam.

---



 **PARTE II** com informações extras e operacionais, mantendo o v8 “core puro” e abrindo caminho suave para apps (Lab/Powerfarm/Minicontratos).

# LogLineOS v8 — PARTE II (Detalhamento e Operação)

## 13) Modelo de dados (físico & lógico)

### 13.1 Layout físico sugerido (single-node)

```
/var/logline/
  ledger/               # spans append-only (segmentos rotativos)
    segments/000001.ndjson
    segments/000002.ndjson
    index/              # índices leves (this→offsets, tenant→offsets)
  receipts/             # recibos de operações sensíveis
    2025-10-05.ndjson
  exports/              # dumps assinados (snapshot/pull)
  cfg/                  # políticas por tenant (yaml/.lll)
  jwks/                 # chaves ativas (kid), histórico rotacionado
```

### 13.2 Span canônico (wire)

```json
{
  "id":"s_01FJ...", "tenant":"t_voulezvous",
  "who":"dan", "did":"sale.post", "this":"order:12345",
  "when":"2025-10-05T22:18:07Z",
  "confirmed_by":["pos://register-7"], "status":"confirmed",
  "data":{ "gross": 19.90, "items": 3 }
}
```

### 13.3 Índices leves (on-disk)

* `this.idx`: `this → [segment_id, offset]`
* `tenant.idx`: `tenant → [segment_id, offset]`
* (opcional M2) `who.idx`, `did.idx`

> Racional: prioriza **reconstrução rápida de trajetória** e **consultas multi-tenant** sem um banco externo.

---

## 14) Determinismo & reprodutibilidade

### 14.1 Regras de determinismo (EVAL × AOT)

* Proibido acessar **tempo/sorte/aleatório** sem vir por `env.get`/hostcall (valor injetável).
* Proíbe I/O direta fora de hostcalls.
* **Shadow-run** obrigatório para mudanças de IR/backends.

### 14.2 Semente e replay

* **`replay_token`** opcional no manifesto `.lllb` para execuções reprodutíveis.
* CLI:

```bash
loglinerun --replay <token> my_pipeline.lllb
```

---

## 15) Backpressure & capacidade

### 15.1 Gateway

* **Token bucket** por `tenant` e por `role`.
* NDJSON com **flush por N objetos ou T ms** (configurável).

### 15.2 Router/Data-plane

* Fila de derivação separada (trajectory/quality), com **limite absoluto** e **queda graciosa**:

  * `on_overload: "shed_derived" | "slow_ingest" | "reject_429"`

### 15.3 Guardrails de derivados

```lll
policy derived_events_perf {
  max_per_minute: 2000
  overflow_action: "shed_derived"
}
```

---

## 16) Segurança (hardening prático)

* **Sandbox** (TCB): denylist syscalls; cgroups/rlimits (mem/cpu/wall); sem `execve`.
* **LLST** (JWT curto, 15 min): rotação `kid` sobreposta, clock skew ±60s.
* **API**: CORS restrito; TLS obrigatório; `problem+json` para erros.
* **Receipts**: toda operação de side-effect emite recibo com `jti`, `kid`, `sig`.

**Exemplo de receipt (resumo)**

```json
{ "op":"ledger.append","span_id":"s_...","tenant":"t_...",
  "jti":"r_09...", "kid":"2025-10A", "sig":"base64...","ts":"2025-10-05T22:19Z" }
```

---

## 17) Multi-tenant: isolamento & governança

* **Isolamento lógico** em todo caminho (authz, quotas, métricas, armazenamento).
* **Políticas carregadas por tenant** (hot-reload): `cfg/tenants/<tenant>.yaml`
* **Feature Flags**:

  * `features.trajectory`: ativa linker/close/quality (derivados).
  * `features.diamond`: ativa **apenas** o **filtro** (candidato).
  * `features.cluster` (M2 opcional): piloto `span_cluster_*`.

---

## 18) Quality Meter — percentis online

Para sustentar **2–4%** candidatos sem varrer tudo:

* Estimador de quantil **streaming** (p.ex., P²/bi-heap/TDigest-like).
* Exposição em métricas: `quality.pXX.current` por tenant.
* **Dry-run** (CLI/REST) para simular impactos antes de ligar em produção.

**CLI**

```bash
ll quality simulate --spans input.ndjson --policy quality/policy.yaml \
  --out spans/span_simulation_result.logline
```

---

## 19) OpenAPI a partir de `.lll`

* Schemas `.lll` → **gerador** exporta:

  * `POST /ingest` (JSON/NDJSON)
  * `GET /ledger/stream` (cursor)
  * `GET /metrics/public` (contadores)
  * `POST /quality/dryrun` (M2)
* Publicar bundle (`openapi.yaml`) com exemplos de corpo/erros.

---

## 20) Observabilidade — convenções

**Nomes (prefixos)**

* `gateway.*`: `latency_ms`, `requests_total`, `status_2xx/4xx/5xx`
* `ledger.*`: `append_latency_ms`, `receipts_total`
* `trajectory.*`: `active`, `closed_total`, `close_latency_ms`
* `quality.*`: `score_count`, `p50/p95/p99`, `candidates_total`

**Alarmes rápidos**

* `gateway.status_5xx_rate > 2%` por 5 min
* `auth.jwt_invalid_rate > 1%`
* `quality.candidates_total` fora do **envelope** (ex.: 0.5–10%)

---

## 21) Runbooks (resumo)

* **Auth incidente**: trocar `kid`, invalidar LLST, endurecer CORS, elevar quotas mínimas.
* **Ledger atraso**: checar I/O, reduzir `flush_interval`, habilitar `shed_derived`.
* **Derived storm**: baixar `max_per_minute` ou desligar `features.trajectory` no tenant afetado.
* **Restore**: aplicar snapshot + reprocessar índices (determinístico).

---

## 22) Testes & QA

* **E2E**: Ingest→Ledger→Trajectory→Quality→Metrics.
* **Shadow-run**: corpus fixo; divergência **= 0**; relatar diffs.
* **Fuzz/Security**: manifests corrompidos, JWT inválidos, WS flood, NDJSON truncado.
* **CI gates**: latência p95 target, erro < 0.5%, determinismo.

---

## 23) Versão e compatibilidade

* **`abi:"v1"`** no manifesto; mudanças **breaking** → `v2`.
* Deprecações anunciadas via header `X-LogLine-Deprecation` + changelog.

---

## 24) Billing & limites (ganchos)

* **Ganchos** por tenant:

  * `ingest_spans_count`, `derived_spans_count`, `exports_gb`, `ws_minutes`.
* **Policies de cobrança** ficam **fora do core** (app/serviço), mas contadores são canônicos.

---

## 25) Exemplos práticos (neutros)

### 25.1 Validator canônico (reforçado)

```lll
validator canonical_contract_v1 {
  require field "id"
  require field "who"
  require field "did"
  require field "this"
  require field "when" as "rfc3339"
  allow field "confirmed_by" as "array"
  require field "tenant"
  on_fail "reject"
}
```

### 25.2 Trajectory Linker (essência)

```lll
pipeline trajectory_linker {
  when features.trajectory
  policy_ref: "trajectory_linker"
  derive "trajectory_edge" on link_open_or_continue()
  derive "trajectory_closed" on close_by_timeout_or_rule()
}
```

### 25.3 Quality Score & Meter

```lll
validator trajectory_quality_score {
  input: "trajectory_edge|trajectory_closed"
  emit:  "trajectory_quality" with components(mass,persistence,verification)
}
validator quality_meter_v1_1 {
  input: "trajectory_quality"
  when percentile(score) >= policy.quality_meter.percentile_target
  and  score >= policy.quality_meter.min_score
  emit: "diamond_candidate"
}
```

---

## 26) Deploy — topologias de referência

**Dev (Mac mini)**

* Systemd/launchd; storage local; dashboards locais.

**Prod inicial**

* 1× Gateway + 1× Runtime/TCB + 1× Storage (SSD).
* Backup diário (exports assinados) + snapshot semanal.

---

## 27) Caminho v8 → v8.1 (riscos & alavancas)

* **Risco**: picos de derivados.
  **Alavanca**: `shed_derived` + percentil streaming + flags por tenant.

* **Risco**: latência de append > alvo em bursts.
  **Alavanca**: batching ajustável + fsync por intervalo + coluna leve.

* **Risco**: confusão entre “candidato” e “diamante”.
  **Alavanca**: nomenclatura neutra; promoção real **só em apps**.

* **Risco**: lock-in de nomes (`trajectory` vs `cluster`).
  **Alavanca**: `features.cluster` (piloto) e alias gradativo.

---

## 28) Checklist de aceite (pronto para audit)

* [ ] Apenas `.lllb/.wasm` assinados executam (ABI v1, caps_allow).
* [ ] OIDC/LLST (curto, rotação) + RBAC→Capabilities por tenant.
* [ ] Ingestão segura → Ledger (receipts) → Trajectory (edge/close).
* [ ] `trajectory_quality` determinístico; `diamond_candidate` pelo filtro.
* [ ] Métricas/alarms ativos; exports assinados; runbooks testados.
* [ ] CLI de simulação funcionando; OpenAPI gerado e publicado.
* [ ] Flags por tenant e guardrails de derivados operacionais.

---





