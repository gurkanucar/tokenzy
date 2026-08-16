# Tokenzy — Nihai Plan (v0.1, Go) — rev.2

Tek executable, SQLite (WAL), gömülü HTMX admin paneli. Confezy ile aynı iskelet: Go 1.22+ `net/http`, `modernc.org/sqlite`, `html/template`, `//go:embed`, session cookie (UI), `X-App-Key` (API), argon2 (admin şifresi), readDB(8) + writeDB(1) pattern'i. Dış bağımlılık: `modernc.org/sqlite` + `golang.org/x/crypto` (+ `google/uuid`).

Amaç: JSON payload taşıyan, tek/çok/sınırlı kullanımlık, süreli, iptal edilebilir opak token'lar. Payload sisteme opaktır — doğrulanmaz, yorumlanmaz, olduğu gibi geri verilir.

---

## 1. Kesinleşen kararlar (rev.2)

**K1 — Tek format.** machine/human ayrımı YOK, `format` kolonu YOK. Tüm token'lar aynı şekilde üretilir. Human-readable kısa kod ihtiyacı doğarsa ileride ayrı bir özellik olarak düşünülür; v0.1'in derdi değil.

**K2 — Token = iki random UUID yan yana.**

```go
t := "tkn_" + strings.ReplaceAll(uuid.NewString()+uuid.NewString(), "-", "")
// tkn_ + 64 hex karakter, toplam ~244 bit rastgelelik
```

~244 bit entropi ile uzay taranamaz → **deneme sayacı, cooldown, rate limit matematiksel olarak gerekmez** (istenirse operasyonel hijyen için sonra eklenir, v0.1'de yok). Benzersizlik astronomik güvencede ama DB'deki UNIQUE kısıt bedava, yine de durur.

**K3 — Plaintext saklama, hash YOK.**
Token DB'de düz metin saklanır. Kazanımlar: (a) yönetim ucundan token/QR **yeniden gösterilebilir** — panelden "kopyala/QR bas" mümkün; (b) lookup düz `WHERE token = ?` ile, ekstra hash adımı yok; (c) tek kolonla hem arama hem gösterme. Telafi yükümlülükleri (bunlar pazarlıksız):
- Token ve payload **log katmanında maskelenir** — hiçbir log satırında plaintext token geçmez.
- Listeleme ucunda token asla dönmez, sadece prefix; tam token yalnızca **tekil inceleme** ucundan ve **admin scope** ile görünür.
- DB dosyası ve yedekleri artık sır deposudur: dosya izinleri dar, yedeklere erişim kısıtlı.

**K4 — "Tek seferlikse validate edince otomatik revoke olur mu?" → Evet, fiilen.**
Mekanizma şöyle: `maxUses = 1` olan token ilk başarılı consume'da atomik UPDATE ile `used_count = 1` olur → durum anında `exhausted` hesaplanır → ikinci consume koşulu (`used_count < max_uses`) sağlayamaz, `invalid_token` alır. Yani ayrıca bir "revoke çağrısı" gerekmez, tüketme kendisi öldürür. Terminoloji ayrımı bilinçli:
- `exhausted` = kullanım hakkı bitti (doğal ölüm, consume'un sonucu)
- `revoked` = yönetici id ile elle iptal etti (müdahale, `revoked_at` set edilir)
İkisi de aynı sonucu verir (token artık geçmez) ama panelde ayrı görünür — "bu bilet kullanıldı mı yoksa biri mi iptal etti" sorusunun cevabı kaybolmaz. Kayıt silinmez, retention süresince durur (kim, ne zaman kullandı izi).

---

## 2. Veri Modeli

```text
Project
└── Environment (prod otomatik, dev/staging eklenebilir)
    ├── Tokens
    ├── API Keys   (consume / write / admin)
    └── Webhooks   (milestone 8)
```

Durum DB'de saklanmaz, hesaplanır (öncelik sırasıyla):

```text
revoked   : revoked_at != NULL
expired   : expires_at <= now
exhausted : max_uses != NULL && used_count >= max_uses
active    : gerisi
```

---

## 3. SQLite Şeması

confezy'deki `users, sessions, projects, environments, api_keys` tabloları aynen taşınır (api_keys scope CHECK'i `('consume','write','admin')`; API key'ler hash'li kalır — plaintext kararı token'lara özgüdür, API key'in yeniden gösterilme ihtiyacı yoktur).

```sql
CREATE TABLE tokens (
  id             TEXT PRIMARY KEY,            -- "tok_" + 16 byte hex
  environment_id INTEGER NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
  token          TEXT NOT NULL UNIQUE,        -- PLAINTEXT: tkn_ + 64 hex
  token_prefix   TEXT NOT NULL,               -- ilk 12 karakter, listelerde göstermek için
  payload_json   TEXT NOT NULL,               -- opak JSON, max 16 KB
  max_uses       INTEGER,                     -- NULL = sınırsız
  used_count     INTEGER NOT NULL DEFAULT 0,
  expires_at     INTEGER NOT NULL,            -- unix ts
  revoked_at     INTEGER,
  created_at     INTEGER NOT NULL,
  last_used_at   INTEGER
);

CREATE INDEX idx_tokens_env_created ON tokens(environment_id, created_at DESC);
CREATE INDEX idx_tokens_expires ON tokens(expires_at);   -- cleanup job için
```

Webhook tabloları (milestone 8 migration'ı): `webhooks (id, environment_id, url, secret, events, created_at, disabled_at)` ve `webhook_deliveries (id, webhook_id, event_id, event_type, payload, attempt, status_code, next_retry_at, delivered_at, created_at)` — confezy'deki yapıyla aynı.

---

## 4. Token Üretimi

```http
POST /v1/tokens
X-App-Key: tk_write_prod_xxx
```

```json
{
  "payload": { "userId": "usr_123", "action": "accept_invitation" },
  "maxUses": 1,
  "ttlSeconds": 900
}
```

Cevap:

```json
{
  "id": "tok_a1b2c3...",
  "token": "tkn_3f9a...(64 hex)",
  "expiresAt": "2026-08-16T15:30:00Z",
  "maxUses": 1
}
```

Girdi kuralları:
- `payload`: geçerli JSON, serialize hali ≤ 16 KB. Büyük veri için referans konur, verinin kendisi değil.
- `ttlSeconds`: zorunlu, > 0. Çift tavan: işletme tavanı env var (`TOKENZY_MAX_TTL`, default 90 gün) + mutlak akıl-sağlığı tavanı hard-coded (10 yıl) — taşma/geçmişte-expires_at hatasına karşı girişte red.
- `maxUses`: null (sınırsız) veya ≥ 1.

---

## 5. Consume — en kritik nokta

Token URL'de değil body'de taşınır (proxy/access log sızıntısı).

```http
POST /v1/consume
X-App-Key: tk_consume_prod_xxx
```

```json
{ "token": "tkn_3f9a..." }
```

Tek atomik adım (koşul + etki birlikte, writeDB üzerinden):

```sql
UPDATE tokens
SET used_count = used_count + 1, last_used_at = ?
WHERE token = ?
  AND environment_id = ?          -- key'in bağlı olduğu env
  AND revoked_at IS NULL
  AND expires_at > ?
  AND (max_uses IS NULL OR used_count < max_uses)
RETURNING payload_json, used_count, max_uses;
```

- Etkilenen satır = 1 → payload dönülür. `maxUses = 1` ise bu UPDATE token'ı aynı anda öldürür (K4): ayrı revoke adımı yoktur, tüketme = geçersizleştirme. Eşzamanlı iki istek gelirse yalnızca biri kazanır — "önce oku sonra işaretle" iki adımı ASLA yazılmaz.
- Etkilenen satır = 0 → sebep ne olursa olsun (yok / expired / exhausted / revoked) dışarıya **tek tip cevap**:

```json
{ "valid": false, "error": "invalid_token" }
```

Başarılı cevap:

```json
{
  "valid": true,
  "payload": { "userId": "usr_123", "action": "accept_invitation" },
  "usage": { "used": 1, "maximum": 1, "remaining": 0 }
}
```

(`maximum`/`remaining` sınırsız token'da `null`.)

---

## 6. Yönetim API'leri (admin key)

Çözümleme token ile, yönetim **id** ile çalışır — "token'ı bilmeden iptal edebilme" (cihaz kayboldu senaryosu) bu ayrımdan gelir.

```http
GET    /v1/manage/tokens              ?status=active|expired|exhausted|revoked&limit&cursor
GET    /v1/manage/tokens/{id}
POST   /v1/manage/tokens/{id}/revoke
DELETE /v1/manage/tokens/{id}
```

- **Listeleme metadata döner:** id, prefix, status, usedCount, maxUses, expiresAt, createdAt, lastUsedAt. Token ve payload listede YOK.
- **Tekil inceleme payload'ı VE tam token'ı döner** (plaintext kararının karşılığı burada tahsil edilir — QR yeniden basılabilir). Kritik kural: inceleme salt-okumadır, one-time token'ı **asla tüketmez**; tüketen tek yol `/v1/consume`'dur.
- Token'ı gösterebilen bu uç fiilen token üretme gücüne denktir → yalnızca `admin` scope, en sıkı korunan uç.
- Revoke: `revoked_at = now` — etkisi anlıktır çünkü her consume DB'ye bakar (stateful tasarım, bilinçli tercih).
- Scope matrisi:

```text
consume → sadece POST /v1/consume
write   → consume + POST /v1/tokens
admin   → write + /v1/manage/*
```

---

## 7. TTL Temizliği (cleanup job)

İki bağımsız savunma:
1. Consume sorgusu her zaman `expires_at > now` kontrol eder → job gecikse bile süresi dolmuş token kullanılamaz.
2. Background job (goroutine + `time.Ticker`, 10 dk):

```text
DELETE FROM tokens WHERE expires_at < now - 7 gün                        -- expired retention
DELETE FROM tokens WHERE (exhausted veya revoked) AND ilgili ts < now - 30 gün
Batch: LIMIT 1000/tur, writeDB üzerinden
```

Retention env var: `TOKENZY_RETENTION_EXPIRED=168h`, `TOKENZY_RETENTION_CONSUMED=720h`. Plaintext saklandığı için temizliğin düzenli işlemesi artık sadece yer tasarrufu değil, sır hijyenidir.

---

## 8. Webhook (milestone 8)

Event'ler: `token.created`, `token.consumed`, `token.exhausted`, `token.revoked`. (`token.expired` YOK — expiration bir an değil zaman koşuludur.)

- Webhook payload'ında **token'ın kendisi asla bulunmaz** — plaintext DB'de dursa bile ağa çıkan hiçbir yan kanalda token gezmez; id + prefix + metadata + (opsiyonel) token payload'ı gönderilir.
- Header: `X-Webhook-Id`, `X-Webhook-Signature: sha256=HMAC(secret, body)`.
- Retry: hemen → 30 sn → 2 dk → 10 dk; delivery kayıtları tutulur (operasyonel log).
- Gönderim: consume transaction'ı commit olduktan SONRA (in-memory channel + tek worker goroutine).

---

## 9. Admin UI (HTMX + html/template — confezy'den kopyalanır)

Aynı prensipler: embed HTMX + el yazması CSS, `:root`/`[data-theme=dark]` custom properties, localStorage tema toggle, `/ui/*` session korumalı, API'ler saf JSON kalır.

```text
/ui/login
/ui/projects
/ui/p/{slug}                       env listesi
/ui/p/{slug}/{env}/tokens          liste + status filtresi
/ui/p/{slug}/{env}/tokens/new      üretim formu (payload textarea + JSON validate, ttl, maxUses)
/ui/p/{slug}/{env}/keys            key üret/revoke
/ui/p/{slug}/{env}/webhooks        webhook CRUD + delivery listesi (m8)
```

HTMX etkileşimleri:
- Token listesi: filtre butonları `hx-get` ile tablo fragment'ını yeniler; cursor tabanlı "daha fazla yükle". Listede sadece prefix + status rozeti.
- Üretim: form `hx-post` → modal fragment, token gösterilir + kopyala butonu.
- Detay satırı: `hx-get` ile açılır; payload pretty-print + **"Token'ı göster" butonu** (ayrı `hx-get`, tıklanmadan token DOM'a hiç gelmez) + kopyala. İstenirse aynı yerde QR render (küçük bir inline JS QR üreteci embed edilebilir — dış bağımlılıksız, tek dosya; v0.1'de opsiyonel).
- Revoke: `hx-post` + `hx-confirm` → satır güncellenir, rozet "revoked".

---

## 10. Proje Yapısı

```text
tokenzy/
├── go.mod
├── main.go                    # CLI: serve, admin-create
├── internal/
│   ├── db/                    # confezy'den: readDB(8)+writeDB(1), PRAGMA DSN, migration runner
│   │   └── migrations/
│   │       ├── 001_init.sql
│   │       └── 002_webhooks.sql
│   ├── model/
│   ├── auth/                  # confezy'den: apikey.go (scope'lar değişir), session.go
│   ├── token/
│   │   ├── generate.go        # çift UUID birleştirme
│   │   ├── consume.go         # atomik UPDATE ... RETURNING
│   │   └── status.go          # hesaplanan durum
│   ├── cleanup/
│   │   └── job.go             # ticker + batch delete
│   ├── webhook/
│   │   └── dispatch.go        # channel + worker + retry (m8)
│   ├── api/
│   │   ├── tokens.go          # POST /v1/tokens
│   │   ├── consume.go         # POST /v1/consume
│   │   └── manage.go          # /v1/manage/*
│   └── ui/
├── templates/                 # //go:embed — base.html confezy'den
└── static/                    # htmx.min.js, app.css — confezy'den
```

Çalıştırma / build: confezy ile aynı (`admin-create`, `serve -port -db`; `CGO_ENABLED=0 go build`).

---

## 11. Uygulama Sırası

1. **İskelet transferi**: confezy'den db/auth/session/ui-base/migration runner, scope'lar `consume/write/admin`.
2. **Project/env/admin**: confezy'den aynen; `prod` otomatik.
3. **API key**: üretim/hash/lookup/scope middleware (`tk_{scope}_{env}_{rand}` — API key'ler hash'li kalır).
4. **Token üretimi**: POST /v1/tokens, çift UUID, girdi kuralları, plaintext kayıt + log maskeleme.
5. **Atomik consume**: UPDATE...RETURNING, tek tip hata. Eşzamanlılık testi ŞART: aynı `maxUses=1` token'a paralel 50 istek → tam 1 başarılı. Ek test: başarılı consume sonrası ikinci istek `invalid_token` (K4'ün kanıtı).
6. **Cleanup job**: ticker, batch delete, retention env vars.
7. **Admin paneli**: liste/filtre/üretim/detay ("Token'ı göster")/revoke + key yönetimi.
8. **Webhook**: 4 event, HMAC, retry, delivery UI.
9. **v0.2**: `Idempotency-Key`, import/export, metrikler (geçersiz consume oranı, one-time'da "ikinci deneme" oranı = kopya/replay sinyali), opsiyonel rate limit.

Milestone 5'in sonunda servis gerçek işini yapar; 7'nin sonunda günlük kullanılabilir.

---

## 12. Checklist (release öncesi)

- [ ] Token = tkn_ + iki UUID (64 hex, ~244 bit), crypto RNG; DB'de UNIQUE
- [ ] Yüksek entropi nedeniyle rate limit/deneme sayacı bilinçli olarak yok
- [ ] Token plaintext ama: loglarda maskeli, listede sadece prefix, tam hali yalnız admin-scope tekil incelemede
- [ ] Webhook/log/liste — hiçbir yan kanalda tam token gezmiyor
- [ ] DB dosyası + yedekleri sır deposu muamelesi görüyor (izinler, erişim)
- [ ] Payload ≤ 16 KB, geçerli JSON; "çözen herkes payload'ı görür" README'de
- [ ] TTL çift tavanlı, girişte reddediliyor
- [ ] Consume tek atomik UPDATE; paralel test + "ikinci deneme invalid" testi geçiyor
- [ ] maxUses=1 → consume otomatik öldürür (exhausted); revoke ise elle iptal (revoked) — panelde ayrı görünüyor
- [ ] Yönetici incelemesi tüketmiyor; revoke id ile ve anlık
- [ ] consume key mobilde, write/admin sadece backend'de — README'de büyük harflerle
- [ ] Cleanup gecikse bile expired token kullanılamıyor