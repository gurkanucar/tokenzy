# Tokenzy — Nihai Plan (v0.1, Go) — rev.3

Tek executable, SQLite (WAL), gömülü HTMX admin paneli. Confezy ile aynı iskelet: Go 1.22+ `net/http`, `modernc.org/sqlite`, `html/template`, `//go:embed`, session cookie (UI), `X-App-Key` (API), argon2 (admin şifresi), readDB(8) + writeDB(1) pattern'i. Dış bağımlılık: `modernc.org/sqlite` + `golang.org/x/crypto` (+ `google/uuid`).

İki modül:
- **Token**: JSON payload taşıyan, tek/çok/sınırlı kullanımlık, süreli, iptal edilebilir opak token'lar (~244 bit, çift UUID).
- **OTP**: `type` + `identifier` bağlamına bağlı, kısa numerik kod (6-8 hane, ayarlanabilir). Şifre sıfırlama, e-posta/telefon doğrulama vb.

İkisi ayrı tablo, ayrı endpoint, ayrı güvenlik modeli — çünkü entropi profilleri taban tabana zıt (bkz §1/K5).

---

## 1. Kesinleşen kararlar

**K1 — Token'da tek format.** machine/human ayrımı YOK. Kısa kod ihtiyacını artık OTP modülü karşılıyor.

**K2 — Token = iki random UUID yan yana.**

```go
t := "tkn_" + strings.ReplaceAll(uuid.NewString()+uuid.NewString(), "-", "")
// tkn_ + 64 hex karakter, ~244 bit rastgelelik
```

Uzay taranamaz → token tarafında deneme sayacı/rate limit gerekmez. UNIQUE kısıt bedava, yine de durur.

**K3 — Plaintext saklama (token VE otp), hash YOK.**
Kazanımlar: yönetim ucundan yeniden gösterme (token/QR), OTP'de **resend** (var olan kodu tekrar dönebilme — hash'le imkansız olurdu), düz lookup. Pazarlıksız telafiler: log katmanında token/kod/identifier maskeleme, listelerde tam değer yok, DB dosyası + yedekleri sır deposu muamelesi, cleanup düzenli işler.

**K4 — maxUses=1 token consume'da otomatik ölür.** Atomik UPDATE `used_count`'u artırır → durum `exhausted` → ikinci istek `invalid_token`. Ayrı revoke çağrısı gerekmez. `exhausted` (doğal ölüm) ile `revoked` (elle iptal) panelde ayrı görünür. **Aynı ilke OTP'de:** başarılı validate `consumed_at`'ı set eder → OTP o an ölür; ya da TTL dolar → yine ölür. İkisi de otomatiktir.

**K5 — OTP düşük entropilidir, savunma modeli farklıdır.**
6 haneli kod = 1 milyonluk uzay; token'ın aksine brute-force **gerçekçi** bir tehdittir. Bu yüzden OTP'de token'da bilerek koymadığımız şey zorunludur: **`max_attempts` (deneme sayacı)**. Her yanlış deneme sayacı artırır; tavana ulaşan OTP ölür (`locked`). Bu olmadan OTP modülü yayına çıkmaz. Entropi token'da savunmanın kendisiydi; OTP'de savunma deneme tavanıdır.

**K6 — OTP kimliği üçlüdür: (type, identifier, code).**
Doğrulama üç alanın da eşleşmesini ister. `type` çağıranın belirlediği serbest bir bağlam etiketidir (`password_reset`, `email_verify`...), `identifier` da sisteme opak bir string'dir (e-posta, telefon, TC no — sistem umursamaz, yorumlamaz). Bir (env, type, identifier) üçlüsü için aynı anda **en fazla bir aktif OTP** bulunur; generate tekrar çağrılırsa var olan aktif kod dönülür (resend semantiği, bkz §6).

---

## 2. Veri Modeli

```text
Project
└── Environment (prod otomatik, dev/staging eklenebilir)
    ├── Tokens
    ├── OTPs
    ├── API Keys   (consume / write / admin)
    └── Webhooks   (milestone 9)
```

Hesaplanan durumlar (DB'de saklanmaz):

```text
Token: revoked → expired → exhausted (used_count >= max_uses) → active
OTP:   revoked → consumed (consumed_at) → expired → locked (attempt_count >= max_attempts) → active
```

---

## 3. SQLite Şeması

confezy'den aynen: `users, sessions, projects, environments, api_keys` (scope CHECK: `('consume','write','admin')`; **API key'ler hash'li kalır** — plaintext kararı token/otp'ye özgü, key'in yeniden gösterilme ihtiyacı yok).

```sql
CREATE TABLE tokens (
  id             TEXT PRIMARY KEY,            -- "tok_" + 16 byte hex
  environment_id INTEGER NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
  token          TEXT NOT NULL UNIQUE,        -- PLAINTEXT: tkn_ + 64 hex
  token_prefix   TEXT NOT NULL,               -- ilk 12 karakter, listeler için
  payload_json   TEXT NOT NULL,               -- opak JSON, max 16 KB
  max_uses       INTEGER,                     -- NULL = sınırsız
  used_count     INTEGER NOT NULL DEFAULT 0,
  expires_at     INTEGER NOT NULL,
  revoked_at     INTEGER,
  created_at     INTEGER NOT NULL,
  last_used_at   INTEGER
);

CREATE INDEX idx_tokens_env_created ON tokens(environment_id, created_at DESC);
CREATE INDEX idx_tokens_expires     ON tokens(expires_at);          -- cleanup

CREATE TABLE otps (
  id             TEXT PRIMARY KEY,            -- "otp_" + 16 byte hex
  environment_id INTEGER NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
  type           TEXT NOT NULL,               -- "password_reset" (^[a-z0-9_]{1,64}$)
  identifier     TEXT NOT NULL,               -- e-posta/telefon/TC... opak string, ≤256
  code           TEXT NOT NULL,               -- PLAINTEXT numerik, 4-10 hane
  attempt_count  INTEGER NOT NULL DEFAULT 0,
  max_attempts   INTEGER NOT NULL DEFAULT 5,
  expires_at     INTEGER NOT NULL,
  consumed_at    INTEGER,
  revoked_at     INTEGER,
  created_at     INTEGER NOT NULL
);

-- KRİTİK indeks: generate'teki aktif-kayıt araması ve validate'in tamamı bu yoldan gider
CREATE INDEX idx_otps_lookup      ON otps(environment_id, type, identifier);
CREATE INDEX idx_otps_expires     ON otps(expires_at);              -- cleanup
CREATE INDEX idx_otps_env_created ON otps(environment_id, created_at DESC);  -- panel listesi
```

Notlar:
- `code` üzerinde UNIQUE **yok ve olmamalı** — 6 haneli kodlar farklı identifier'larda çakışır, bu normaldir. Benzersizlik alanı (env, type, identifier) üçlüsünün *aktif* kaydıdır ve bu, kod içinde transaction ile sağlanır (§6) — partial unique index kullanılmaz çünkü `expires_at > now` koşulu indekse konulamaz, süresi dolmuş ama henüz temizlenmemiş satırlar yeni üretimi bloke ederdi.
- Webhook tabloları (m9 migration'ı) rev.2 ile aynı.

---

## 4. Token Üretimi ve Consume (rev.2'den değişmedi)

```http
POST /v1/tokens        (write)   { payload, maxUses, ttlSeconds }
POST /v1/consume       (consume) { token }
```

- Üretim kuralları: payload ≤ 16 KB geçerli JSON; ttl zorunlu, çift tavan (`TOKENZY_MAX_TTL` default 90 gün + hard-coded 10 yıl); maxUses null veya ≥ 1.
- Consume tek atomik UPDATE (koşul + etki + RETURNING), etkilenen satır 0 ise tek tip `invalid_token`. Eşzamanlı isteklerde yalnızca biri kazanır.
- Yönetim: `GET/POST/DELETE /v1/manage/tokens...` — liste metadata, tekil inceleme payload + tam token (admin scope), inceleme asla tüketmez, revoke id ile.

(Detaylar rev.2 ile aynı; SQL ve cevap formatları değişmedi.)

---

## 5. OTP Üretimi + Resend

```http
POST /v1/otp
X-App-Key: tk_write_prod_xxx
```

```json
{
  "type": "password_reset",
  "identifier": "user@example.com",
  "length": 6,
  "ttlSeconds": 300,
  "maxAttempts": 5
}
```

Girdi kuralları:
- `type`: zorunlu, `^[a-z0-9_]{1,64}$`.
- `identifier`: zorunlu, ≤ 256 karakter, sisteme opak (e-posta mı telefon mu TC mi — umursanmaz, trim dışında dokunulmaz).
- `length`: opsiyonel, 4-10, default 6. Kod `crypto/rand` ile üretilir, baştaki sıfırlar korunur (kod her zaman string'dir: `"048291"`).
- `ttlSeconds`: zorunlu, > 0, tavan `TOKENZY_OTP_MAX_TTL` (default 1 saat).
- `maxAttempts`: opsiyonel, 1-20, default 5.

**Akış (tek transaction, writeDB — resend semantiği burada):**

```text
1. Aktif kayıt ara: (env, type, identifier) VE consumed_at IS NULL
   VE revoked_at IS NULL VE expires_at > now VE attempt_count < max_attempts
2. VARSA  → aynı kaydı dön (kod dahil), reused: true
           → "tekrar gönder" butonu bu sayede bedava: çağıran aynı kodu
             tekrar SMS/mail atar, kullanıcı iki farklı kodla şaşırmaz
3. YOKSA  → yeni kod üret, INSERT, reused: false
           (eski ölü satırlar kalır, cleanup süpürür)
```

writeDB tek connection olduğu için bu transaction doğal serialize olur — aynı identifier'a eşzamanlı iki generate isteği yarışamaz, ikisi de aynı kodu alır.

Cevap:

```json
{
  "id": "otp_9f2e...",
  "type": "password_reset",
  "identifier": "user@example.com",
  "code": "482913",
  "expiresAt": "2026-08-16T15:05:00Z",
  "maxAttempts": 5,
  "reused": false
}
```

Not: `reused: true` dönüldüğünde `expiresAt` orijinal üretimin süresidir — resend TTL'i uzatmaz. Bu bilinçli: aksi halde sürekli resend ile kod sonsuza dek yaşatılabilirdi. Çağıran taraf "süre çok azaldıysa yenisini üret" isterse önce id ile revoke edip tekrar generate çağırır (ya da v0.2'de `forceNew: true` parametresi eklenir).

---

## 6. OTP Validate — üç alan birden

```http
POST /v1/otp/validate
X-App-Key: tk_consume_prod_xxx
```

```json
{
  "type": "password_reset",
  "identifier": "user@example.com",
  "code": "482913"
}
```

Üç alan da eşleşmek zorundadır — kod doğru ama type yanlışsa geçmez (password_reset kodu email_verify'da kullanılamaz).

**Akış (tek transaction, writeDB):**

```sql
-- Adım 1: atomik tüket (K4: başarılı validate = otomatik expire)
UPDATE otps
SET consumed_at = ?
WHERE environment_id = ? AND type = ? AND identifier = ? AND code = ?
  AND consumed_at IS NULL
  AND revoked_at IS NULL
  AND expires_at > ?
  AND attempt_count < max_attempts
RETURNING id;

-- Adım 2 (yalnızca adım 1 → 0 satır ise): yanlış denemeyi say
UPDATE otps
SET attempt_count = attempt_count + 1
WHERE environment_id = ? AND type = ? AND identifier = ?
  AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > ?;
```

- Adım 1 → 1 satır: kod doğruydu, OTP **o an öldü** (consumed). Cevap:

```json
{ "valid": true, "type": "password_reset", "identifier": "user@example.com" }
```

- Adım 1 → 0 satır: sebep ne olursa olsun (kod yanlış / süresi dolmuş / zaten kullanılmış / locked / hiç yok) dışarıya **tek tip cevap** — doğru identifier'ı yoklayan birine "kod var ama yanlış" ile "hiç kod yok" ayrımı bilgi sızdırır:

```json
{ "valid": false, "error": "invalid_code" }
```

- Adım 2'deki sayaç artışı `max_attempts`'a ulaşınca OTP `locked` olur ve doğru kod bile artık geçmez (adım 1'in koşulu engeller). 6 haneli düşük entropinin tek gerçek savunması budur (K5).
- İki adım aynı transaction'dadır; eşzamanlı iki doğru-kod isteğinden yalnızca biri `valid: true` alır (adım 1 atomiktir).

Yönetim uçları:

```http
GET    /v1/manage/otps              ?status=active|consumed|expired|locked|revoked&type=&identifier=&limit&cursor
GET    /v1/manage/otps/{id}         (kod dahil — admin scope; inceleme tüketmez)
POST   /v1/manage/otps/{id}/revoke
DELETE /v1/manage/otps/{id}
```

Liste cevabında `code` YOK (id, type, identifier, status, attemptCount/maxAttempts, expiresAt, createdAt); tam kod yalnız tekil incelemede.

---

## 7. Scope Matrisi

```text
consume → POST /v1/consume, POST /v1/otp/validate
write   → consume + POST /v1/tokens + POST /v1/otp
admin   → write + /v1/manage/* (tokens ve otps)
```

Mobil/istemci tarafına yalnızca `consume` key gömülür. OTP üretimi her zaman güvenilir backend'den yapılır — kodu SMS/mail ile gönderen zaten o backend'dir.

---

## 8. TTL Temizliği (cleanup job)

İki bağımsız savunma (her iki tabloda da):
1. Consume/validate sorguları her zaman `expires_at > now` kontrol eder → job gecikse bile süresi dolmuş token/OTP kullanılamaz.
2. Background job (goroutine + `time.Ticker`, 10 dk, batch LIMIT 1000/tur, writeDB):

```text
tokens: expired > 7 gün  → sil ; exhausted/revoked > 30 gün → sil
otps  : ölü satırlar (consumed/expired/locked/revoked) > 24 saat → sil
```

OTP retention'ı kısa tutulur (`TOKENZY_RETENTION_OTP=24h`) — plaintext kod + kişisel veri olabilecek identifier (e-posta/telefon/TC) taşıdığı için burada temizlik yer tasarrufu değil, **veri hijyenidir**. Diğerleri: `TOKENZY_RETENTION_EXPIRED=168h`, `TOKENZY_RETENTION_CONSUMED=720h`.

---

## 9. Webhook (milestone 9)

Event'ler: `token.created`, `token.consumed`, `token.exhausted`, `token.revoked` + `otp.consumed`, `otp.locked` (opsiyonel, aynı altyapı). Webhook payload'ında token'ın kendisi ve OTP kodu **asla bulunmaz**; identifier bulunur ama URL'si dış dünyaya bakan webhook'larda buna dikkat çağıranın sorumluluğudur (README'ye yazılır). HMAC imza, retry (hemen → 30 sn → 2 dk → 10 dk), delivery log — rev.2 ile aynı.

---

## 10. Admin UI (HTMX — confezy'den kopyalanır)

Aynı prensipler: embed HTMX + el yazması CSS, dark/light custom properties + localStorage toggle, `/ui/*` session korumalı.

```text
/ui/login
/ui/projects
/ui/p/{slug}                        env listesi
/ui/p/{slug}/{env}/tokens           liste + status filtresi + üretim + detay/revoke
/ui/p/{slug}/{env}/otps             liste + status/type/identifier filtresi + üretim + detay/revoke
/ui/p/{slug}/{env}/keys             key üret/revoke
/ui/p/{slug}/{env}/webhooks         (m9)
```

OTP ekranı HTMX etkileşimleri:
- Liste: status rozetleri (active/consumed/expired/locked/revoked), attempt göstergesi (`2/5`), type ve identifier'a göre arama (`hx-get` + input `hx-trigger="keyup changed delay:300ms"`).
- Üretim formu: type, identifier, length (6/8 hızlı seçim + serbest), ttl, maxAttempts → `hx-post`, cevap modalında kod gösterilir + kopyala; `reused: true` ise "Var olan aktif kod döndü" uyarısı.
- Detay: "Kodu göster" butonu (token'daki gibi tıklanmadan DOM'a gelmez).
- Revoke: `hx-post` + `hx-confirm`.

---

## 11. Proje Yapısı

```text
tokenzy/
├── go.mod
├── main.go
├── internal/
│   ├── db/                    # readDB(8)+writeDB(1), PRAGMA DSN, migration runner
│   │   └── migrations/
│   │       ├── 001_init.sql   # tokens + otps + indeksler
│   │       └── 002_webhooks.sql
│   ├── model/
│   ├── auth/                  # apikey.go (consume/write/admin), session.go
│   ├── token/                 # generate.go, consume.go, status.go
│   ├── otp/
│   │   ├── generate.go        # crypto/rand numerik kod + resend transaction'ı
│   │   ├── validate.go        # atomik tüket + attempt sayacı (tek tx)
│   │   └── status.go
│   ├── cleanup/job.go         # iki tabloyu da süpürür
│   ├── webhook/dispatch.go    # (m9)
│   ├── api/                   # tokens.go, consume.go, otp.go, manage.go
│   └── ui/
├── templates/                 # //go:embed
└── static/                    # htmx.min.js, app.css
```

---

## 12. Uygulama Sırası

1. **İskelet transferi** (confezy: db/auth/session/ui-base/migrations).
2. **Project/env/admin** — `prod` otomatik.
3. **API key** — `tk_{scope}_{env}_{rand}`, hash'li.
4. **Token üretimi** — çift UUID, plaintext, maskeleme.
5. **Atomik consume** — paralel 50 istek testi (tam 1 başarılı) + "ikinci deneme invalid" testi.
6. **OTP modülü** — generate + resend + validate. Test şartları:
   - Aynı (type, identifier)'a ikinci generate → aynı kod, `reused: true`, TTL uzamıyor
   - Yanlış kod × maxAttempts → locked; sonrasında DOĞRU kod da `invalid_code`
   - Doğru kod → `valid: true`; hemen ardından aynı kod → `invalid_code` (auto-expire kanıtı)
   - Paralel iki doğru-kod isteği → tam 1 `valid: true`
   - type uyuşmazlığı → `invalid_code` (kod doğru olsa bile)
7. **Cleanup job** — iki tablo, OTP retention 24h.
8. **Admin paneli** — tokens + otps ekranları, key yönetimi.
9. **Webhook** — token + otp event'leri, HMAC, retry, delivery UI.
10. **v0.2** — `Idempotency-Key`, `forceNew` (OTP), import/export, metrikler (geçersiz validate oranı, locked oranı = brute-force sinyali), opsiyonel rate limit.

---

## 13. Checklist (release öncesi)

- [ ] Token: çift UUID ~244 bit, UNIQUE; deneme sayacı bilinçli olarak YOK
- [ ] OTP: crypto/rand numerik, baştaki sıfırlar korunuyor (string); `max_attempts` savunması AKTİF ve testli — bu olmadan yayın YOK
- [ ] Validate üç alan birden eşleşiyor (type + identifier + code); tüm hata halleri tek tip `invalid_code`
- [ ] Başarılı validate OTP'yi anında öldürüyor (consumed_at); TTL dolumu bağımsız ikinci ölüm yolu
- [ ] Resend: aktif kayıt varsa aynı kod dönüyor, TTL uzamıyor
- [ ] (env, type, identifier) başına tek aktif OTP — transaction ile, partial index ile DEĞİL
- [ ] `code` kolonunda UNIQUE yok (bilinçli)
- [ ] İndeksler: otps(env,type,identifier), otps(expires_at), otps(env,created_at); tokens(env,created_at), tokens(expires_at)
- [ ] Plaintext telafileri: log maskeleme (token, kod VE identifier), listede tam değer yok, DB+yedek sır muamelesi
- [ ] OTP retention 24h — identifier kişisel veri olabilir, hijyen şart
- [ ] Webhook/log — hiçbir yan kanalda tam token/kod gezmiyor
- [ ] consume key istemcide, write/admin sadece backend'de — README'de büyük harflerle
- [ ] Milestone 5 ve 6'daki eşzamanlılık testlerinin tamamı geçiyor