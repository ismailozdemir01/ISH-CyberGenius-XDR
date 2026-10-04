# OZHEX-CyberGenius-XDR — A'dan Z'ye Kullanım Kılavuzu

## 1. Sistem nedir?

OZHEX-CyberGenius-XDR; Microsoft Graph Security, Microsoft Defender for Endpoint ve Advanced Hunting verilerini tek bir çalışma alanında birleştiren savunma amaçlı XDR uygulamasıdır.

Temel akış:

`Telemetry → Detection → Correlation → Incident → Investigation → Evidence → Risk → Timeline → Response → Report`

Uygulama tek FastAPI sunucusu ve tek browser istemcisi olarak çalışır. Ayrı bir frontend sunucusu veya ikinci PowerShell penceresi zorunlu değildir.

## 2. Mimari

- **FastAPI:** API + browser dashboard.
- **SQLite:** incident, telemetry, investigation, evidence, correlation ve response kayıtları.
- **Microsoft Graph Security:** incident okuma/yazma, comment ve Advanced Hunting.
- **Microsoft Defender for Endpoint:** cihaz envanteri ve response işlemleri.
- **Microsoft Translator:** otomatik dil algılama ve çeviri.
- **Browser Web Speech API:** analyst speech-to-text.
- **Dashboard:** `/` adresinden aynı FastAPI process'i tarafından servis edilir.
- **Swagger:** `/docs`.

## 3. Gereksinimler

- Windows 10/11 veya Linux/macOS.
- Python 3.11+.
- Git.
- Microsoft tenant üzerinde gerekli Entra application registration ve API permissions.
- Gerçek Microsoft entegrasyonu için `TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET`.
- Çeviri için `TRANSLATOR_KEY` ve gerektiğinde `TRANSLATOR_REGION`.

## 4. Kurulum

```powershell
git clone https://github.com/ismailozdemir01/ISH-CyberGenius-XDR.git
cd ISH-CyberGenius-XDR
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[test]"
Copy-Item .env.example .env
```

> GitHub repository adı değiştirildiğinde yukarıdaki clone URL'si yeni OZHEX repository URL'siyle kullanılmalıdır.

Linux/macOS:

```bash
git clone https://github.com/ismailozdemir01/ISH-CyberGenius-XDR.git
cd ISH-CyberGenius-XDR
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e '.[test]'
cp .env.example .env
```

## 5. Microsoft kimlik bilgileri

`.env` içine değerleri koyun:

```env
TENANT_ID=<Microsoft Entra tenant ID>
CLIENT_ID=<App registration client ID>
CLIENT_SECRET=<client secret>
DATABASE_PATH=./data/xdr.db
GRAPH_BASE_URL=https://graph.microsoft.com/v1.0
DEFENDER_API_BASE_URL=https://api.security.microsoft.com
TRANSLATOR_ENDPOINT=https://api.cognitive.microsofttranslator.com
TRANSLATOR_KEY=<translator key>
TRANSLATOR_REGION=<translator region when required>
REQUEST_TIMEOUT=30
API_KEY=<random API key>
```

Secret'ı GitHub'a, README'ye veya kaynak koduna koymayın. `.env` dosyasını commit etmeyin.

## 6. API izinleri

Uygulamanın kullandığı işlemler için Microsoft tarafında ilgili application permissions ve admin consent gereklidir. Özellikle incident yazma, Advanced Hunting ve Defender response işlemlerinde tenant'ın izin modelini Microsoft dokümantasyonuna göre yapılandırın.

Uygulama Microsoft credentials yoksa yerel modda başlatılabilir; ancak Microsoft'a bağlı incident, hunting, translation ve response endpointleri ilgili credentials olmadan çalışmaz.

## 7. Çalıştırma

```powershell
.\.venv\Scripts\Activate.ps1
python main.py
```

Ardından tarayıcıda:

`http://127.0.0.1:8000/`

Swagger:

`http://127.0.0.1:8000/docs`

Health:

`http://127.0.0.1:8000/health`

## 8. Dashboard kullanımı

Dashboard incident, evidence, hunting, correlation, risk, entity graph, timeline ve response iş akışlarını tek arayüzde sunar.

### Voice & Translation

1. Tarayıcı mikrofon iznini verin.
2. Speech language seçin veya browser language kullanın.
3. `Start speech` ile konuşun.
4. Oluşan metni kontrol edin.
5. Hedef dili seçin.
6. `Detect and translate` ile Microsoft Translator'a gönderin.

Speech recognition browser tarafında gerçekleşir; çeviri istendiğinde yalnızca ortaya çıkan metin backend'e gönderilir.

### Advanced Hunting

KQL alanına Microsoft Advanced Hunting sorgusu girin. Örnek:

```kusto
DeviceProcessEvents
| limit 20
```

### Behavioral Correlation

Telemetry sisteme alındığında correlation motoru olayları zaman ve cihaz bağlamında ilişkilendirir.

### Machine isolation

Bir cihazı izole etmek gerçek Defender response işlemidir. Machine ID, comment ve isolation type girilip açık onay verildiğinde gerçek Microsoft Defender API çağrısı yapılır.

### Report

Incident report bağlantısı incident, evidence, investigation ve response geçmişini Markdown formatında üretir.

## 9. API kullanımı

Temel endpointler:

```text
GET  /health
GET  /api/incidents
GET  /api/incidents/{incident_id}
PATCH /api/incidents/{incident_id}
POST /api/incidents/{incident_id}/comments
POST /api/incidents/{incident_id}/evidence
GET  /api/incidents/{incident_id}/report
POST /api/hunting
POST /api/translate
GET  /api/machines
POST /api/response/isolate
POST /api/response/unisolate
GET  /api/response/actions
POST /api/telemetry
GET  /api/telemetry
POST /api/correlate
GET  /api/correlations
GET  /api/timeline/{incident_id}
GET  /api/analytics/overview
GET  /api/detections/rules
```

Tam request/response şemaları `/docs` üzerinde görülebilir.

## 10. Testler

```powershell
python -m compileall -q app tests
pytest -q
```

CI Python 3.11, 3.12 ve 3.13 üzerinde aynı test kapısını çalıştırır.

## 11. Güvenlik

- `.env` commit edilmemelidir.
- Client secret kaynak kodunda tutulmamalıdır.
- Dashboard internet üzerinde authentication olmadan yayınlanmamalıdır.
- Production deployment reverse proxy, TLS, authentication ve network access control ile korunmalıdır.
- Response endpointleri gerçek sistemlere etki ettiğinden RBAC ve operasyon onayı uygulanmalıdır.

## 12. Production yaklaşımı

Kurumsal kullanımda FastAPI reverse proxy arkasında, merkezi secret management, TLS, identity-aware access, audit log shipping ve yedekleme ile çalıştırılmalıdır.

## 13. Operasyon akışı

```text
Incident → Evidence → Hunting → Correlation → Entity/Timeline → Risk → Containment → Verification → Report
```

Bu akış analyst kararını desteklemek içindir; response işlemleri açıkça yetkilendirilmiş operasyonlar olmalıdır.
