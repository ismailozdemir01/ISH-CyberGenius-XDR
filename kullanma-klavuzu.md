# ISH-CyberGenius-XDR — A'dan Z'ye Kullanım Kılavuzu

## 1. Sistem nedir?

ISH-CyberGenius-XDR; Microsoft Graph Security, Microsoft Defender for Endpoint ve Advanced Hunting verilerini tek bir çalışma alanında birleştiren savunma amaçlı XDR uygulamasıdır.

Temel akış:

`Telemetry → Detection → Correlation → Incident → Investigation → Evidence → Risk → Timeline → Response → Report`

Uygulama tek FastAPI sunucusu ve tek browser istemcisi olarak çalışır. Ayrı bir frontend sunucusu veya ikinci PowerShell penceresi zorunlu değildir.

## 2. Mimari

- **FastAPI:** API + browser dashboard.
- **SQLite:** incident, telemetry, investigation, evidence, correlation ve response kayıtları.
- **Microsoft Graph Security:** incident okuma/yazma, comment ve Advanced Hunting.
- **Microsoft Defender for Endpoint:** cihaz envanteri ve response işlemleri.
- **Dashboard:** `/` adresinden aynı FastAPI process'i tarafından servis edilir.
- **Swagger:** `/docs`.

## 3. Gereksinimler

- Windows 10/11 veya Linux/macOS.
- Python 3.11+.
- Git.
- Microsoft tenant üzerinde gerekli Entra application registration ve API permissions.
- Gerçek Microsoft entegrasyonu için `TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET`.

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
REQUEST_TIMEOUT=30
```

Secret'ı GitHub'a, README'ye veya kaynak koduna koymayın. `.env` dosyasını commit etmeyin.

## 6. API izinleri

Uygulamanın kullandığı işlemler için Microsoft tarafında ilgili application permissions ve admin consent gereklidir. Özellikle incident yazma, Advanced Hunting ve Defender response işlemlerinde tenant'ın izin modelini Microsoft dokümantasyonuna göre yapılandırın.

Uygulama Microsoft credentials yoksa yerel modda başlatılabilir; ancak Microsoft'a bağlı incident, hunting ve response endpointleri credentials olmadan çalışmaz.

## 7. Tek PowerShell ile çalıştırma

Normal kullanımda iki terminal gerekmez. Server ve browser client aynı FastAPI uygulamasındadır.

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

### 8.1 Incident listesi

Dashboard açıldığında incident listesi yüklenir. `Refresh incidents` Microsoft tarafındaki mevcut incident verisini yeniler.

### 8.2 Incident seçimi

Bir incident seçildiğinde:

- severity
- status
- classification
- determination
- evidence
- investigation history
- response history
- correlation findings
- risk bilgisi

aynı çalışma alanında görüntülenir.

### 8.3 Advanced Hunting

KQL alanına Microsoft Advanced Hunting sorgusu girin. Örnek:

```kusto
DeviceProcessEvents
| limit 20
```

Incident seçiliyken `Run KQL` kullanıldığında sonuç investigation kaydı olarak saklanır ve incident evidence'ına bağlanır.

### 8.4 Behavioral Correlation

Telemetry daha önce sisteme alınmışsa correlation motoru ilgili olayları zaman ve cihaz bağlamında ilişkilendirir.

Örnek davranışlar:

- encoded PowerShell
- PowerShell process activity
- network activity
- RDP activity
- aynı cihazdaki kısa zaman aralıklı olay zincirleri

### 8.5 Evidence

Hunting, correlation ve response çıktıları incident ile ilişkilendirilerek kalıcı evidence olarak saklanır.

### 8.6 Machine inventory

`Machines` düğmesi Defender for Endpoint cihaz envanterini getirir.

### 8.7 Isolation

Bir cihazı izole etmek gerçek Defender response işlemidir.

1. Machine ID girin.
2. Comment girin.
3. Isolation type seçin.
4. `Isolate` düğmesine basın.
5. Confirmation ekranını onaylayın.

Bu işlem test/mock değildir; bağlı Defender tenantında gerçek containment işlemi yapar.

### 8.8 Unisolate

Aynı şekilde gerçek Defender release-from-isolation işlemini başlatır. Yalnızca yetkili operasyonlarda kullanın.

### 8.9 Report

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

## 10. Yerel telemetry

Defender Advanced Hunting biçimine benzeyen JSON olayları `/api/telemetry` ile içeri alınabilir. Bu özellik entegrasyon ve detection/correlation geliştirme içindir; Microsoft tenantından veri geliyormuş gibi sahte response üretmez.

## 11. Risk analizi

Risk motoru incident/correlation verilerinden açıklanabilir faktörler çıkarır. Skor tek başına karar mekanizması değildir; analyst tarafından evidence ve timeline ile birlikte değerlendirilmelidir.

## 12. Attack timeline

Timeline; incident, evidence, investigation, correlation ve response kayıtlarını kronolojik çalışma görünümüne dönüştürür.

## 13. Veritabanı

Varsayılan SQLite dosyası:

```text
./data/xdr.db
```

Üretim ortamında düzenli yedekleme ve erişim kontrolü uygulanmalıdır.

## 14. Testler

```powershell
pytest -q
```

CI aynı testleri desteklenen Python sürümleri üzerinde çalıştırır.

## 15. Sorun giderme

### `/` açılmıyor

- Virtual environment aktif mi?
- `pip install -e ".[test]"` çalıştı mı?
- `python main.py` process'i çalışıyor mu?
- Port 8000 başka process tarafından kullanılıyor mu?

### `graph_configured=false`

`.env` içinde üç değer kontrol edin:

```text
TENANT_ID
CLIENT_ID
CLIENT_SECRET
```

Server'ı credentials değişikliğinden sonra yeniden başlatın.

### Microsoft API 401/403

Token audience, application permission, admin consent ve tenant policy yapılandırmasını kontrol edin.

### Isolation 403

Defender response için gerekli application permission ve ilgili Defender yetkilendirmelerini kontrol edin.

## 16. Güvenlik

- `.env` commit edilmemelidir.
- Client secret kaynak kodunda tutulmamalıdır.
- Dashboard internet üzerinde authentication olmadan yayınlanmamalıdır.
- Production deployment reverse proxy, TLS, authentication ve network access control ile korunmalıdır.
- Response endpointleri gerçek sistemlere etki ettiğinden RBAC ve operasyon onayı uygulanmalıdır.

## 17. Production yaklaşımı

Tek process küçük/orta ölçekli kullanım için yeterlidir. Kurumsal kullanımda FastAPI uygulaması reverse proxy arkasında, merkezi secret management, TLS, identity-aware access, audit log shipping ve yedekleme ile çalıştırılmalıdır.

## 18. Kapatma

PowerShell penceresinde:

```text
Ctrl+C
```

## 19. Önerilen operasyon akışı

```text
1. Incident'i aç
2. Evidence'i incele
3. KQL ile hunting yap
4. Correlation çalıştır
5. Entity ve timeline'ı incele
6. Risk faktörlerini doğrula
7. Gerekliyse containment uygula
8. Response sonucunu doğrula
9. Incident'i güncelle
10. Report oluştur
```

Bu akış analyst kararını desteklemek içindir; response işlemleri açıkça yetkilendirilmiş operasyonlar olmalıdır.
