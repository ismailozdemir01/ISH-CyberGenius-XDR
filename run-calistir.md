# ISH-CyberGenius-XDR — Çalıştırma Kılavuzu

## 1. En kısa yol — Windows / tek PowerShell

Repository'yi klonladıktan sonra:

```powershell
cd ISH-CyberGenius-XDR
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[test]"
Copy-Item .env.example .env
```

`.env` dosyasını doldurun, sonra:

```powershell
python main.py
```

Tarayıcı:

```text
http://127.0.0.1:8000/
```

Swagger:

```text
http://127.0.0.1:8000/docs
```

## 2. Server + client mimarisi

Bu projede ayrı bir frontend/client server çalıştırmak zorunda değilsiniz.

Tek process:

```text
PowerShell
   │
   └── python main.py
          │
          ├── FastAPI API
          ├── Browser Dashboard
          ├── SQLite
          ├── Microsoft Graph Security
          └── Microsoft Defender for Endpoint
```

Browser sadece HTTP client olarak çalışır. Dashboard dosyaları FastAPI tarafından servis edilir.

Dolayısıyla normal kullanımda **tek PowerShell yeterlidir**.

## 3. `main.py`

Repository kökünde `main.py` varsa aşağıdaki komutla doğrudan başlatılır:

```powershell
python main.py
```

Eğer geliştirme sırasında doğrudan Uvicorn kullanmak isterseniz:

```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Production benzeri yerel çalıştırma:

```powershell
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

`0.0.0.0` kullanımı uygulamayı ağ arayüzlerine açabileceği için güvenilir ağ ortamı dışında kullanılmamalıdır.

## 4. Otomatik kurulum/başlatma

Önerilen Windows başlangıç komutu:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\.venv\Scripts\Activate.ps1
python main.py
```

## 5. İlk çalıştırma kontrolü

Server başladıktan sonra:

```powershell
Invoke-WebRequest http://127.0.0.1:8000/health | Select-Object -ExpandProperty Content
```

Beklenen yapı:

```json
{
  "status": "ok",
  "graph_configured": true,
  "database": "./data/xdr.db",
  "version": "1.0.0"
}
```

`graph_configured: false` olması uygulamanın local olarak çalışabildiğini, fakat Microsoft credentials'ın yapılandırılmadığını gösterir.

## 6. `.env` yapılandırması

```env
TENANT_ID=<tenant-id>
CLIENT_ID=<client-id>
CLIENT_SECRET=<secret>
DATABASE_PATH=./data/xdr.db
GRAPH_BASE_URL=https://graph.microsoft.com/v1.0
DEFENDER_API_BASE_URL=https://api.security.microsoft.com
REQUEST_TIMEOUT=30
```

Secret değerlerini shell history, Git commit veya public loglara yazmayın.

## 7. İki PowerShell gerekli mi?

**Hayır.** Normal çalışma için:

```text
PowerShell #1 → python main.py
Browser     → http://127.0.0.1:8000/
```

yeterlidir.

İkinci PowerShell yalnızca geliştirme sırasında örneğin test çalıştırmak için kullanılabilir:

```powershell
pytest -q
```

Bu ikinci terminal bir client server değildir.

## 8. Port değiştirme

Örneğin 8080:

```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8080
```

Dashboard:

```text
http://127.0.0.1:8080/
```

## 9. Firewall / ağ erişimi

Yerel kullanım için `127.0.0.1` tercih edin.

Başka bir makinenin bağlanması gerekiyorsa kontrollü private network kullanın ve authentication/TLS olmadan uygulamayı internete açmayın.

## 10. Test

```powershell
.\.venv\Scripts\Activate.ps1
pytest -q
```

## 11. Durdurma

Server terminalinde:

```text
Ctrl+C
```

## 12. Temiz yeniden başlatma

```powershell
Ctrl+C
.\.venv\Scripts\Activate.ps1
python main.py
```

## 13. Veritabanını sıfırlama

Dikkat: bu işlem lokal incident/evidence/investigation/response geçmişini siler.

Server'ı durdurduktan sonra:

```powershell
Remove-Item .\data\xdr.db -ErrorAction SilentlyContinue
python main.py
```

Microsoft tenantındaki kayıtlar bu işlemle silinmez; yalnızca yerel SQLite cache/history temizlenir.

## 14. Production başlatma

Geliştirme sunucusundaki `--reload` production için kullanılmamalıdır.

Örnek:

```powershell
.\.venv\Scripts\Activate.ps1
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 2
```

Production ortamında ayrıca reverse proxy, TLS, authentication, secret management, backup ve merkezi audit logging uygulanmalıdır.

## 15. Çalışma sırası

```text
START
  ↓
Python environment
  ↓
.env yüklenir
  ↓
FastAPI başlar
  ↓
SQLite hazırlanır
  ↓
Browser dashboard açılır
  ↓
Microsoft Graph / Defender bağlantısı gerektiğinde kullanılır
  ↓
Incident → Hunting → Correlation → Evidence → Response
```

## 16. Hızlı hata tablosu

| Belirti | Kontrol |
|---|---|
| `python` bulunamadı | Python 3.11+ PATH/launcher |
| `No module named app` | Proje kökünden çalıştırın |
| `/` açılmıyor | Server terminalindeki traceback |
| Port 8000 dolu | Başka port kullanın |
| `graph_configured=false` | `.env` credentials |
| 401 | Credentials/token yapılandırması |
| 403 | Microsoft API permission/admin consent |
| Isolation başarısız | Defender response permission/policy |
| DB açılamıyor | `data/` klasörü ve filesystem permission |

## 17. Güvenli varsayılan

İlk kurulumda uygulamayı localhost'ta çalıştırın:

```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

İşletim sistemi firewall'ını kapatmayın. Uygulamayı doğrudan public Internet'e bağlamayın.
