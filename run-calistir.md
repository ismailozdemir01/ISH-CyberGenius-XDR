# OZHEX-CyberGenius-XDR — Çalıştırma Kılavuzu

## 1. Windows / tek PowerShell

Repository'yi klonladıktan sonra:

```powershell
cd OZHEX-CyberGenius-XDR
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

## 2. Tek process mimarisi

```text
PowerShell
   │
   └── python main.py
          ├── FastAPI API
          ├── OZHEX-CyberGenius-XDR Dashboard
          ├── SQLite
          ├── Microsoft Graph Security
          ├── Microsoft Defender for Endpoint
          └── Microsoft Translator
```

Browser yalnızca HTTP client olarak çalışır. Ayrı frontend server zorunlu değildir.

## 3. Uvicorn

```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Geliştirme:

```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

`--reload` production için kullanılmamalıdır.

## 4. İlk kontrol

```powershell
Invoke-WebRequest http://127.0.0.1:8000/health | Select-Object -ExpandProperty Content
```

Health yanıtındaki `version`, `graph_configured` ve `translator_configured` alanlarını kontrol edin.

## 5. Test

```powershell
.\.venv\Scripts\Activate.ps1
python -m compileall -q app tests
pytest -q
```

CI Python 3.11, 3.12 ve 3.13 üzerinde çalışır.

## 6. Güvenli varsayılan

İlk kurulumda localhost kullanın:

```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

İşletim sistemi firewall'ını kapatmayın. Uygulamayı doğrudan public Internet'e bağlamayın.

## 7. Durdurma

```text
Ctrl+C
```

## 8. Sorun giderme

| Belirti | Kontrol |
|---|---|
| `python` bulunamadı | Python 3.11+ PATH/launcher |
| `No module named app` | Proje kökünden çalıştırın |
| `/` açılmıyor | Server traceback |
| Port 8000 dolu | Başka port kullanın |
| `graph_configured=false` | `.env` Microsoft credentials |
| `translator_configured=false` | `TRANSLATOR_KEY` |
| 401 | API key |
| 403 | Microsoft permission/admin consent |
| Isolation başarısız | Defender response permission/policy |
