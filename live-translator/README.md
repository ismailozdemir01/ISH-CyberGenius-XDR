# ISH-CyberGenius Live Translator

Windows-first live English speech-to-text and Turkish translation companion for online cybersecurity events.

## What is real

- Windows speaker audio is captured through a WASAPI loopback recorder.
- English speech is transcribed locally with `faster-whisper`.
- If Azure AI Translator credentials are configured, the English transcript is translated to Turkish through the official Translator REST API.
- If Azure credentials are absent/unavailable, the application falls back to a local cybersecurity terminology helper. That fallback is **not** a full machine translator.
- No audio recording file is written by this application.

## Privacy and event rules

Local Whisper processing keeps the audio used for speech recognition on the machine. Enabling Azure translation sends the recognized transcript text to Azure for translation; audio itself is not sent by this application. Check the event's recording/transcription terms before using persistent recording or redistribution. This application does not attempt to bypass event controls.

## Windows prerequisites

- Windows 10/11
- Python 3.11+
- Working Windows speaker/audio output
- Internet access only if Azure translation is enabled
- A local Whisper model; the first model load may download model files depending on the `faster-whisper`/CTranslate2 cache state

## Install

Recommended:

```powershell
cd live-translator
Set-ExecutionPolicy -Scope Process Bypass
.\run.ps1
```

The launcher creates `.venv`, installs dependencies, creates `.env` from `.env.example` when missing, and starts the application.

## Full Turkish translation

Edit `live-translator/.env`:

```env
AZURE_TRANSLATOR_KEY=<your Azure AI Translator key>
AZURE_TRANSLATOR_REGION=<your Azure resource region>
AZURE_TRANSLATOR_ENDPOINT=https://api.cognitive.microsofttranslator.com
```

Do not commit `.env` or secrets to Git.

Without these credentials, the application still performs local English STT but the Turkish output is only cybersecurity terminology assistance.

## Select the Windows audio output

List speakers:

```powershell
python main.py --list-speakers
```

Use an exact speaker name if Windows has multiple outputs:

```powershell
python main.py --speaker "Speakers (Realtek(R) Audio)"
```

By default, the Windows default speaker is selected. Because capture uses WASAPI loopback, the Microsoft event audio playing through that speaker becomes the STT input.

## Run directly

```powershell
python main.py
```

The terminal displays:

```text
EN: Let's investigate the affected device...
TR: Etkilenen cihazı inceleyelim...
MODE: Azure AI Translator
```

Press `Ctrl+C` to stop.

## Performance

`small.en` is the default model. On CPU-only machines, latency may be higher. A smaller model such as `base.en` can be selected when lower latency is more important than transcription accuracy:

```powershell
python main.py --model base.en
```

The live chunk size defaults to 4 seconds. Smaller chunks reduce perceived latency but can reduce context and increase processing overhead.

## Troubleshooting

### No audio

1. Start audio playback in the Microsoft event.
2. Run `python main.py --list-speakers`.
3. Select the Windows speaker actually producing the event sound.
4. Verify Windows volume is not muted.

### Azure translation is OFF

Check that both `AZURE_TRANSLATOR_KEY` and `AZURE_TRANSLATOR_REGION` are set in `.env`. The key is never stored in source code.

### Whisper is too slow

Try:

```powershell
python main.py --model base.en
```

A compatible NVIDIA GPU can substantially improve local inference when the installed CTranslate2 build supports it.

## Scope

This is a translation/transcription companion. It does not inspect, modify, or control Microsoft Defender, Teams, browsers, or the XDR API, and it does not bypass access controls or event restrictions.
