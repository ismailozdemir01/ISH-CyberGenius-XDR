# ISH-CyberGenius Live Translator

Windows-first local live speech-to-text and Turkish translation companion for online cybersecurity events.

## Goal

Capture the selected Windows system-audio loopback, transcribe English speech locally when Whisper is installed, optionally translate the transcript to Turkish, and display a live bilingual terminal UI.

This tool is deliberately separate from the XDR runtime. It does not inspect, modify, or control Microsoft Defender, Teams, browsers, or the XDR API.

## Privacy

The default architecture uses local audio capture and a local Whisper-compatible STT process. No audio is uploaded by this repository. If you configure an external translation provider in the future, review that provider's data handling and the event's recording/usage rules first.

## Windows prerequisites

- Windows 10/11
- Python 3.11+
- FFmpeg available on PATH
- A loopback capture source exposed by the Windows audio stack (for example WASAPI loopback through a supported Python audio backend)
- A local Whisper installation/model

## Install

```powershell
cd live-translator
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Run

```powershell
python main.py
```

The application opens a local terminal UI and continuously processes short audio windows. Press `Ctrl+C` to stop.

## Important

Speech recognition accuracy depends on audio quality, model size, terminology, and CPU/GPU performance. This is a live transcription assistant, not a guaranteed verbatim or simultaneous interpreter.

Do not enable recording/persistent transcript storage for an event unless the event's terms permit it.
