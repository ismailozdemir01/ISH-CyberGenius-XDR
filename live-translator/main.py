from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

import numpy as np
import soundcard as sc
from faster_whisper import WhisperModel


@dataclass
class Settings:
    speaker: str | None
    model: str
    sample_rate: int
    chunk_seconds: float
    beam_size: int
    translator_enabled: bool


def load_dotenv() -> None:
    path = os.path.join(os.path.dirname(__file__), ".env")
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def local_terminology(text: str) -> str:
    replacements = {
        "advanced hunting": "Advanced Hunting",
        "threat intelligence": "tehdit istihbaratı",
        "incident response": "olay müdahalesi",
        "endpoint detection and response": "uç nokta tespit ve müdahale",
        "attack surface": "saldırı yüzeyi",
        "lateral movement": "yatay hareket",
        "credential theft": "kimlik bilgisi hırsızlığı",
        "identity": "kimlik",
        "endpoint": "uç nokta",
        "incident": "olay",
        "alert": "uyarı",
        "evidence": "kanıt",
        "investigation": "inceleme",
        "response": "müdahale",
        "device": "cihaz",
    }
    result = text
    for source, target in replacements.items():
        result = result.replace(source, target).replace(source.title(), target)
    return result


def azure_translate(text: str) -> str | None:
    key = os.getenv("AZURE_TRANSLATOR_KEY", "").strip()
    region = os.getenv("AZURE_TRANSLATOR_REGION", "").strip()
    endpoint = os.getenv("AZURE_TRANSLATOR_ENDPOINT", "https://api.cognitive.microsofttranslator.com").rstrip("/")
    if not key or not region:
        return None

    params = urllib.parse.urlencode({"api-version": "3.0", "from": "en", "to": "tr"})
    body = json.dumps([{"text": text}]).encode("utf-8")
    request = urllib.request.Request(
        f"{endpoint}/translate?{params}",
        data=body,
        method="POST",
        headers={
            "Ocp-Apim-Subscription-Key": key,
            "Ocp-Apim-Subscription-Region": region,
            "Content-Type": "application/json; charset=UTF-8",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return payload[0]["translations"][0]["text"]
    except (urllib.error.URLError, urllib.error.HTTPError, KeyError, IndexError, json.JSONDecodeError) as exc:
        print(f"[translator] Azure translation unavailable: {exc}", file=sys.stderr)
        return None


def list_speakers() -> list[object]:
    speakers = list(sc.all_speakers())
    print("Available Windows speakers / loopback sources:\n")
    for index, speaker in enumerate(speakers):
        print(f"  [{index}] {speaker.name}")
    return speakers


def parse_args() -> Settings:
    parser = argparse.ArgumentParser(description="ISH-CyberGenius local Windows live translator")
    parser.add_argument("--speaker", help="Exact Windows speaker name; default is the system default speaker")
    parser.add_argument("--list-speakers", action="store_true")
    parser.add_argument("--model", default=os.getenv("WHISPER_MODEL", "small.en"))
    parser.add_argument("--sample-rate", type=int, default=int(os.getenv("SAMPLE_RATE", "16000")))
    parser.add_argument("--chunk-seconds", type=float, default=float(os.getenv("CHUNK_SECONDS", "4")))
    parser.add_argument("--beam-size", type=int, default=5)
    args = parser.parse_args()

    if args.list_speakers:
        list_speakers()
        raise SystemExit(0)

    return Settings(
        speaker=args.speaker,
        model=args.model,
        sample_rate=args.sample_rate,
        chunk_seconds=args.chunk_seconds,
        beam_size=args.beam_size,
        translator_enabled=bool(os.getenv("AZURE_TRANSLATOR_KEY") and os.getenv("AZURE_TRANSLATOR_REGION")),
    )


def choose_speaker(name: str | None):
    if name:
        for speaker in sc.all_speakers():
            if speaker.name == name:
                return speaker
        raise RuntimeError(f'Windows speaker not found: "{name}". Run: python main.py --list-speakers')
    speaker = sc.default_speaker()
    if speaker is None:
        raise RuntimeError("No Windows default speaker was found.")
    return speaker


def main() -> None:
    load_dotenv()
    settings = parse_args()
    speaker = choose_speaker(settings.speaker)

    print("ISH-CyberGenius Live Translator")
    print(f"System audio: {speaker.name}")
    print(f"Whisper model: {settings.model}")
    print(f"Full Azure Turkish translation: {'ON' if settings.translator_enabled else 'OFF'}")
    if not settings.translator_enabled:
        print("Set AZURE_TRANSLATOR_KEY and AZURE_TRANSLATOR_REGION in live-translator/.env for real English -> Turkish translation.")
    print("\nStart the Microsoft event. Press Ctrl+C to stop.\n")

    model = WhisperModel(settings.model, device="auto", compute_type="auto")

    # soundcard exposes the Windows speaker through a WASAPI loopback recorder.
    with speaker.recorder(samplerate=settings.sample_rate, channels=1) as recorder:
        while True:
            frames = max(1, int(settings.sample_rate * settings.chunk_seconds))
            audio = recorder.record(numframes=frames)
            audio = np.asarray(audio, dtype=np.float32).reshape(-1)

            segments, _ = model.transcribe(
                audio,
                language="en",
                beam_size=settings.beam_size,
                vad_filter=True,
                condition_on_previous_text=True,
            )
            text = " ".join(segment.text.strip() for segment in segments).strip()
            if not text:
                continue

            translated = azure_translate(text) if settings.translator_enabled else None
            if translated is None:
                translated = local_terminology(text)

            print("=" * 88)
            print("EN:", text)
            print("TR:", translated)
            if settings.translator_enabled:
                print("MODE: Azure AI Translator")
            else:
                print("MODE: local cybersecurity terminology assistance")
            print("=" * 88, flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
    except Exception as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        raise
