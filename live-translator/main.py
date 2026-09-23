from __future__ import annotations

import argparse
import queue
import sys
import time
from dataclasses import dataclass

import numpy as np
import sounddevice as sd
from faster_whisper import WhisperModel


@dataclass
class Settings:
    device: int | None
    model: str
    language: str
    sample_rate: int
    chunk_seconds: float
    beam_size: int


class LoopbackRecorder:
    def __init__(self, sample_rate: int, device: int | None, channels: int = 1) -> None:
        self.sample_rate = sample_rate
        self.device = device
        self.channels = channels
        self.blocks: queue.Queue[np.ndarray] = queue.Queue()

    def callback(self, indata: np.ndarray, frames: int, time_info: object, status: sd.CallbackFlags) -> None:
        if status:
            print(f"\n[audio] {status}", file=sys.stderr)
        self.blocks.put(indata[:, 0].copy())

    def stream(self) -> sd.InputStream:
        return sd.InputStream(
            samplerate=self.sample_rate,
            device=self.device,
            channels=self.channels,
            dtype="float32",
            callback=self.callback,
            blocksize=0,
        )

    def collect(self, seconds: float) -> np.ndarray:
        target = int(self.sample_rate * seconds)
        chunks: list[np.ndarray] = []
        count = 0
        while count < target:
            chunk = self.blocks.get()
            chunks.append(chunk)
            count += len(chunk)
        audio = np.concatenate(chunks)
        return audio[:target]


def translate_to_turkish(text: str) -> str:
    """Local deterministic terminology assistance.

    Full machine translation is intentionally not hidden behind a fake implementation.
    This function only normalizes common cybersecurity terms. A real MT provider can
    be added later without changing the audio/STT pipeline.
    """
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


def parse_args() -> Settings:
    parser = argparse.ArgumentParser(description="Local Windows live cybersecurity speech assistant")
    parser.add_argument("--device", type=int, default=None, help="sounddevice input device index")
    parser.add_argument("--model", default="small.en", help="faster-whisper model, e.g. small.en/base.en")
    parser.add_argument("--sample-rate", type=int, default=16000)
    parser.add_argument("--chunk-seconds", type=float, default=5.0)
    parser.add_argument("--beam-size", type=int, default=5)
    args = parser.parse_args()
    return Settings(args.device, args.model, "en", args.sample_rate, args.chunk_seconds, args.beam_size)


def main() -> None:
    settings = parse_args()
    print("ISH-CyberGenius Live Translator")
    print("Loading local Whisper model:", settings.model)
    model = WhisperModel(settings.model, device="auto", compute_type="auto")
    recorder = LoopbackRecorder(settings.sample_rate, settings.device)

    print("\nAudio devices:")
    print(sd.query_devices())
    print("\nStart the Microsoft event and select a supported loopback/input device.")
    print("Press Ctrl+C to stop.\n")

    with recorder.stream():
        while True:
            audio = recorder.collect(settings.chunk_seconds)
            segments, _ = model.transcribe(
                audio,
                language=settings.language,
                beam_size=settings.beam_size,
                vad_filter=True,
                condition_on_previous_text=True,
            )
            text = " ".join(segment.text.strip() for segment in segments).strip()
            if not text:
                continue
            print("=" * 80)
            print("EN:", text)
            print("TR:", translate_to_turkish(text))
            print("=" * 80, flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
    except Exception as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        raise
