"""Optional push-to-talk voice interface. Install requirements-voice.txt to enable."""
from __future__ import annotations

import tempfile
from pathlib import Path


class VoiceUnavailable(RuntimeError):
    pass


class VoiceInterface:
    """Record one utterance, transcribe locally, and speak the response."""

    def __init__(self, model_size: str = "base"):
        try:
            import sounddevice as sd
            import soundfile as sf
            from faster_whisper import WhisperModel
            import pyttsx3
        except ImportError as exc:
            raise VoiceUnavailable(
                "Voice extras are missing. Install with: pip install -r requirements-voice.txt"
            ) from exc
        self.sd = sd
        self.sf = sf
        self.whisper = WhisperModel(model_size, device="cpu", compute_type="int8")
        self.tts = pyttsx3.init()

    def listen_once(self, seconds: int = 7, sample_rate: int = 16000) -> str:
        duration = max(2, min(seconds, 15))
        print(f"Listening for up to {duration} seconds...")
        audio = self.sd.rec(
            int(duration * sample_rate),
            samplerate=sample_rate,
            channels=1,
            dtype="float32",
        )
        self.sd.wait()
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as handle:
            temp_path = Path(handle.name)
        try:
            self.sf.write(str(temp_path), audio, sample_rate)
            segments, _ = self.whisper.transcribe(str(temp_path), vad_filter=True)
            return " ".join(segment.text.strip() for segment in segments).strip()
        finally:
            temp_path.unlink(missing_ok=True)

    def speak(self, text: str) -> None:
        self.tts.say(text)
        self.tts.runAndWait()
