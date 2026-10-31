#!/usr/bin/env python3
"""Génère la narration (voix neuronale française), la musique d'ambiance,
les sous-titres SRT et le minutage (timeline.json) utilisé par le rendu vidéo.

Usage : python3 build_audio.py [--ca /chemin/ca-bundle.crt]
"""
import argparse
import asyncio
import hashlib
import json
import math
import os
import subprocess
import sys
import wave

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
BUILD = os.path.join(HERE, "build")
AUDIO_DIR = os.path.join(BUILD, "tts")
SR = 48000

# Minutage (secondes)
LEAD_FIRST = 1.4      # silence avant la première phrase de la vidéo
LEAD = 0.9            # silence au début de chaque scène (pendant le fondu)
GAP = 0.42            # pause entre deux phrases
GAP_SHORT = 0.16      # pause après une virgule / deux-points
TAIL = 1.15           # temps après la dernière phrase d'une scène
TAIL_LAST = 3.2       # fin de la vidéo
OVERLAP = 0.6         # chevauchement (fondu enchaîné) entre scènes


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--ca", default=os.environ.get("TTS_CA_BUNDLE"),
                   help="Bundle CA à utiliser pour la connexion TTS (proxy)")
    return p.parse_args()


async def tts(text, voice, rate, out_path):
    import edge_tts
    for attempt in range(5):
        try:
            com = edge_tts.Communicate(text, voice, rate=rate)
            await com.save(out_path + ".part")
            if os.path.getsize(out_path + ".part") < 1000:
                raise RuntimeError("audio vide")
            os.replace(out_path + ".part", out_path)
            return
        except Exception as e:  # réseau instable : on réessaie
            wait = 2 ** (attempt + 1)
            print(f"  ! TTS échec ({e}); nouvel essai dans {wait}s", file=sys.stderr)
            await asyncio.sleep(wait)
    raise SystemExit("TTS impossible après plusieurs essais")


def decode(path):
    raw = subprocess.run(
        ["ffmpeg", "-v", "error", "-i", path, "-f", "f32le", "-ac", "1", "-ar", str(SR), "-"],
        check=True, capture_output=True).stdout
    return np.frombuffer(raw, dtype=np.float32).copy()


def trim(x, thr_db=-48.0, keep=0.03):
    thr = 10 ** (thr_db / 20)
    idx = np.where(np.abs(x) > thr)[0]
    if len(idx) == 0:
        return x
    a = max(0, idx[0] - int(keep * SR))
    b = min(len(x), idx[-1] + int(keep * SR * 2))
    return x[a:b]


def split_caption(text, maxlen=86):
    text = text.strip()
    if len(text) <= maxlen:
        return [text]
    mid = len(text) / 2
    best = None
    for i, ch in enumerate(text):
        if ch in ",;:" and i + 1 < len(text) and text[i + 1] == " ":
            score = abs(i - mid)
            if best is None or score < best[0]:
                best = (score, i + 1)
    if best is None or best[0] > len(text) * 0.3:
        spaces = [i for i, ch in enumerate(text) if ch == " "]
        cut = min(spaces, key=lambda i: abs(i - mid))
    else:
        cut = best[1]
    return split_caption(text[:cut], maxlen) + split_caption(text[cut:], maxlen)


def wrap2(text, width=46):
    if len(text) <= width:
        return text
    mid = len(text) / 2
    spaces = [i for i, ch in enumerate(text) if ch == " "]
    cut = min(spaces, key=lambda i: abs(i - mid))
    return text[:cut] + "\n" + text[cut + 1:]


def srt_time(t):
    ms = int(round(t * 1000))
    h, ms = divmod(ms, 3600000)
    m, ms = divmod(ms, 60000)
    s, ms = divmod(ms, 1000)
    return f"{h:02d}:{m:02d}:{s:02d},{ms:03d}"


def make_music(duration, scene_starts):
    """Nappe d'ambiance douce synthétisée (accords lents, aucune ressource externe)."""
    n = int(duration * SR)
    t = np.arange(n) / SR
    # Progression : Am(add9) – Fmaj7 – C(add9) – G(6), 8 s par accord
    A2, C3, D3, E3, F3, G3, A3, B3, C4, D4, E4, F4, G4, A4, B4 = (
        110.0, 130.81, 146.83, 164.81, 174.61, 196.0, 220.0, 246.94,
        261.63, 293.66, 329.63, 349.23, 392.0, 440.0, 493.88)
    chords = [
        [A2, E3, A3, C4, E4, B4],
        [F3 / 2, C3, F3, A3, E4, G4],
        [C3, G3, C4, D4, E4, G4],
        [G3 / 2, D3, G3, B3, D4, E4],
    ]
    chord_len = 8.0
    out = np.zeros((2, n), dtype=np.float64)
    nchords = int(math.ceil(duration / chord_len)) + 1
    rng = np.random.default_rng(7)
    for k in range(nchords):
        c0 = k * chord_len - 2.0
        c1 = c0 + chord_len + 4.0
        a, b = max(0, int(c0 * SR)), min(n, int(c1 * SR))
        if a >= b:
            continue
        tt = t[a:b]
        local = tt - c0
        span = c1 - c0
        env = np.sin(np.pi * np.clip(local / span, 0, 1)) ** 1.6
        notes = chords[k % len(chords)]
        for j, f in enumerate(notes):
            for ch, det in ((0, 1 - 0.0011), (1, 1 + 0.0011)):
                ph = rng.uniform(0, 2 * np.pi)
                amp = 0.9 / (1 + 0.35 * j)
                lfo = 1 + 0.25 * np.sin(2 * np.pi * (0.07 + 0.013 * j) * tt + ph)
                sig = np.sin(2 * np.pi * f * det * tt + ph)
                sig += 0.12 * np.sin(2 * np.pi * 2 * f * det * tt + ph * 1.3)
                out[ch, a:b] += amp * lfo * env * sig
    peak = np.max(np.abs(out)) or 1
    out /= peak
    # Fondus d'entrée / sortie
    fin = np.clip(t / 4.0, 0, 1)
    fout = np.clip((duration - t) / 5.0, 0, 1)
    out *= (fin * fout) ** 1.5
    return out


def write_wav(path, stereo):
    pcm = np.clip(stereo.T, -1, 1)
    pcm = (pcm * 32767).astype("<i2")
    with wave.open(path, "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(SR)
        w.writeframes(pcm.tobytes())


def main():
    args = parse_args()
    if args.ca:
        import certifi
        certifi.where = lambda: args.ca
    os.makedirs(AUDIO_DIR, exist_ok=True)
    with open(os.path.join(HERE, "scenes.json"), encoding="utf-8") as f:
        data = json.load(f)
    voice = data["meta"]["voice"]
    rate = data["meta"].get("rate", "+0%")

    # 1) Synthèse vocale phrase par phrase (avec cache)
    clips = []
    for si, sc in enumerate(data["scenes"]):
        row = []
        for bi, beat in enumerate(sc["beats"]):
            say = beat.get("say", beat["text"])
            h = hashlib.sha1(f"{voice}|{rate}|{say}".encode()).hexdigest()[:12]
            path = os.path.join(AUDIO_DIR, f"s{si:02d}_b{bi:02d}_{h}.mp3")
            if not os.path.exists(path):
                print(f"TTS scène {si + 1} phrase {bi + 1}: {say[:60]}…")
                asyncio.run(tts(say, voice, rate, path))
            row.append(trim(decode(path)))
        clips.append(row)

    # 2) Minutage
    timeline = {"fps": 30, "scenes": []}
    t = 0.0
    placements = []
    for si, sc in enumerate(data["scenes"]):
        start = t
        cur = start + (LEAD_FIRST if si == 0 else LEAD)
        beats = []
        for bi, beat in enumerate(sc["beats"]):
            d = len(clips[si][bi]) / SR
            beats.append({"start": round(cur, 3), "end": round(cur + d, 3), "text": beat["text"]})
            placements.append((cur, clips[si][bi]))
            last = beat["text"].rstrip()
            cur += d + (GAP_SHORT if last.endswith((",", ":")) else GAP)
        end = beats[-1]["end"] + (TAIL_LAST if si == len(data["scenes"]) - 1 else TAIL)
        timeline["scenes"].append({"id": sc["id"], "start": round(start, 3), "end": round(end, 3), "beats": beats})
        t = end - OVERLAP
    duration = timeline["scenes"][-1]["end"]
    timeline["duration"] = round(duration, 3)

    # 3) Mixage
    n = int(math.ceil(duration * SR)) + SR
    voice_track = np.zeros(n, dtype=np.float64)
    for at, clip in placements:
        a = int(at * SR)
        voice_track[a:a + len(clip)] += clip
    vpeak = np.max(np.abs(voice_track)) or 1
    voice_track *= 0.89 / vpeak  # crête voix ≈ -1 dBFS
    music = make_music(n / SR, [s["start"] for s in timeline["scenes"]])
    music_gain = 10 ** (-27 / 20)  # nappe très discrète sous la voix
    mix = np.vstack([voice_track, voice_track]) + music * music_gain
    mix /= max(1.0, np.max(np.abs(mix)) / 0.97)
    write_wav(os.path.join(BUILD, "audio_mix.wav"), mix)

    # 4) Sous-titres
    cues = []
    for sc in timeline["scenes"]:
        for b in sc["beats"]:
            parts = split_caption(b["text"])
            total = sum(len(p) for p in parts)
            cur = b["start"]
            span = b["end"] - b["start"]
            for p in parts:
                d = span * len(p) / total
                cues.append((cur, cur + d, wrap2(p.strip())))
                cur += d
    srt = []
    for i, (a, b, txt) in enumerate(cues, 1):
        srt.append(f"{i}\n{srt_time(a)} --> {srt_time(b + 0.25)}\n{txt}\n")
    with open(os.path.join(BUILD, "sous-titres.srt"), "w", encoding="utf-8") as f:
        f.write("\n".join(srt))

    with open(os.path.join(BUILD, "timeline.json"), "w", encoding="utf-8") as f:
        json.dump(timeline, f, ensure_ascii=False, indent=1)
    print(f"Durée totale : {duration:.1f} s ({int(duration // 60)} min {int(duration % 60):02d} s), "
          f"{sum(len(s['beats']) for s in timeline['scenes'])} phrases, {len(cues)} sous-titres")


if __name__ == "__main__":
    main()
