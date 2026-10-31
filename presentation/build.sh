#!/usr/bin/env bash
# Reconstruit toute la vidéo : voix + musique + sous-titres, puis rendu image par image.
# Prérequis : python3 (numpy, edge-tts), node + playwright (Chromium), ffmpeg.
set -euo pipefail
cd "$(dirname "$0")"

python3 build_audio.py ${TTS_CA_BUNDLE:+--ca "$TTS_CA_BUNDLE"}
node render.js video ../output/IA_entre_progres_et_defis.mp4 --workers "${WORKERS:-3}" --crf "${CRF:-20}"
cp build/sous-titres.srt ../output/IA_entre_progres_et_defis.srt
