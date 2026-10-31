#!/usr/bin/env node
/*
 * Rendu image par image de slides.html avec Playwright, encodage H.264 avec ffmpeg.
 *
 *   node render.js stills <dossier> <t1,t2,...>     -> captures PNG à des instants donnés
 *   node render.js video  <sortie.mp4> [--workers 3] [--crf 20]
 */
const { chromium } = require('playwright');
const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const HERE = __dirname;
const BUILD = path.join(HERE, 'build');
const data = JSON.parse(fs.readFileSync(path.join(HERE, 'scenes.json'), 'utf8'));
const timeline = JSON.parse(fs.readFileSync(path.join(BUILD, 'timeline.json'), 'utf8'));
const FPS = timeline.fps;

function arg(name, def) {
  const i = process.argv.indexOf(name);
  return i > 0 ? process.argv[i + 1] : def;
}

async function openPage(browser) {
  const page = await browser.newPage({ viewport: { width: 1920, height: 1080 }, deviceScaleFactor: 1 });
  await page.goto('file://' + path.join(HERE, 'slides.html'));
  await page.evaluate(([d, t]) => window.setup(d, t), [data, timeline]);
  await page.evaluate(() => document.fonts.ready);
  return page;
}

async function stills(outDir, times) {
  fs.mkdirSync(outDir, { recursive: true });
  const browser = await chromium.launch();
  const page = await openPage(browser);
  for (const t of times) {
    await page.evaluate(x => window.renderAt(x), t);
    const f = path.join(outDir, `still_${t.toFixed(2).padStart(7, '0')}.png`);
    await page.screenshot({ path: f });
    console.log(f);
  }
  await browser.close();
}

async function renderChunk(k, f0, f1, crf, log) {
  const out = path.join(BUILD, `seg_${k}.mp4`);
  const ff = spawn('ffmpeg', ['-y', '-v', 'error', '-f', 'image2pipe', '-framerate', String(FPS), '-c:v', 'mjpeg', '-i', '-',
    '-c:v', 'libx264', '-preset', 'medium', '-crf', String(crf), '-tune', 'stillimage', '-pix_fmt', 'yuv420p',
    '-x264-params', 'keyint=150:min-keyint=30', '-r', String(FPS), out], { stdio: ['pipe', 'inherit', 'inherit'] });
  const done = new Promise((res, rej) => ff.on('close', c => c === 0 ? res() : rej(new Error('ffmpeg ' + c))));
  const browser = await chromium.launch();
  const page = await openPage(browser);
  for (let f = f0; f < f1; f++) {
    await page.evaluate(x => window.renderAt(x), f / FPS);
    const buf = await page.screenshot({ type: 'jpeg', quality: 94 });
    if (!ff.stdin.write(buf)) await new Promise(r => ff.stdin.once('drain', r));
    log(k, f - f0 + 1);
  }
  ff.stdin.end();
  await browser.close();
  await done;
  return out;
}

async function video(outFile, workers, crf) {
  const N = Math.ceil(timeline.duration * FPS);
  const per = Math.ceil(N / workers);
  const progress = new Array(workers).fill(0);
  const t0 = Date.now();
  let last = 0;
  const log = (k, n) => {
    progress[k] = n;
    const done = progress.reduce((a, b) => a + b, 0);
    if (done - last >= 300 || done === N) {
      last = done;
      const el = (Date.now() - t0) / 1000;
      console.log(`  ${done}/${N} images (${(done / el).toFixed(1)} img/s, reste ~${Math.round((N - done) / (done / el))} s)`);
    }
  };
  console.log(`Rendu de ${N} images (${timeline.duration}s à ${FPS} i/s) avec ${workers} processus…`);
  const segs = await Promise.all([...Array(workers).keys()].map(k =>
    renderChunk(k, k * per, Math.min(N, (k + 1) * per), crf, log)));
  const list = path.join(BUILD, 'segments.txt');
  fs.writeFileSync(list, segs.map(s => `file '${s}'`).join('\n'));
  const silent = path.join(BUILD, 'video_silent.mp4');
  execFileSync('ffmpeg', ['-y', '-v', 'error', '-f', 'concat', '-safe', '0', '-i', list, '-c', 'copy', silent], { stdio: 'inherit' });
  execFileSync('ffmpeg', ['-y', '-v', 'error', '-i', silent, '-i', path.join(BUILD, 'audio_mix.wav'),
    '-i', path.join(BUILD, 'sous-titres.srt'),
    '-map', '0:v', '-map', '1:a', '-map', '2:s', '-c:v', 'copy', '-c:a', 'aac', '-b:a', '192k',
    '-c:s', 'mov_text', '-metadata:s:a:0', 'language=fre', '-metadata:s:s:0', 'language=fre',
    '-metadata:s:s:0', 'title=Français', '-metadata', `title=${data.meta.title}`,
    '-movflags', '+faststart', '-shortest', outFile], { stdio: 'inherit' });
  console.log(`Vidéo prête : ${outFile} (${((Date.now() - t0) / 60000).toFixed(1)} min)`);
}

(async () => {
  const mode = process.argv[2];
  if (mode === 'stills') {
    await stills(process.argv[3], process.argv[4].split(',').map(Number));
  } else if (mode === 'video') {
    await video(path.resolve(process.argv[3]), +arg('--workers', 3), +arg('--crf', 20));
  } else {
    console.error('usage: render.js stills <dir> <t1,t2,..> | video <out.mp4> [--workers N] [--crf N]');
    process.exit(1);
  }
})().catch(e => { console.error(e); process.exit(1); });
