# L'intelligence artificielle : entre progrès et défis

Présentation vidéo d'environ 6 minutes, en 1080p, avec une voix off en français.

<div dir="rtl">

**عرض تقديمي على شكل فيديو بتعليق صوتي بالفرنسية حول موضوع «الذكاء الاصطناعي بين التقدم والتحديات».**
مدة الفيديو حوالي 6 دقائق، بدقة 1080p، ويتكون من 16 شريحة متحركة تتزامن مع التعليق الصوتي، مع ترجمة نصية بالفرنسية يمكن تفعيلها.

</div>

## Fichiers

| Fichier | Contenu |
|---|---|
| [`output/IA_entre_progres_et_defis.mp4`](output/IA_entre_progres_et_defis.mp4) | La vidéo finale (H.264 + AAC, avec une piste de sous-titres français activable) |
| [`output/IA_entre_progres_et_defis.srt`](output/IA_entre_progres_et_defis.srt) | Les sous-titres au format SRT |
| [`output/texte_narration.md`](output/texte_narration.md) | Le texte complet de la narration, avec le minutage de chaque diapositive |
| [`output/apercu.jpg`](output/apercu.jpg) | Une planche d'aperçu des diapositives |
| `presentation/` | Le code source qui permet de régénérer la vidéo |

## Plan de la présentation

1. **Introduction** : titre et plan
2. **Comprendre l'IA** : définition (IA, apprentissage automatique, apprentissage profond, IA générative) et frise historique de 1956 à 2022
3. **Les progrès** : santé et recherche (diagnostic, AlphaFold et le prix Nobel de chimie 2024), économie et vie quotidienne, climat, agriculture et énergie
4. **Les défis** : emploi (FMI, 2024), biais, éthique et vie privée, désinformation et hypertrucages, coût environnemental (AIE, 2025)
5. **Perspectives** : encadrer l'IA (UNESCO 2021, règlement européen 2024, coopération mondiale), conclusion et remerciements

## Régénérer la vidéo

Le contenu (textes des diapositives et narration) se trouve dans `presentation/scenes.json`. Pour changer une phrase ou une diapositive, il suffit de modifier ce fichier puis de relancer :

```bash
pip install edge-tts numpy
cd presentation && ./build.sh
```

Outils nécessaires : Python 3, Node.js avec Playwright (Chromium), ffmpeg et une connexion Internet pour la synthèse vocale.

- `build_audio.py` génère la voix phrase par phrase avec la voix neuronale `fr-FR-HenriNeural`. Il produit aussi une nappe musicale discrète, synthétisée sans fichier externe, ainsi que le minutage et les sous-titres.
- `slides.html` contient le design des 16 diapositives et un moteur d'animation déterministe. Chaque élément apparaît au moment où la voix l'évoque.
- `render.js` capture chaque image avec Chromium, l'encode en H.264 avec ffmpeg, puis assemble la vidéo, l'audio et les sous-titres.

Pour ajouter le nom du présentateur sur la diapositive de titre, renseignez le champ `"presenter"` dans `scenes.json`.

## Sources des chiffres cités

- Fonds monétaire international, *Gen-AI: Artificial Intelligence and the Future of Work* (janvier 2024) : environ 40 % des emplois dans le monde sont exposés à l'IA, et environ 60 % dans les économies avancées.
- Agence internationale de l'énergie, *Energy and AI* (avril 2025) : la consommation d'électricité des centres de données pourrait plus que doubler d'ici 2030.
- UNESCO, *Recommandation sur l'éthique de l'intelligence artificielle*, adoptée par les 193 États membres en novembre 2021.
- Union européenne, règlement sur l'intelligence artificielle (« AI Act »), entré en vigueur le 1er août 2024.
- Prix Nobel de chimie 2024, attribué notamment à Demis Hassabis et John Jumper pour AlphaFold.
- Buolamwini et Gebru, *Gender Shades* (2018), sur les biais de la reconnaissance faciale.

La voix off a été générée par une intelligence artificielle, comme l'indique la vidéo elle-même.
