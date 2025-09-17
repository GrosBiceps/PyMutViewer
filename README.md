# MutViewer (PyMutViewer) — Visualiseur 3D et prédicteur d’impact de mutations

> **Outil de bureau PyQt5** pour analyser une mutation **HGVS transcript**, récupérer automatiquement la structure **AlphaFold**, visualiser la protéine en 3D avec **3Dmol.js**, superposer les **features UniProt**, et estimer l’effet de la mutation (ΔΔG) via **DynaMut2** et **INPS‑MD**. Inclut l’ouverture rapide d’outils externes (**ProtVar**, **Miztli**), un petit **serveur HTTP** pour intégration pipeline, et un **export PDF** soigné.

---

## Sommaire
- [Aperçu](#aperçu)
- [Fonctionnalités](#fonctionnalités)
- [Architecture](#architecture)
- [Installation](#installation)
- [Configuration (`config.yaml`)](#configuration-configyaml)
- [Démarrage](#démarrage)
- [Utilisation](#utilisation)
- [Serveur HTTP embarqué (pipeline)](#serveur-http-embarqué-pipeline)
- [Export PDF](#export-pdf)
- [Dépannage](#dépannage)
- [Feuille de route](#feuille-de-route)
- [Crédits & remerciements](#crédits--remerciements)
- [Avertissement](#avertissement)
- [Licence](#licence)

---

## Aperçu

MutViewer automatise la chaîne **HGVS → HGVSp / UniProt → AlphaFold (PDB) → Visualisation 3D → Prédictions ΔΔG**.  
L’interface (onglets) permet d’**entrer la mutation**, **voir** la structure, **soumettre** des prédictions, **ouvrir** des outils complémentaires et **exporter** un rapport PDF.

> Exemple de mutation : `NM_005228.5(EGFR):c.2390G>C`

---

## Fonctionnalités

### Entrée mutation
- Saisie d’une mutation en **notation HGVS transcript**
- Validation du format (regex) et extraction du **gène**

### Visualisation 3D (navigateur)
- Récupération de l’**ID UniProt** et du **HGVSp** via **Ensembl VEP**
- Téléchargement automatique du modèle **AlphaFold** (PDB)
- Visualisation interactive avec **3Dmol.js** :
  - **Mode pLDDT** (coloration confiance 0→100)
  - **Mode features** : superposition des **features UniProt** (domaines, sites actifs, liaisons métal, etc.)
  - Mise en évidence du résidu **muté** (boule sur CA, orange)
- **Panneau de sélection** des types de features (critique, tous, aucun), **style** (cartoon/surface/stick/sphere) et **opacité**

### Prédictions (ΔΔG)
- **DynaMut2** : soumission du PDB (AlphaFold) + mutation, **ΔΔG** (kcal/mol) → stabilisant / déstabilisant / neutre
- **INPS‑MD** : soumission + **polling** jusqu’à 30 min, liens **JSON/TSV** récupérés automatiquement
- Affichage du **JSON** et des **URLs** de résultats

### APIs externes
- **ProtVar (EBI)** : ouvre la requête avec la mutation HGVS
- **Miztli** : ouvre avec *gène + code court* (ex. `E346K`)

### Export PDF
- Rapport PDF professionnel (résumé, liens, captures **3D/DynaMut2/INPS‑MD** lorsque disponibles)

### Réseau & robustesse
- **Proxies CHU** optionnels via `config.yaml`
- Sessions HTTP **robustes** (retries/backoff), tolérance aux erreurs

### Serveur HTTP embarqué
- Mini listener pour intégration pipeline (endpoint `/mutviewer/search`)

---

## Architecture

```
PyQt5 App (onglets)
├─ Entrée mutation (HGVS) → VEP (REST) → (HGVSp, UniProt)
├─ Visualisation 3D → AlphaFold (PDB) → 3Dmol.js (navigateur)
├─ Prédictions → DynaMut2 (API) / INPS‑MD (form+polling)
├─ APIs externes → ProtVar / Miztli (ouverture navigateur)
├─ Export PDF → html2image + Qt PDF
└─ HTTP Listener → /mutviewer/search (GET)
```

**Modules clés** : `AppConfig` (config YAML, proxy/serveur), `PipelineHTTPListener` (serveur HTTP), `ViewerTab` (génération HTML 3D), `PredictionsTab` (DynaMut2/INPS‑MD), `ExternalAPIsTab`, `ExportTab`.

---

## Installation

> **Prérequis** : Python 3.9+ recommandé (Windows/Linux/macOS)

1) **Cloner** le dépôt puis créer un environnement virtuel :
```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate
```

2) **Installer les dépendances** minimales :
```bash
pip install PyQt5 requests pyyaml pandas PyPDF2 html2image pillow
# Optionnel (prévisualisation locale 3D en Python) :
pip install py3Dmol
```

3) **(Optionnel) Assets hors‑ligne pour 3Dmol.js**  
Placez ces ressources si vous voulez un mode totalement hors‑ligne :  
```
Assets/3Dmol.js-master/build/3Dmol-min.js
Assets/3Dmol.js-master/py3Dmol/
```
> Sinon, l’appli charge 3Dmol via un CDN directement dans la page HTML ouverte.

---

## Configuration (`config.yaml`)

Copiez `config.example.yaml` vers `config.yaml` puis adaptez :

```yaml
proxy:
  use_chu_proxy: false           # true pour activer les proxies CHU
  proxy_selected: "chu-a"        # nom d'un proxy défini ci-dessous
  proxies:
    chu-a:
      http:  "http://proxy-a:3128"
      https: "http://proxy-a:3128"
    chu-b:
      http:  "http://proxy-b:3128"
      https: "http://proxy-b:3128"

server:
  ip: "127.0.0.1"                # IP d'écoute du serveur HTTP
  port: 8123
  token: ""                      # optionnel : jeton X-Auth-Token
  allowed_ips: ["127.0.0.1", "::1"]

application:
  title: "MutViewer - Visualiseur de mutations 3D"
  http_timeout: 180              # s
  http_retries: 3
```

**Notes**  
- Si `use_chu_proxy: true`, vérifiez que `proxy_selected` existe dans `proxies` et que les URLs commencent par `http://` ou `https://`.
- `allowed_ips` limite les clients autorisés sur le **listener HTTP** (voir ci‑dessous).

---

## Démarrage

Renommez idéalement le fichier principal en `mutviewer.py` (facultatif), puis :

```bash
python "MutViewer Vfinale sans GUI modif CHU.py"
# ou
python mutviewer.py
```

Au lancement :
- la **fenêtre** PyQt5 s’ouvre,
- un **serveur HTTP** démarre en arrière‑plan (port défini dans `config.yaml`).

---

## Utilisation

### 1) Entrer une mutation
- Onglet **Entrée mutation** → coller une HGVS transcript (ex. `NM_005228.5(EGFR):c.2390G>C`) puis **Valider**.

### 2) Visualiser en 3D
- L’appli récupère HGVSp + UniProt via **VEP**, puis télécharge le PDB **AlphaFold** correspondant.
- L’onglet **Visualisation 3D** génère une page HTML interactive et l’ouvre dans votre **navigateur**.
- Choisir **pLDDT** (coloration confiance) *ou* **features** (domaines, sites actifs, etc.).
- Sélectionner les types de features à afficher et le **style** (cartoon/surface/stick/sphere).

### 3) Prédire l’impact (ΔΔG)
- Onglet **Prédictions** :
  - **DynaMut2** : renseigner la chaîne (par défaut **A**) et le **code court** (ex. `E346K`) puis lancer.
  - **INPS‑MD** : idem ; possibilité d’activer le **polling** pour attendre les liens **JSON/TSV**.
- Les résultats (ΔΔG, URLs, JSON) s’affichent dans le panneau.

### 4) Outils externes
- Onglet **APIs externes** → **ProtVar** (HGVS) / **Miztli** (gène + code court)

### 5) Exporter un rapport PDF
- Onglet **Export PDF** → *Exporter le rapport PDF*  
  Le rapport compile les méta‑infos, liens, et **captures** automatiques
  de la vue 3D/DynaMut2/INPS‑MD (lorsque disponibles).

---

## Serveur HTTP embarqué (pipeline)

Un **listener** HTTP démarre avec l’appli pour recevoir des requêtes de pipeline locales.

- **Endpoint** : `GET /mutviewer/search`
- **Auth** : si `server.token` est défini, fournir `X-Auth-Token` **ou** `?X-Auth-Token=...`
- **IPs autorisées** : `server.allowed_ips`

**Exemples**
```
GET http://127.0.0.1:8123/mutviewer/search?hgvs=NM_004304.5(ALK):c.3520T>C
GET http://127.0.0.1:8123/mutviewer/search?gene=EGFR&mut=E746_A750del
```

**Réponse**
```json
{ "ok": true, "queued": true }
```

> Avec `hgvs`, l’application charge le flux complet (VEP → AlphaFold → 3D).  
> Avec `gene` + `mut`, l’interface est pré‑remplie (chemin de repli).

---

## Export PDF

- Génération d’une page **résumé** (portrait) + pages **figures** (paysage) si des captures sont disponibles.
- **Pièces jointes** (JSON/TSV, HTML temporaires, CSV des features UniProt) copiées dans un dossier `*_assets`.

> Dépendances : `html2image`, `PyPDF2` (fusion), `Pillow` (compression d’images).

---

## Dépannage

- **“PyYAML n’est pas installé”** → `pip install pyyaml`
- **“config.yaml introuvable”** → copier `config.example.yaml` et adapter.
- **Erreur VEP/AlphaFold/UniProt** → vérifier la connectivité et le **proxy**.
- **DynaMut2/INPS‑MD** → services tiers : réessayez plus tard si surcharge ; valider le **format** du code mutation (`E346K`).
- **Vue 3D vide** → vérifier l’accès au CDN 3Dmol.js ou placer `Assets/3Dmol.js-master/build/3Dmol-min.js` en local.
- **Listener HTTP 403** → vérifier `allowed_ips` et/ou le **token**.

---

## Feuille de route
- Mode *offline* complet (assets bundlés) et cache PDB
- Plus de prédicteurs (FoldX, Maestro, etc.)
- Export **CSV/JSON** enrichi des features + scores
- Tests unitaires et CI

---

## Crédits & remerciements

- **Ensembl VEP**, **AlphaFold DB**, **UniProt**, **3Dmol.js**
- **DynaMut2** (UQ BioSig) et **INPS‑MD** (UniBo)
- Projet initié par **Florian Magne**

---

## Avertissement

> Ce logiciel est en développement et interroge des APIs externes pour des méthodes d’interprétation en **dernière intention**.  
> **Toute utilisation engage la responsabilité de l’utilisateur** dans la prise de décision.

---

## Licence

Choisissez une licence (ex. **MIT**, **BSD‑3**, **GPL‑3.0**).  
Ajoutez le fichier `LICENSE` au dépôt.
