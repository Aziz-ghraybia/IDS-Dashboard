this Project was created as a university project so at first there is a quick explanaition written in french
so if you don't understand anything there is an english explaination after the french one
# IDS-Dashboard – Système de Détection d’Intrusions (IDS)

## 1. Fonctionnement du projet

Ce projet est un **Système de Détection d’Intrusions (IDS)** basé sur le **Machine Learning**.
Il analyse le trafic réseau en temps réel, extrait des **flux réseau (flows)** à partir des paquets capturés, puis utilise des modèles d’apprentissage automatique pour détecter si le trafic est **normal** ou **malveillant**.

### 🔍 Capture des paquets – Scapy
Le projet utilise **Scapy**, une bibliothèque Python spécialisée dans l’analyse réseau.

- `sniff()` permet de capturer les paquets réseau en temps réel
- Chaque paquet contient des informations comme :
  - IP source / destination
  - Ports
  - Protocole
  - Taille
  - Flags TCP

### 🔁 Qu’est-ce qu’un flow réseau ?
Un **flow** est un regroupement de paquets partageant les mêmes caractéristiques, par exemple :
- IP source
- IP destination
- Port source
- Port destination
- Protocole

Les flows permettent de représenter le trafic réseau de manière **structurée** et exploitable par des algorithmes de Machine Learning.

### 🤖 Modèles de Machine Learning utilisés

#### 🌳 Random Forest
Random Forest est un algorithme basé sur un ensemble d’arbres de décision.

- Chaque arbre prend une décision
- Le vote majoritaire détermine la prédiction finale
- Avantages :
  - Robuste au bruit
  - Bonne précision
  - Faible risque de surapprentissage

#### 🚀 XGBoost
XGBoost (Extreme Gradient Boosting) est un algorithme de boosting très performant.

- Les arbres sont entraînés de manière séquentielle
- Chaque arbre corrige les erreurs du précédent
- Avantages :
  - Très rapide
  - Excellente précision
  - Très utilisé en cybersécurité et data science

### 📊 Visualisation
Le projet utilise **Matplotlib** pour afficher :
- Le nombre d’attaques détectées
- La répartition du trafic normal / malveillant
- Des statistiques globales sur le réseau analysé

---

## 2. Commandes pour utiliser le projet

### 🔹 Création de l’environnement virtuel
python -m venv venv
### 🔹 Activation de l’environnement virtuel
venv\Scripts\activate
### 🔹 Installation des dépendances
pip install -r requirements.txt
### 🔹 Lancement du projet
python GUI.py


-----------------------------------------------------------------------------------------------------------------------
## 📘 `README.md` (English)

```md
# IDS-Dashboard – Intrusion Detection System (IDS)

## 1. How the project works

This project is a **Machine Learning–based Intrusion Detection System (IDS)**.
It analyzes network traffic in real time, extracts **network flows** from captured packets, and uses machine learning models to decide whether the traffic is **normal** or **malicious**.

### 🔍 Packet capture – Scapy
The project uses **Scapy**, a powerful Python library for network analysis.

- `sniff()` is used to capture packets in real time
- Each packet contains information such as:
  - Source / destination IP
  - Ports
  - Protocol
  - Packet size
  - TCP flags

### 🔁 What is a network flow?
A **flow** is a group of packets sharing the same characteristics, such as:
- Source IP
- Destination IP
- Source port
- Destination port
- Protocol

Flows provide a **structured representation** of network traffic that can be processed by machine learning algorithms.

### 🤖 Machine Learning models used

#### 🌳 Random Forest
Random Forest is an ensemble algorithm based on multiple decision trees.

- Each tree makes a prediction
- The final decision is based on majority voting
- Advantages:
  - Robust to noise
  - High accuracy
  - Low risk of overfitting

#### 🚀 XGBoost
XGBoost (Extreme Gradient Boosting) is a highly optimized boosting algorithm.

- Trees are trained sequentially
- Each new tree corrects previous errors
- Advantages:
  - Very fast
  - Excellent accuracy
  - Widely used in cybersecurity and data science

### 📊 Visualization
The project uses **Matplotlib** to display:
- Number of detected attacks
- Distribution of normal vs malicious traffic
- Global network traffic statistics

---

## 2. Commands required to use the project

### 🔹 Create a virtual environment
python -m venv venv
### 🔹 Activate the virtual environment
venv\Scripts\activate

### 🔹 Install Libraries
pip install -r requirements.txt

### 🔹 Run the project
python GUI.py