#!/usr/bin/env python3
import sys
import os
import re
import string
import pickle
import requests
import json
from datetime import datetime

import pandas as pd
import numpy as np
import nltk
from nltk.stem import SnowballStemmer
from nltk.corpus import stopwords
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from bs4 import BeautifulSoup
from flask import Flask, render_template_string, request, redirect, url_for , make_response
import google.generativeai as genai


from PyQt6.QtCore import QUrl, pyqtSignal, QThread
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget,
    QVBoxLayout, QToolBar, QLineEdit, QPushButton, QMessageBox
)
from PyQt6.QtWebEngineWidgets import QWebEngineView
def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)
NEW_TAB_FILE = resource_path("newtab.html")
CONTROLS_FILENAME = resource_path("parental_controls.json")
HISTORY_FILENAME = resource_path("browsing_history.json")
MODEL_FILENAME = resource_path("hate_speech_model.pkl")
FLASK_SERVER_URL = "http://127.0.0.1:5000"


VIRUSTOTAL_API_KEY = "enter your api keys"
GOOGLE_SAFE_BROWSING_API_KEY = "enter your api keys"

try:
    stemmer = SnowballStemmer("english")
    stopword = set(stopwords.words("english"))
except LookupError:
    print("Error: NLTK 'stopwords' not found. Run: import nltk; nltk.download('stopwords')")
    sys.exit(1)

class AIInsightThread(QThread):
    insight_ready = pyqtSignal(str)
    insight_error = pyqtSignal(str)

    def __init__(self, history):
        super().__init__()
        self.history = history

    def run(self):
        try:
            api_key = "enter your api keys"
            if not api_key:
                self.insight_error.emit("<h2>API Key Not Found</h2><p>Please set the <b>GOOGLE_API_KEY</b> environment variable before running the application.</p>")
                return

            genai.configure(api_key=api_key)
            model = genai.GenerativeModel('gemini-1.5-flash')

            if not self.history:
                self.insight_ready.emit("<h2>Not Enough Data</h2><p>There is not enough browsing history to generate insights. Please browse a few websites first.</p>")
                return
            
            unique_urls = list(set([item['url'] for item in self.history][-20:]))
            
            prompt = (f"Based on this list of recently visited URLs by a child: {unique_urls}. "
                      f"Act as a helpful family safety assistant. Provide short, actionable, and friendly insights and advice to a parent. "
                      f"Categorize the browsing activity (e.g., Educational, Entertainment, Social Media). "
                      f"Offer gentle suggestions or conversation starters for the parent. "
                      f"Structure your response in simple HTML with <h2> for titles and <ul><li> for bullet points.")

            response = model.generate_content(prompt)
            
            clean_text = response.text.strip()
            if clean_text.startswith("```html"):
                clean_text = clean_text[7:]
            if clean_text.endswith("```"):
                clean_text = clean_text[:-3]

            self.insight_ready.emit(clean_text.strip())
            
        except Exception as e:
            self.insight_error.emit(f"<h2>An Error Occurred</h2><p>Could not generate insights. Please check your internet connection and API key permissions.</p><p><b>Details:</b> {e}</p>")


class FlaskThread(QThread):
    controls_updated = pyqtSignal()
    def __init__(self, window_ref):
        super().__init__()
        self.window = window_ref
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = os.urandom(24)
    def run(self):
        @self.app.route('/', methods=['GET'])
        def dashboard():
            # --- THIS FUNCTION IS MODIFIED ---
            tab_count = self.window.tabs.count()
            blocked_count = self.window.sites_blocked_session
            alert_count = self.window.ai_alerts_session
            recent_history = self.window.history[-10:]
            recent_history.reverse()

            # Render the HTML first
            html = render_template_string(
                dashboard_html,
                tab_count=tab_count,
                blocked_count=blocked_count,
                alert_count=alert_count,
                recent_history=recent_history
            )

            # Create a response and add a security policy header
            response = make_response(html)
            csp = (
                "default-src 'self'; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                "font-src https://fonts.gstatic.com; "
                "img-src 'self' https://i.imgur.com;"
            )
            response.headers['Content-Security-Policy'] = csp
            return response

        @self.app.route('/controls', methods=['GET', 'POST'])
        def controls():
            try:
                with open(CONTROLS_FILENAME, 'r') as f: data = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError): data = {"whitelist": [], "blacklist": []}
            if request.method == 'POST':
                if url_to_add := request.form.get('add_blacklist'):
                    if url_to_add not in data['blacklist']: data['blacklist'].append(url_to_add.strip().lower())
                if url_to_add := request.form.get('add_whitelist'):
                    if url_to_add not in data['whitelist']: data['whitelist'].append(url_to_add.strip().lower())
                if url_to_remove := request.form.get('remove_blacklist'):
                    data['blacklist'] = [u for u in data['blacklist'] if u != url_to_remove]
                if url_to_remove := request.form.get('remove_whitelist'):
                    data['whitelist'] = [u for u in data['whitelist'] if u != url_to_remove]
                with open(CONTROLS_FILENAME, 'w') as f: json.dump(data, f, indent=2)
                self.controls_updated.emit()
                return redirect(url_for('controls'))
            return render_template_string(controls_html,blacklist=data.get('blacklist', []),whitelist=data.get('whitelist', []))

        @self.app.route('/history', methods=['GET'])
        def history():
            full_history = self.window.history[:]
            full_history.reverse()
            return render_template_string(history_html, history=full_history)

        print("🚀 Starting Flask server for UI...")
        self.app.run(port=5000, debug=False, use_reloader=False)

def standardize(text):
    text = str(text).lower(); text = re.sub(r'\[.*?\]', '', text); text = re.sub(r'<.*?>+', '', text); text = re.sub(r'\w*\d\w*', ' ', text); text = re.sub(r'\n', '', text); text = re.sub(r'https?://\S+|www\.\S+', '', text); text = re.sub(r'[%s]' % re.escape(string.punctuation), '', text)
    words = [stemmer.stem(w) for w in text.split() if w not in stopword]
    return " ".join(words)

def check_google_safe_browsing(url: str):
    if not GOOGLE_SAFE_BROWSING_API_KEY or "YOUR_GOOGLE" in GOOGLE_SAFE_BROWSING_API_KEY: return None
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    payload = {'client': {'clientId': "SafeSurfBrowser", 'clientVersion': "1.4.0"},'threatInfo': {'threatTypes': ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],'platformTypes': ["ANY_PLATFORM"],'threatEntryTypes': ["URL"],'threatEntries': [{'url': url}]}}
    try:
        response = requests.post(api_url, json=payload); response.raise_for_status(); data = response.json()
        if 'matches' in data: return data['matches'][0]['threatType']
    except requests.exceptions.RequestException as e: print(f"❌ Error checking Google Safe Browsing: {e}")
    return None

def check_virustotal(url: str):
    if not VIRUSTOTAL_API_KEY or "YOUR_VIRUSTOTAL" in VIRUSTOTAL_API_KEY: return None
    api_url = 'https://www.virustotal.com/vtapi/v2/url/report'; params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': url}
    try:
        response = requests.get(api_url, params=params); response.raise_for_status(); data = response.json()
        if data.get('response_code') == 1 and data.get('positives', 0) > 0: return f"{data.get('positives')}/{data.get('total')}"
    except requests.exceptions.RequestException as e: print(f"❌ Error checking VirusTotal: {e}")
    return None

def analyze_image_for_nudity(image_url: str):
    print(f"🖼️  [Conceptual] Analyzing image: {image_url[:70]}...");
    if "unsafe_image_example" in image_url: return True
    return False

dashboard_html = r"""<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" /> <meta name="viewport" content="width=device-width, initial-scale=1.0" /> <title>SafeSurf Dashboard</title> <link href="https://fonts.googleapis.com/css2?family=Press+Start+2P&display=swap" rel="stylesheet" />
    <style>
      * { margin: 0; padding: 0; box-sizing: border-box; } body { font-family: "Press Start 2P", monospace; background-color: white; color: #fff; } .sidebar { position: fixed; left: 0; top: 0; width: 260px; height: 100%; background: hsl(191, 100%, 50%); padding-top: 20px; font-size: 14px; } .sidebar img { display: block; margin: 0 auto 20px; width: 150px; height: auto; } .sidebar ul { list-style: none; } .sidebar ul li { padding: 15px 20px; cursor: pointer; transition: 0.3s; } .sidebar ul li:hover { background: #1f4068; } .sidebar ul li.active { background: #e43f5a; } .main-content { margin-left: 260px; padding: 20px; color: #333; } .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; } .header h1 { display: none; } .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; } .card { background: #0f3460; border-radius: 10px; padding: 20px; box-shadow: 0 4px 10px rgba(0,0,0,0.3); text-align: center; transition: 0.3s; } .card:hover { transform: translateY(-5px); } .card h3 { color: #e43f5a; margin-bottom: 10px; font-size: 14px; } .card p { color: #fff; font-size: 24px; } table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 10px rgba(0,0,0,0.1); margin-bottom: 30px; } table th, table td { color: #333; padding: 12px 15px; text-align: left; font-size: 12px; } table th { background: #e43f5a; color: #fff; } table tr:nth-child(even) { background: #f2f2f2; } table td { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 200px; } .footer { margin-top: 20px; text-align: center; color: #aaa; font-size: 8px; } a { color: white; text-decoration: none; }
    </style>
  </head>
  <body>
    <div class="sidebar">
      <h1>SafeSurf</h1>
      <ul>
        <li class="active"><a href="/">Dashboard</a></li>
        <li><a href="/controls">Parental Controls</a></li>
        <li><a href="/history">Browsing History</a></li>
      </ul>
    </div>
    <div class="main-content">
      <h1>Dashboard</h1>
      <div class="cards">
        <div class="card"><h3>Active Tabs</h3><p>{{ tab_count }}</p></div>
        <div class="card"><h3>Sites Blocked</h3><p>{{ blocked_count }}</p></div>
        <div class="card"><h3>AI Alerts</h3><p>{{ alert_count }}</p></div>
      </div>
      <h2>Recent Browsing Activity</h2>
      <table>
        <thead> <tr><th>Title</th><th>URL</th><th>Time</th></tr> </thead>
        <tbody>
          {% for item in recent_history %} <tr> <td>{{ item.title }}</td> <td>{{ item.url }}</td> <td>{{ item.timestamp }}</td> </tr> {% else %} <tr><td colspan="3" style="text-align:center;">No browsing history yet.</td></tr> {% endfor %}
        </tbody>
      </table>
      <div class="footer">&copy; 2025 SafeSurf | AI-Powered Safety Browser</div>
    </div>
  </body>
</html>
"""

newtab_html = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>New Tab</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Balsamiq+Sans:wght@700&display=swap" rel="stylesheet">
  <style>
    body {
        font-family: 'Balsamiq Sans', cursive;
        background: #87CEEB;
        background: -webkit-linear-gradient(to top, #87CEEB, #f0f9ff);
        background: linear-gradient(to top, #87CEEB, #f0f9ff);
        margin: 0;
        padding: 24px;
        display: flex;
        justify-content: center;
        align-items: center;
        min-height: 100vh;
        color: #333;
    }
    .wrap {
        max-width: 1000px;
        margin: 0 auto;
        text-align: center;
    }
    .illustration {
        width: 150px;
        height: 150px;
        margin: 0 auto 20px;
    }
    h1 {
        color: #ff6347;
        font-size: 3.5em;
        text-shadow: 2px 2px #fff;
    }
    p {
        color: #555;
        font-size: 1.2em;
    }
    .grid {
        display: flex;
        flex-wrap: wrap;
        gap: 20px;
        margin-top: 30px;
        justify-content: center;
    }
    .tile {
        background: #fff;
        border-radius: 20px;
        padding: 20px;
        box-shadow: 0 8px 25px rgba(0,0,0,0.1);
        min-width: 180px;
        text-decoration: none;
        color: #222;
        transition: transform 0.2s ease-in-out, box-shadow 0.2s ease-in-out;
    }
    .tile:hover {
        transform: scale(1.05);
        box-shadow: 0 12px 30px rgba(0,0,0,0.15);
    }
    .tile strong {
        font-size: 1.5em;
        display: block;
    }
    .tile small {
        display: block;
        color: #666;
        margin-top: 8px;
        font-size: 1em;
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="illustration">
        <svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
            <circle cx="50" cy="50" r="40" fill="#FFD700" />
            <circle cx="35" cy="40" r="5" fill="#333" />
            <circle cx="65" cy="40" r="5" fill="#333" />
            <path d="M 30 60 Q 50 75 70 60" stroke="#333" stroke-width="4" fill="none" stroke-linecap="round" />
        </svg>
    </div>
    <h1>Let's Go Exploring!</h1>
    <p>Click a button below to start your adventure.</p>
    <div class="grid">
      <a class="tile" href="https://www.google.com"><strong>Google</strong><small>Search the Web</small></a>
      <a class="tile" href="https://pbskids.org"><strong>PBS Kids</strong><small>Games & Videos</small></a>
      <a class="tile" href="https://kids.nationalgeographic.com"><strong>Nat Geo Kids</strong><small>Amazing Animals</small></a>
      <a class="tile" href="https://www.youtubekids.com"><strong>YouTube Kids</strong><small>Watch Videos</small></a>
      <a class="tile" href="https://www.coolmathgames.com"><strong>Coolmath</strong><small>Fun & Games</small></a>
      <a class="tile" href="https://www.wikipedia.org"><strong>Wikipedia</strong><small>Learn Anything</small></a>
    </div>
  </div>
</body>
</html>
"""


controls_html = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"> <meta name="viewport" content="width=device-width, initial-scale=1.0"> <title>Parental Controls</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f0f2f5; margin: 0; padding: 20px; color: #1c1e21; } .container { max-width: 900px; margin: 0 auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); } h1 { text-align: center; color: #0d6efd; border-bottom: 2px solid #eee; padding-bottom: 10px; } .controls { display: grid; grid-template-columns: 1fr 1fr; gap: 40px; } .list-section h2 { color: #333; } .input-group { display: flex; gap: 10px; margin-bottom: 15px; } .input-group input { flex-grow: 1; padding: 10px; font-size: 16px; border: 1px solid #ccc; border-radius: 6px; } .input-group button { padding: 10px 15px; font-size: 16px; border: none; border-radius: 6px; color: #fff; cursor: pointer; transition: background-color 0.2s; } .btn-add-bl { background-color: #dc3545; } .btn-add-bl:hover { background-color: #bb2d3b; } .btn-add-wl { background-color: #198754; } .btn-add-wl:hover { background-color: #157347; } ul { list-style: none; padding: 0; max-height: 400px; overflow-y: auto; border: 1px solid #eee; border-radius: 6px; } li { display: flex; justify-content: space-between; align-items: center; padding: 12px; font-size: 16px; border-bottom: 1px solid #eee; } li:last-child { border-bottom: none; } li span { word-break: break-all; } .btn-remove { background-color: #6c757d; color: white; padding: 5px 10px; font-size: 12px; border: none; border-radius: 6px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Parental Controls</h1>
        <div class="controls">
            <div class="list-section">
                <h2>🚫 Blacklist (Blocked Sites)</h2>
                <form method="POST" class="input-group"> <input type="text" name="add_blacklist" placeholder="e.g., badsite.com" required> <button type="submit" class="btn-add-bl">Add</button> </form>
                <ul> {% for item in blacklist %} <li> <span>{{ item }}</span> <form method="POST" style="display:inline;"> <input type="hidden" name="remove_blacklist" value="{{ item }}"> <button type="submit" class="btn-remove">Remove</button> </form> </li> {% else %} <li style="color: #888;">No sites in this list.</li> {% endfor %} </ul>
            </div>
            <div class="list-section">
                <h2>✅ Whitelist (Allowed Sites)</h2>
                <form method="POST" class="input-group"> <input type="text" name="add_whitelist" placeholder="e.g., goodsite.com" required> <button type="submit" class="btn-add-wl">Add</button> </form>
                <ul> {% for item in whitelist %} <li> <span>{{ item }}</span> <form method="POST" style="display:inline;"> <input type="hidden" name="remove_whitelist" value="{{ item }}"> <button type="submit" class="btn-remove">Remove</button> </form> </li> {% else %} <li style="color: #888;">No sites in this list.</li> {% endfor %} </ul>
            </div>
        </div>
    </div>
</body>
</html>
"""

history_html = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"> <meta name="viewport" content="width=device-width, initial-scale=1.0"> <title>Browsing History</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f0f2f5; margin: 0; padding: 20px; color: #1c1e21; } .container { max-width: 1000px; margin: 0 auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); } h1 { text-align: center; color: #0d6efd; border-bottom: 2px solid #eee; padding-bottom: 10px; } table { width: 100%; border-collapse: collapse; margin-top: 20px; } table th, table td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; } table th { background-color: #f8f9fa; } table td { max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; } a { color: #0d6efd; text-decoration: none; } a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Browsing History</h1>
        <table>
            <thead> <tr><th>Title</th><th>URL</th><th>Time Visited</th></tr> </thead>
            <tbody>
                {% for item in history %}
                <tr>
                    <td>{{ item.title }}</td>
                    <td><a href="{{ item.url }}" title="{{ item.url }}">{{ item.url }}</a></td>
                    <td>{{ item.timestamp }}</td>
                </tr>
                {% else %}
                <tr><td colspan="3" style="text-align:center;">Your browsing history is empty.</td></tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</body>
</html>
"""

insights_base_html = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"> <meta name="viewport" content="width=device-width, initial-scale=1.0"> <title>AI Insights</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f0f2f5; margin: 0; padding: 20px; color: #1c1e21; } .container { max-width: 800px; margin: 0 auto; background: #fff; padding: 20px 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); } h1 { text-align: center; color: #6f42c1; border-bottom: 2px solid #eee; padding-bottom: 10px; } .loading { text-align: center; font-size: 18px; color: #666; } .content { margin-top: 20px; line-height: 1.6; } .content h2 { color: #0d6efd; } .content ul { list-style-position: inside; padding-left: 0; }
    </style>
</head>
<body> <div class="container"> <h1>🧠 AI-Powered Insights</h1> <div class="content">{{ content | safe }}</div> </div> </body>
</html>
"""

insights_loading_html = insights_base_html.replace("{{ content | safe }}", "<p class='loading'>Generating insights based on browsing history... Please wait, this may take a moment.</p>")

def write_html_files():
    # Now we can use the NEW_TAB_FILE constant directly, as it's a full path
    with open(NEW_TAB_FILE, "w", encoding="utf-8") as f:
        f.write(newtab_html)

def file_url(path):
    # This function is now simpler because 'path' is already an absolute path
    return QUrl.fromLocalFile(path)

def train_and_save_model():
    print("="*60, "\n⏳ Model file not found. Starting one-time training...\n", "="*60)
    try:
        df = pd.read_parquet("hf://datasets/tdavidson/hate_speech_offensive/data/train-00000-of-00001.parquet")
        df['Category'] = df['class'].map({0: "Hate Speech", 1: "Hate Speech", 2: "No Hate Speech"})
        df = df[['tweet', 'Category']]; df["tweet"] = df["tweet"].apply(standardize)
        x, y = np.asanyarray(df['tweet']), np.asanyarray(df['Category'])
        vec = CountVectorizer(); x = vec.fit_transform(x)
        x_train, _, y_train, _ = train_test_split(x, y, test_size=0.20, random_state=42)
        tree = DecisionTreeClassifier(criterion="entropy"); tree.fit(x_train, y_train)
        with open(MODEL_FILENAME, 'wb') as file: pickle.dump({'model': tree, 'vectorizer': vec}, file)
        print("\n✅ Model training and saving complete!\n", "="*60); return True
    except Exception as e: print(f"\n❌ An error occurred during model training: {e}"); return False

class BrowserTab(QWidget):
    textReadyForAnalysis = pyqtSignal(object, str)
    imagesReadyForAnalysis = pyqtSignal(list)
    page_visited = pyqtSignal(str, str)
    def __init__(self, url: str):
        super().__init__()
        layout = QVBoxLayout(self); layout.setContentsMargins(0,0,0,0)
        self.webview = QWebEngineView()
        self.webview.setUrl(QUrl(url))
        layout.addWidget(self.webview)
        self.webview.loadFinished.connect(self.on_load_finished)
        self.webview.titleChanged.connect(self._on_title_changed)
    def _on_title_changed(self, title):
        url = self.webview.url().toString()
        if title and url and not url.startswith(('file:', FLASK_SERVER_URL)): self.page_visited.emit(url, title)
    def on_load_finished(self):
        if self.webview.url().scheme() != 'file' and not self.webview.url().host() == '127.0.0.1':
            self.webview.page().toHtml(self.process_html)
    def process_html(self, html: str):
        soup = BeautifulSoup(html, 'html.parser')
        if body := soup.find('body'): self.textReadyForAnalysis.emit(self, body.get_text(separator=' ', strip=True))
        image_urls = [img.get('src') for img in soup.find_all('img') if img.get('src')]
        self.imagesReadyForAnalysis.emit(image_urls)
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SafeSurf")
        self.resize(1200, 750)
        self.history = []
        self.sites_blocked_session = 0
        self.ai_alerts_session = 0
        self.whitelist, self.blacklist = [], []
        self._load_parental_controls()
        self._load_history()
        self.ml_model, self.vectorizer = None, None
        self._load_ml_model()
        self.flask_thread = FlaskThread(self)
        self.flask_thread.controls_updated.connect(self._load_parental_controls)
        self.flask_thread.start()
        
        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.setCentralWidget(self.tabs)
        
        # --- TOOLBAR SETUP ---
        toolbar = QToolBar("Main Toolbar")
        self.addToolBar(toolbar)

        # --- NEW: Home Button ---
        home_btn = QAction("🏠", self)
        home_btn.triggered.connect(self.go_home)
        toolbar.addAction(home_btn)
        
        toolbar.addSeparator()

        self.urlbar = QLineEdit(placeholderText="Enter URL here...")
        self.urlbar.returnPressed.connect(self.navigate_to_url)
        toolbar.addWidget(self.urlbar)
        
        self.searchbar = QLineEdit(placeholderText="Search Google...")
        self.searchbar.returnPressed.connect(self.search_web)
        toolbar.addWidget(self.searchbar)
        
        toolbar.addSeparator()
        
        dash_btn = QPushButton("Dashboard")
        dash_btn.clicked.connect(self.open_dashboard)
        toolbar.addWidget(dash_btn)
        
        insights_btn = QPushButton("🧠 AI Insights")
        insights_btn.clicked.connect(self.open_ai_insights)
        toolbar.addWidget(insights_btn)
        
        # --- NEW: New Tab Button ---
        new_tab_btn = QAction("+", self)
        new_tab_btn.triggered.connect(lambda: self.add_new_tab(file_url(NEW_TAB_FILE).toString()))
        toolbar.addAction(new_tab_btn)
        
        self.add_new_tab(file_url(NEW_TAB_FILE).toString())

    # --- NEW: Go Home Method ---
    def go_home(self):
        """Navigates the current tab to the new tab page."""
        if current_tab := self.tabs.currentWidget():
            current_tab.webview.setUrl(file_url(NEW_TAB_FILE))

    def open_ai_insights(self):
        self.add_new_tab("about:blank")
        self.tabs.currentWidget().webview.setHtml(insights_loading_html)
        self.tabs.setTabText(self.tabs.currentIndex(), "AI Insights")
        self.insight_worker = AIInsightThread(self.history)
        self.insight_worker.insight_ready.connect(self._on_insight_ready)
        self.insight_worker.insight_error.connect(self._on_insight_error)
        self.insight_worker.start()

    def _on_insight_ready(self, insight_html):
        if current_tab := self.tabs.currentWidget():
            with self.flask_thread.app.app_context():
                final_html = render_template_string(insights_base_html, content=insight_html)
            current_tab.webview.setHtml(final_html)

    def _on_insight_error(self, error_html):
        if current_tab := self.tabs.currentWidget():
            with self.flask_thread.app.app_context():
                final_html = render_template_string(insights_base_html, content=error_html)
            current_tab.webview.setHtml(final_html)

    def _load_ml_model(self):
        if not os.path.exists(MODEL_FILENAME): return
        try:
            with open(MODEL_FILENAME, 'rb') as file:
                d = pickle.load(file)
                self.ml_model, self.vectorizer = d['model'], d['vectorizer']
            print("🧠 Hate speech model loaded.")
        except Exception as e:
            QMessageBox.critical(self, "Model Load Error", f"Could not load the model:\n{e}")
            
    def _load_parental_controls(self):
        try:
            with open(CONTROLS_FILENAME, 'r') as f:
                data = json.load(f)
                self.whitelist, self.blacklist = data.get('whitelist', []), data.get('blacklist', [])
        except (FileNotFoundError, json.JSONDecodeError):
            self.whitelist, self.blacklist = [], []
            with open(CONTROLS_FILENAME, 'w') as f:
                json.dump({'whitelist': [], 'blacklist': []}, f, indent=2)
        print(f"🔒 Parental controls (re)loaded: {len(self.blacklist)} blacklisted sites.")
        
    def _load_history(self):
        try:
            with open(HISTORY_FILENAME, 'r') as f:
                self.history = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.history = []
        print(f"📚 Loaded {len(self.history)} history items.")
        
    def _add_to_history(self, url, title):
        if self.history and self.history[-1]['url'] == url:
            return
        entry = { "url": url, "title": title, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S") }
        self.history.append(entry)
        with open(HISTORY_FILENAME, 'w') as f:
            json.dump(self.history, f, indent=2)
            
    def analyze_page_content(self, sender_tab, text: str):
        if not all([self.ml_model, self.vectorizer, text, sender_tab]): return
        if self.ml_model.predict(self.vectorizer.transform([standardize(text)]))[0] == "Hate Speech":
            self.ai_alerts_session += 1
            self.sites_blocked_session += 1
            QMessageBox.warning(self, "Harmful Content Detected", "⚠️ SafeSurf AI blocked this page for hateful language.")
            sender_tab.webview.setUrl(file_url(NEW_TAB_FILE))
            
    def analyze_page_images(self, image_urls: list):
        for url in image_urls:
            if analyze_image_for_nudity(url):
                self.ai_alerts_session += 1
                QMessageBox.critical(self, "Inappropriate Content", "⚠️ SafeSurf AI detected a potentially inappropriate image.")
                break
                
    def add_new_tab(self, url: str):
        tab = BrowserTab(url)
        idx = self.tabs.addTab(tab, "New Tab")
        self.tabs.setCurrentIndex(idx)
        tab.webview.urlChanged.connect(lambda qurl, t=tab: self.on_url_changed(t, qurl))
        tab.textReadyForAnalysis.connect(self.analyze_page_content)
        tab.imagesReadyForAnalysis.connect(self.analyze_page_images)
        tab.page_visited.connect(self._add_to_history)
        
    def on_url_changed(self, tab, qurl):
        current_url = qurl.toString()
        if tab == self.tabs.currentWidget():
            self.urlbar.setText(current_url)
        if qurl.scheme() == 'file' or qurl.host() == '127.0.0.1':
            return
        safe_url = file_url(NEW_TAB_FILE)
        for domain in self.blacklist:
            if domain in current_url:
                self.sites_blocked_session += 1
                QMessageBox.critical(self, "Blocked Site", f"Access to '{domain}' is blocked by parental controls.")
                tab.webview.setUrl(safe_url)
                return
        print(f"\nNavigated to: {current_url}\n  -> Performing security checks...")
        if gsb := check_google_safe_browsing(current_url):
            QMessageBox.critical(self, "Google Safe Browsing Warning", f"🚨 DANGER! Site flagged by Google for: **{gsb}**.")
            tab.webview.setUrl(safe_url)
            return
        if vt := check_virustotal(current_url):
            QMessageBox.critical(self, "VirusTotal Warning", f"🚨 DANGER! Site flagged by **{vt}** security vendors.")
            tab.webview.setUrl(safe_url)
            return
            
    def close_tab(self, index):
        if self.tabs.count() > 1:
            self.tabs.removeTab(index)
            
    def open_dashboard(self):
        self.add_new_tab(f"{FLASK_SERVER_URL}/")
        
    def navigate_to_url(self):
        text = self.urlbar.text().strip()
        if "://" not in text and "." in text:
            text = "https://" + text
        elif "://" not in text:
            self.searchbar.setText(text)
            self.search_web()
            return
        if cur := self.tabs.currentWidget():
            cur.webview.setUrl(QUrl(text))
            
    def search_web(self):
        if query := self.searchbar.text().strip():
            search_url = "https://www.google.com/search?q=" + query.replace(" ", "+")
            self.add_new_tab(search_url)


def main():
    if not os.path.exists(MODEL_FILENAME):
        if not train_and_save_model():
            sys.exit("Exiting due to model training failure.")
    app = QApplication(sys.argv)
    write_html_files()
    window = MainWindow()
    window.show()
    print("✅ SafeSurf Browser is now running.")
    sys.exit(app.exec())

if __name__ == "__main__":

    main()
