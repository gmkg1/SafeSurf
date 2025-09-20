SafeSurf: AI-Powered Safety Browser 🕵️‍♀️
SafeSurf is a Python-based web browser built with PyQt6 and Flask, designed for child safety. It includes features to protect users from malicious and inappropriate content, giving parents a clear overview of their child's online activity.

✨ Features
Parental Controls: Easily add websites to a blacklist to block them or a whitelist to restrict browsing to only approved sites.

Hate Speech Detection: An integrated machine learning model analyzes page content in real-time, blocking pages flagged for hateful or offensive language.

Real-time Threat Protection: Uses Google Safe Browsing and VirusTotal APIs to check URLs for malware, phishing, and other security threats before a page loads.

AI-Powered Insights: A dedicated dashboard uses the Google Gemini API to analyze browsing history and provide parents with friendly, actionable insights into their child's online interests and activity.

Local Web Dashboard: A built-in web server (via Flask) provides a user-friendly dashboard to manage parental controls, view browsing history, and see security alerts.

Inappropriate Image Detection: (Conceptual) The browser includes a function to analyze image URLs for nudity, providing an alert if potentially inappropriate images are detected.

🛠️ Installation
Clone the repository:

Bash

git clone https://github.com/your-username/safesurf.git
cd safesurf
Create and activate a virtual environment:

Bash

python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
Install the required libraries:

Bash

pip install PyQt6 PyQt6-WebEngine Flask beautifulsoup4 nltk scikit-learn pandas numpy pyarrow requests google-generativeai
Download NLTK data:
Run the following Python code once to download the necessary NLTK stopwords:

Bash

python -c "import nltk; nltk.download('stopwords')"
Obtain API Keys:
For full functionality, you need to replace the placeholder API keys in the main.py file with your own:

Google Safe Browsing API Key: For real-time threat checks.

Google Gemini API Key: For AI-powered insights.

VirusTotal API Key: For additional URL security analysis.

🚀 Usage
Train the ML Model:
The first time you run the application, it will automatically download a public dataset, train the hate speech detection model, and save it as hate_speech_model.pkl. This may take a few minutes.

Run the browser:

Bash

python3 main.py
Access the Dashboard:
Open a new tab in the SafeSurf browser and navigate to http://127.0.0.1:5000 to access the main dashboard. From here, you can manage parental controls and view activity logs.

How to Use:

URL Bar: Type a full URL (e.g., https://example.com) and press Enter to navigate.

Search Bar: Type a search query and press Enter to search on Google.

Dashboard Button: Opens the web dashboard for administrative tasks.

AI Insights Button: Generates and displays a report on recent browsing activity.
