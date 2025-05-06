# Burp-request-change-hydra

## Purpose:
Generate a Hydra command to perform a form-based brute-force login attack using a HTTP request captured by Burp Suite.

## 🔧 Features:
Parses HTTP request from a Burp Suite export file.

Automatically detects username and password fields in the POST body.

Infers whether the request is HTTP or HTTPS.

Constructs a hydra command using the appropriate syntax.

## 🧠 How It Works:
Reads a raw HTTP request file.

Extracts:

Method (GET or POST)

Path

Host

POST body parameters

Replaces username/password fields with Hydra placeholders ^USER^ and ^PASS^.

Outputs a complete hydra command.

## 📌 Usage:
bash
Copy
Edit
python burp2hydra.py <burp_request.txt>
Example:

bash
Copy
Edit
python burp2hydra.py login_request.txt

## ⚠️ Notes:
The script uses a default failure string of "Invalid" – replace it based on the target's actual login error response.

Only POST requests are fully supported. GET requests are parsed but may require manual adjustment.

Username and password parameter names are guessed using common keys (username, user, password, etc.).
