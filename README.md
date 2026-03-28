# WAFY - Infinite Protection, Intelligent Detection

**WAFY** is an Advanced Web Application Firewall (WAF) that protects web applications from known threats such as SQL injection, Cross-Site Scripting (XSS), and other similar attacks by filtering and monitoring HTTP traffic between the application and the Internet.

In addition to signature-based detection, it uses **machine learning-based anomaly detection** to identify obfuscated, zero-day, and previously unknown attacks by analyzing patterns and behaviors in incoming requests.

## **How it works**

![WAF Flow](https://github.com/user-attachments/assets/ab066405-d83d-43ce-801e-269eb44bd2f0)



## Features

- 🚫 Block Known Web Attacks
- 🤖 AI-powered threat detection
- 🛡️ Real-time Request Analysis
- ✨ Modern, Responsive UI
- 📊 Interactive Security Insights
- 🚀 Fast response time


##  Output Screenshots

<img width="1366" height="637" alt="waf-ss1" src="https://github.com/user-attachments/assets/d505be17-9b50-4a8d-9c3e-53bcc998ebcf" />
<img width="1362" height="601" alt="waf-ss2" src="https://github.com/user-attachments/assets/0da870a7-f0e6-472f-9671-29f4ae79954f" />
<img width="1366" height="639" alt="waf-ss3" src="https://github.com/user-attachments/assets/21ecb613-4347-4932-bd42-9ea6dedff530" />
<img width="1366" height="639" alt="waf-ss4" src="https://github.com/user-attachments/assets/54c5564c-7ab0-4709-a594-c4175e92e868" />
<img width="1366" height="639" alt="waf-ss5" src="https://github.com/user-attachments/assets/f466b68e-9767-4c2c-a2a0-3d871a9ae0df" />
<img width="1366" height="639" alt="waf-ss6" src="https://github.com/user-attachments/assets/2a356dea-0613-4f83-90b9-4b29fb98c3f1" />



## Tech Stack

- Python/Flask
- JavaScript
- HTML/CSS
- Machine Learning

## 🧪 Example Requests
### ✅ Valid Requests

**1. Homepage**
```
GET / HTTP/1.1
Host: www.example.com
```

**2. Product listing**
```
GET /products?category=electronics&page=2 HTTP/1.1
Host: www.ecommerce.com
Referer: https://www.ecommerce.com/products
```

**3. Single product**
```
GET /product/12345 HTTP/1.1
Host: www.ecommerce.com
Referer:https://www.ecommerce.com/products?category=electronics&page=2
```

**4. Add to cart (POST with JSON body)**
```
POST /cart/add HTTP/1.1
Host: www.ecommerce.com
Content-Type: application/json
Content-Length: 45

{"productId": "12345", "quantity": 1}
```

### ❌Signature-Based Detection (Malicious Input)

**1. SQL Injection via search**
```
GET /search?q=' OR '1'='1'; DROP TABLE users;-- HTTP/1.1
Host: www.example.com
```

**2. XSS in comment**
```
GET /comment?text=<script>alert('XSS')</script> HTTP/1.1
Host: www.example.com
```

**3. XSS using eval**
```
GET /comment?text=<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script> HTTP/1.1
Host: www.example.com
```

**4. SQL Injection with UNION**
```
GET /search?q=1' UNION SELECT username,password FROM users-- HTTP/1.1
Host: www.example.com
```

### 🚨  ML-based Anomaly Detection (Obfuscated Malicious Input/Encoded Attacks)

**1. URL-encoded SQLi**
```
GET /search?q=%27%20OR%20%271%27%3D%271 HTTP/1.1
Host: www.example.com
```

**2. Hex-encoded SQLi**
```
GET /search?q=\x27\x20OR\x20\x31\x3D\x31 HTTP/1.1
Host: www.example.com
```

**3. Obscure HTML Elements + JS Access**
```
GET /comment?text=<details%20open%20ontoggle=Function('ale'+'rt(1)')()> HTTP/1.1
```

**4. Encoded XSS**
```
GET /comment?text=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E HTTP/1.1
Host: www.example.com
```

## 🛠️Setup

1. Clone the repository:

bash
```
git clone https://github.com/AkhilSharmaCyber/WAFY-Advanced-WAF.git
```
```
cd WAFY-Advanced-WAF
```

2. Install dependencies:

bash
```
pip install -r requirements.txt
```

3. Run the application:

bash
```
python app.py
```

## License

MIT License
" > README.md

## Add and commit README
git add README.md
git commit -m "Add README.md"
git push
