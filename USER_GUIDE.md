# Mini OSINT Toolkit: User Guide (Roman Urdu)

## 1. Install aur start
1. Python 3.10+ chahiye. Terminal mein folder kholein.
2. `pip install -r requirements.txt` (Flask, requests, python-whois, dnspython install hote hain).
3. `python app.py`, phir browser mein http://127.0.0.1:5000 kholein. (Windows: `start_windows.bat` double-click.)
4. **Pehle** `python app.py selftest` chalayein. Yeh aap ke internet par WHOIS, DNS, IP aur username check ek ek baar aazmata hai.
   Koi FAIL aaye to neeche "Masle" dekhein.

## 2. Istemal
1. **New investigation** banayein: title, apna naam, **authorization** (jaise "meri apni domain" ya "Acme ka likhit ijazat, ref SOW-12" ya "practice lab") aur tick.
2. Case ke andar 4 tabs: Domain (WHOIS), DNS records, IP address, Username. Target likh kar **Run lookup**.
3. Result neeche list mein aate hain, har result par observations (High / Warning / Note).
4. **View report** (screen par), **Download HTML** ya **Download Markdown**. PDF ke liye report page par "Print / Save as PDF".
5. Analyst notes likh kar save karein, report mein aa jate hain.

## 3. Practice ke liye safe targets
- Domain: `example.com`, `example.org`, ya aap ki apni domain.
- IP: `1.1.1.1`, `8.8.8.8` (public DNS servers).
- Username: `github`, apna khud ka username.
- Kisi aam insaan ka username ya domain ijazat ke baghair mat daalein.

## 4. Test checklist
| Test | Kya hona chahiye |
|---|---|
| `192.168.1.1` ya `127.0.0.1` IP tab mein | Refuse, lookup nahi hota |
| `localhost` domain mein | Refuse |
| `https://Example.com/page` domain mein | Saaf `example.com` ban jata hai |
| Wohi domain dobara | "reused" likha aata hai (cache) |
| Username tab mein 7 baar lagatar | Rate limit ka paigham |
| Authorization khali ya tick nahi | Case nahi banta |
| Notes mein `<script>alert(1)</script>` | Report mein sirf text dikhta hai |
| Download HTML aur Markdown | Dono khulte hain, sab results maujood |

## 5. Natijon ko kaise samjhein
- **Username: found / not found / unsure.** Unsure ka matlab site ne bot roka ya login maanga. Haath se link khol kar check karein. Instagram, TikTok, X aksar unsure aate hain.
- **WHOIS "privacy hidden":** zyada tar domains ka owner naam chhupa hota hai, yeh normal hai.
- **IP geolocation:** andaza hai, aksar provider ka sheher hota hai, user ka nahi.
- **DNS observations:** SPF/DMARC na hona email spoofing ka khatra batata hai. Yeh sirf ishara hai, faisla nahi.

## 6. Masle
- **pip install fail:** `python -m pip install -r requirements.txt` try karein.
- **WHOIS FAIL:** office/college network par port 43 band hota hai. Tool khud RDAP par chala jata hai (selftest mein "RDAP only" dekhein).
- **Sab kuch FAIL:** internet, VPN ya firewall check karein.
- **Port 5000 busy:** `python app.py serve --port 5050`.
- **Data kahan:** `instance/osint.db` (SQLite). Is file ko delete karne se sab investigations mit jati hain.

## 7. Qanooni baat
Sirf public information, aur sirf apne ya ijazat wale targets. Dusron ki private maloomat jama karna ya kisi ko tang karna jurm ho sakta hai.
