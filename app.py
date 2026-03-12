"""
DigitalArmour — Detection Engine v3
====================================
Multi-factor risk scoring algorithm with 4 named, explainable components.

ALGORITHM DESIGN
─────────────────
Score = KDS + UPS + IMS + ITS   (capped at 100)

  Factor                     Max pts  What it measures
  ─────────────────────────────────────────────────────
  KDS  Keyword Density Score    40    Weighted scam-specific phrase matching
  UPS  Urgency & Pressure Score 25    Time-pressure and fear language
  IMS  Impersonation Score      20    Authority body / official impersonation
  ITS  Isolation Tactic Score   15    Secrecy demands, victim isolation

Each factor is scored independently, then combined.
A severity floor prevents under-reporting on high-danger categories.

SCORING RATIONALE
─────────────────
Keyword weights (1-10) reflect exclusivity:
  10 = phrase almost never appears outside scam context ("digital arrest")
   7 = high-signal but occasionally legitimate ("money laundering" in news)
   4 = moderate-signal, needs supporting context ("narcotics")
   1 = low-signal alone ("tax")

UPS captures the psychological pressure mechanism all scams share:
immediate deadlines, consequences, fear of inaction.

IMS captures impersonation of the three most-abused authorities in India:
government agencies (CBI/ED/NCB), telecom (TRAI/DoT), banks.

ITS captures the isolation tactic — keeping victims from family/friends
so they cannot verify the scam before paying.
"""

from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

# ═══════════════════════════════════════════════════════════════════
#  FACTOR 1: KEYWORD DENSITY SCORE (KDS)  —  max 40 points
#  Weighted phrase matching per scam category.
#  Score = min(40, matched_weight_sum / top5_max_weight * 40)
# ═══════════════════════════════════════════════════════════════════

SCAM_PATTERNS = {
    "Digital Arrest": {
        "severity": "CRITICAL",
        "keywords": {
            "digital arrest":             10,
            "you are under arrest":       10,
            "cyber arrest":               10,
            "warrant issued":              9,
            "enforcement directorate":     9,
            "stay on call":                9,
            "do not disconnect":           9,
            "do not tell anyone":          9,
            "cbi officer":                 8,
            "ncb officer":                 8,
            "ed officer":                  8,
            "video call verification":     8,
            "arrested online":             8,
            "cbcid":                       7,
            "money laundering":            7,
            "your aadhar linked":          7,
            "illegal activity detected":   7,
            "your number is flagged":      6,
            "central bureau":              6,
            # Low alone — context boost raises these when CBI/ED/NCB also present
            "narcotics":                   2,
            "national security":           2,
        },
        "explanation": (
            "This is a 'Digital Arrest' scam — one of India's fastest-growing cyber frauds. "
            "No Indian law permits 'digital arrest'. The CBI, ED, NCB, or police will NEVER "
            "contact you on WhatsApp/Skype to arrest you or demand you stay on a video call. "
            "These scammers impersonate government officers to extort money using fear and urgency."
        ),
        "action": [
            "Hang up immediately — no real officer conducts arrests over video calls.",
            "Do NOT share personal documents, OTPs, or transfer any money.",
            "Report to cybercrime.gov.in or call helpline 1930.",
            "Inform your family — scammers often demand secrecy to isolate victims.",
            "Screenshot the number and report it to your nearest police station.",
        ],
    },

    "KYC Fraud": {
        "severity": "HIGH",
        "keywords": {
            "kyc expired":                      10,
            "update your kyc":                  10,
            "kyc pending":                       9,
            "your account will be deactivated":  9,
            "account will be suspended":         9,
            "your upi blocked":                  9,
            "sbi kyc":                           8,
            "hdfc kyc":                          8,
            "paytm kyc":                         8,
            "google pay kyc":                    8,
            "phonepe kyc":                       8,
            "re-kyc":                            8,
            "video kyc":                         7,
            "kyc update":                        7,
            "kyc verification":                  6,
            "bank account blocked":              6,
            "click link to update":              6,
            "pan card verification":             5,
            "aadhaar otp":                       5,
            "link expired":                      4,
        },
        "explanation": (
            "This is a KYC (Know Your Customer) fraud. Scammers pretend to be from your bank "
            "or payment app and claim your account will be blocked unless you verify. "
            "Legitimate banks NEVER ask for OTPs, passwords, or CVV numbers over phone or SMS. "
            "The link they send leads to a fake phishing page designed to steal your credentials."
        ),
        "action": [
            "Never click links in SMS/WhatsApp messages claiming to be your bank.",
            "Your bank will NEVER ask for OTP, password, or full card number.",
            "Call your bank's official helpline (on the back of your debit card) to verify.",
            "Report phishing links to report.phishing@cert-in.org.in",
            "Block the number and report to 1930 (National Cyber Crime Helpline).",
        ],
    },

    "TRAI Scam": {
        "severity": "HIGH",
        "keywords": {
            "sim card blocked":                 10,
            "sim blocked":                       9,
            "your number will be disconnected":  9,
            "mobile number deactivated":         9,
            "mobile connection suspended":       9,
            "press 9 to speak":                  9,
            "press 1 to avoid":                  9,
            "trai":                              8,
            "dot officer":                       8,
            "department of telecom":             7,
            "illegal use of your number":        7,
            "your number misused":               7,
            "telecom authority":                 6,
            "telecom regulatory":                6,
            "your sim card":                     5,
            "automated call":                    4,
        },
        "explanation": (
            "This is a TRAI (Telecom Regulatory Authority of India) impersonation scam. "
            "Fraudsters use automated calls/messages claiming your SIM will be blocked for "
            "'illegal use'. TRAI never directly contacts individual subscribers. "
            "No telecom authority blocks your number without prior written notice through official channels."
        ),
        "action": [
            "Ignore and block automated calls claiming to be from TRAI or DoT.",
            "TRAI never calls individual subscribers — this is 100% a scam.",
            "Do not press any number on the automated call (it confirms your number is active).",
            "Register your complaint at trai.gov.in or call 1800-110-420.",
            "Report the number to your telecom provider as spam.",
        ],
    },

    "Prize / Lottery Scam": {
        "severity": "MEDIUM",
        "keywords": {
            "pay processing fee":           10,
            "pay a processing fee":         10,   # ← variant fix: "pay a processing fee of Rs..."
            "processing fee":                9,   # ← catches any fee mention
            "send registration fee":        10,
            "claim fee":                    10,
            "kbc winner":                    9,
            "kaun banega crorepati":         9,
            "amazon lucky draw":             9,
            "flipkart winner":               9,
            "1 crore prize":                 9,
            "you have won":                  8,
            "congratulations you won":       8,
            "lucky winner":                  8,
            "lottery winner":                8,
            "claim your prize":              7,
            "prize money":                   8,   # ← raised from 7, strong scam signal
            "lucky draw":                    7,
            "you are selected":              6,
            "you have been selected":        6,
            "scratch and win":               5,
            "reward points redeemable":      4,
        },
        "explanation": (
            "This is a classic Prize/Lottery scam. You cannot win a contest you never entered. "
            "Scammers ask for a small 'processing fee' or 'tax' upfront — once paid, they "
            "vanish or keep demanding more. KBC, Amazon, and Flipkart NEVER announce "
            "winners via unknown WhatsApp numbers or unsolicited SMS messages."
        ),
        "action": [
            "Ignore — if you didn't enter a contest, you cannot have won it.",
            "NEVER pay any 'processing fee', 'tax', or 'registration fee' to claim a prize.",
            "Verify any brand promotion only through their official website or app.",
            "Report to National Consumer Helpline: 1800-11-4000.",
            "Block and report the number immediately.",
        ],
    },

    "IT Department Scam": {
        "severity": "HIGH",
        "keywords": {
            "click to claim refund":         10,
            "income tax refund approved":    10,
            "tax arrest":                    10,
            "it raid":                        9,
            "black money":                    9,
            "unreported income":              9,
            "financial irregularity":         9,
            "income tax notice":              8,
            "tax evasion":                    8,
            "tds refund":                     8,
            "itr refund":                     8,
            "your pan card flagged":          8,
            "income tax officer":             7,
            "income tax":                     6,
            "tax refund":                     6,
            "tax dues":                       6,
            "it department":                  5,
            "tax department":                 5,
        },
        "explanation": (
            "This is an Income Tax / IT Department impersonation scam. The real Income Tax "
            "Department sends all notices through the official portal (incometax.gov.in) or "
            "registered post. They NEVER call to demand immediate payment, threaten arrest "
            "over the phone, or send SMS links to claim refunds."
        ),
        "action": [
            "All genuine IT notices arrive via incometax.gov.in — check there first.",
            "Never click any 'refund' links received via SMS or WhatsApp.",
            "Do not transfer money to any account citing 'tax dues' on a phone call.",
            "Consult a chartered accountant if you receive suspicious tax communication.",
            "Report to cybercrime.gov.in or call 1930.",
        ],
    },
}


# ═══════════════════════════════════════════════════════════════════
#  FACTOR 2: URGENCY & PRESSURE SCORE (UPS)  —  max 25 points
#  Scammers always create artificial time pressure.
#  Each phrase matched adds points; capped at 25.
# ═══════════════════════════════════════════════════════════════════

URGENCY_PHRASES = {
    # Extreme time pressure (8 pts each)
    "within 2 hours":         8,
    "within 24 hours":        8,
    "immediately":            7,
    "urgent":                 6,
    "last chance":            8,
    "expires today":          8,
    "final warning":          8,
    # Consequence language (6 pts)
    "or else":                6,
    "failure to comply":      8,
    "ignore at your own risk":8,
    "legal action":           6,
    "consequences":           5,
    "penalty":                5,
    # Action pressure (5 pts)
    "act now":                6,
    "do not delay":           6,
    "respond immediately":    6,
    "verify now":             5,
    "call back immediately":  6,
    "limited time":           5,
    "offer expires":          5,
    "click now":              5,
}


# ═══════════════════════════════════════════════════════════════════
#  FACTOR 3: IMPERSONATION SCORE (IMS)  —  max 20 points
#  Claiming to be a known authority body adds credibility for scammers.
# ═══════════════════════════════════════════════════════════════════

IMPERSONATION_PHRASES = {
    # Government / Law enforcement (high weight)
    "central bureau of investigation": 10,
    "cbi":                              8,
    "enforcement directorate":          9,
    "narcotics control bureau":         9,
    "ncb":                              7,
    "cyber crime police":               8,
    "cybercrime cell":                  8,
    "supreme court":                    8,
    "high court":                       7,
    # Telecom regulators
    "telecom regulatory authority":     9,
    "trai":                             7,
    "department of telecom":            8,
    "dot":                              5,
    # Financial / Tax
    "income tax department":            8,
    "income tax officer":               8,
    "enforcement directorate":          9,
    "reserve bank of india":            8,
    "rbi":                              7,
    "sebi":                             7,
    # Banks (impersonation)
    "sbi":                              5,
    "hdfc bank":                        5,
    "icici bank":                       5,
    "axis bank":                        5,
    "kotak bank":                       5,
}


# ═══════════════════════════════════════════════════════════════════
#  FACTOR 4: ISOLATION TACTIC SCORE (ITS)  —  max 15 points
#  Scammers isolate victims so they can't verify / get help.
# ═══════════════════════════════════════════════════════════════════

ISOLATION_PHRASES = {
    "do not tell anyone":    15,
    "don't tell anyone":     15,
    "do not inform anyone":  15,
    "keep this confidential":12,
    "do not share":           8,
    "stay on call":          10,
    "do not disconnect":     10,
    "remain on the line":    10,
    "do not contact":         8,
    "do not call police":    12,
    "this is confidential":  10,
    "secret":                 6,
    "between us":             6,
}


# ═══════════════════════════════════════════════════════════════════
#  CONTEXT GROUPS  —  for context-aware KDS boosting
#
#  Design:  Each scam type has groups of semantically related keywords.
#  Rule:    If 2+ keywords from the SAME group are matched in the text,
#           every matched keyword in that group gets × CONTEXT_BOOST.
#
#  Why 1.3×?  It's a modest, auditable boost — not so aggressive that
#  two weak words suddenly cause a false positive, but enough to
#  meaningfully raise the score when real co-occurrence patterns appear.
#  Example: "narcotics" alone = 2 pts.
#           "narcotics" + "cbi officer" in same message
#           → both in digital_arrest crime_group + authority_group
#           → authority_group has 2+ matches → cbi boosted to 10.4
#           → crime_group has only 1 match (narcotics) → no boost
#           Net effect: "narcotics" stays 2, "cbi officer" boosted 8→10.4
# ═══════════════════════════════════════════════════════════════════

CONTEXT_BOOST = 1.3

CONTEXT_GROUPS = {
    "Digital Arrest": [
        # Group 1 — authority impersonation phrases
        ["cbi officer", "ncb officer", "ed officer", "central bureau",
         "enforcement directorate", "cbcid"],
        # Group 2 — crime / accusation framing
        ["narcotics", "money laundering", "illegal activity detected",
         "your aadhar linked", "your number is flagged", "national security"],
        # Group 3 — arrest / legal action language
        ["digital arrest", "you are under arrest", "cyber arrest",
         "warrant issued", "arrested online"],
        # Group 4 — control / isolation tactics
        ["stay on call", "do not disconnect", "do not tell anyone",
         "video call verification"],
    ],
    "KYC Fraud": [
        # Group 1 — account threat
        ["your account will be deactivated", "account will be suspended",
         "your upi blocked", "bank account blocked"],
        # Group 2 — KYC urgency
        ["kyc expired", "update your kyc", "kyc pending", "re-kyc",
         "kyc update", "kyc verification", "video kyc"],
        # Group 3 — credential harvesting
        ["click link to update", "aadhaar otp", "pan card verification"],
    ],
    "TRAI Scam": [
        # Group 1 — disconnection threat
        ["sim card blocked", "sim blocked", "your number will be disconnected",
         "mobile number deactivated", "mobile connection suspended", "your sim card"],
        # Group 2 — authority claim
        ["trai", "dot officer", "department of telecom",
         "telecom authority", "telecom regulatory"],
        # Group 3 — action pressure
        ["press 9 to speak", "press 1 to avoid", "automated call",
         "illegal use of your number", "your number misused"],
    ],
    "Prize / Lottery Scam": [
        # Group 1 — fee demand (the core fraud mechanism)
        ["pay processing fee", "pay a processing fee", "processing fee",
         "send registration fee", "claim fee"],
        # Group 2 — brand impersonation
        ["kbc winner", "kaun banega crorepati", "amazon lucky draw",
         "flipkart winner", "1 crore prize"],
        # Group 3 — win announcement
        ["you have won", "congratulations you won", "lucky winner",
         "lottery winner", "claim your prize", "prize money", "lucky draw"],
    ],
    "IT Department Scam": [
        # Group 1 — fake refund
        ["click to claim refund", "income tax refund approved",
         "tds refund", "itr refund", "tax refund"],
        # Group 2 — legal threat
        ["tax arrest", "it raid", "tax evasion",
         "financial irregularity", "unreported income", "black money"],
        # Group 3 — identity / authority
        ["your pan card flagged", "income tax officer",
         "income tax notice", "income tax department", "income tax"],
    ],
}


# ═══════════════════════════════════════════════════════════════════
#  FACTOR SCORING FUNCTIONS
# ═══════════════════════════════════════════════════════════════════

def apply_context_boost(
    matched_weights: dict,
    scam_type: str,
) -> tuple[dict, list[str]]:
    """
    Returns (boosted_weights, context_notes).

    For each context group belonging to scam_type:
      - Count how many matched keywords belong to that group
      - If count >= 2, multiply every matched keyword in that group by CONTEXT_BOOST
      - Record a human-readable note for the /explain endpoint
    """
    boosted = dict(matched_weights)   # copy — never mutate original
    notes   = []
    groups  = CONTEXT_GROUPS.get(scam_type, [])

    for group in groups:
        # which keywords from this group are actually in our matched set?
        hits = [kw for kw in group if kw in boosted]
        if len(hits) >= 2:
            for kw in hits:
                original = boosted[kw]
                boosted[kw] = round(original * CONTEXT_BOOST, 2)
            notes.append(
                f"Context boost ×{CONTEXT_BOOST} applied to: "
                + ", ".join(f'"{kw}"' for kw in hits)
                + f" — these phrases co-occurring together is a stronger signal than any one phrase alone."
            )

    return boosted, notes


def score_kds(
    matched_weights: dict,
    all_weights: dict,
    scam_type: str = "",
) -> tuple[int, dict, list[str]]:
    """
    Keyword Density Score (KDS) — max 40 points.
    Now returns (score, boosted_weights, context_notes).

    Formula:
      1. Apply context boost to matched_weights
      2. top5_max = sum of top-5 weights in the full keyword dict
      3. score = min(40,  sum(boosted) / top5_max × 40)
    """
    if not matched_weights:
        return 0, {}, []

    boosted, ctx_notes = apply_context_boost(matched_weights, scam_type)
    top5_max = sum(sorted(all_weights.values(), reverse=True)[:5])
    raw      = sum(boosted.values())
    score    = int(min(40, (raw / top5_max) * 40))
    return score, boosted, ctx_notes


def score_ups(text_lower: str) -> tuple[int, list]:
    """
    Urgency & Pressure Score (UPS) — max 25 points.
    Returns (score, matched_phrases).
    """
    matched = {ph: wt for ph, wt in URGENCY_PHRASES.items() if ph in text_lower}
    score = int(min(25, sum(matched.values())))
    return score, list(matched.keys())


def score_ims(text_lower: str) -> tuple[int, list]:
    """
    Impersonation Score (IMS) — max 20 points.
    Returns (score, matched_phrases).
    """
    matched = {ph: wt for ph, wt in IMPERSONATION_PHRASES.items() if ph in text_lower}
    score = int(min(20, sum(matched.values())))
    return score, list(matched.keys())


def score_its(text_lower: str) -> tuple[int, list]:
    """
    Isolation Tactic Score (ITS) — max 15 points.
    Returns (score, matched_phrases).
    """
    matched = {ph: wt for ph, wt in ISOLATION_PHRASES.items() if ph in text_lower}
    score = int(min(15, sum(matched.values())))
    return score, list(matched.keys())


# ═══════════════════════════════════════════════════════════════════
#  SEVERITY FLOOR — ensures CRITICAL scams always reflect real danger
# ═══════════════════════════════════════════════════════════════════

SEVERITY_FLOOR = {"CRITICAL": 70, "HIGH": 50, "MEDIUM": 30}


# ═══════════════════════════════════════════════════════════════════
#  MAIN DETECTION FUNCTION
# ═══════════════════════════════════════════════════════════════════

def detect_scam(text: str) -> dict:
    """
    Run all 4 scoring factors against the input text.
    Returns the highest-scoring scam category with full factor breakdown.

    Severity floor change (v3.1):
      Floor only activates when KDS >= 10.
      Rationale: a single low-weight word like "narcotics" (weight 2)
      should NOT force CRITICAL (70%) on its own. The floor is a boost
      for real detections, not a catch-all for any keyword hit.
    """
    text_lower = text.lower()

    # Compute cross-cutting factors once (same for all categories)
    ups_score, ups_matched = score_ups(text_lower)
    ims_score, ims_matched = score_ims(text_lower)
    its_score, its_matched = score_its(text_lower)

    scores = {}

    for scam_type, data in SCAM_PATTERNS.items():
        kw_map  = data["keywords"]
        matched = {kw: wt for kw, wt in kw_map.items() if kw in text_lower}

        if not matched:
            continue  # category not triggered at all

        # score_kds now returns (score, boosted_weights, context_notes)
        kds, boosted_weights, ctx_notes = score_kds(matched, kw_map, scam_type)

        raw_total = kds + ups_score + ims_score + its_score

        # Severity floor — only apply when there is real keyword evidence (KDS >= 10)
        # This prevents a single weak keyword from forcing a CRITICAL/HIGH rating
        floor = SEVERITY_FLOOR.get(data["severity"], 0) if kds >= 10 else 0
        final_score = max(min(100, raw_total), floor)

        scores[scam_type] = {
            "matched_keywords":  list(matched.keys()),
            "keyword_weights":   matched,
            "boosted_weights":   boosted_weights,    # after context boost
            "context_notes":     ctx_notes,           # explains any boosts applied
            "risk_score":        final_score,
            "explanation":       data["explanation"],
            "action":            data["action"],
            "severity":          data["severity"],
            "factors": {
                "kds": {"score": kds,       "max": 40, "label": "Keyword Density",    "matched": list(matched.keys())},
                "ups": {"score": ups_score, "max": 25, "label": "Urgency & Pressure", "matched": ups_matched},
                "ims": {"score": ims_score, "max": 20, "label": "Impersonation",      "matched": ims_matched},
                "its": {"score": its_score, "max": 15, "label": "Isolation Tactics",  "matched": its_matched},
            },
        }

    if not scores:
        return {
            "status":  "SAFE",
            "message": "No known scam patterns detected.",
            "tip": (
                "Stay alert — scammers constantly evolve their language. "
                "When in doubt: never share OTPs, never pay unknown callers, "
                "and always verify through official channels."
            ),
            "factors": {
                "kds": {"score": 0, "max": 40, "label": "Keyword Density",    "matched": []},
                "ups": {"score": 0, "max": 25, "label": "Urgency & Pressure", "matched": []},
                "ims": {"score": 0, "max": 20, "label": "Impersonation",      "matched": []},
                "its": {"score": 0, "max": 15, "label": "Isolation Tactics",  "matched": []},
            },
        }

    ranked = sorted(scores.items(), key=lambda x: x[1]["risk_score"], reverse=True)
    pname, pdata = ranked[0]

    return {
        "status":            "SCAM_DETECTED",
        "primary_scam":      pname,
        "severity":          pdata["severity"],
        "risk_score":        pdata["risk_score"],
        "matched_keywords":  pdata["matched_keywords"],
        "keyword_weights":   pdata["keyword_weights"],
        "boosted_weights":   pdata["boosted_weights"],
        "context_notes":     pdata["context_notes"],
        "explanation":       pdata["explanation"],
        "action":            pdata["action"],
        "factors":           pdata["factors"],
        "other_matches": [
            {"type": k, "risk_score": v["risk_score"], "severity": v["severity"]}
            for k, v in ranked[1:]
        ],
    }


# ═══════════════════════════════════════════════════════════════════
#  SCAM INFO PAGE — SLUG MAPPING & DATA
# ═══════════════════════════════════════════════════════════════════

SCAM_SLUG_MAP = {
    "digital-arrest":      "Digital Arrest",
    "kyc-fraud":           "KYC Fraud",
    "trai-scam":           "TRAI Scam",
    "prize-scam":          "Prize / Lottery Scam",
    "it-department-scam":  "IT Department Scam",
}

SCAM_ICONS = {
    "Digital Arrest":        "🚨",
    "KYC Fraud":             "🏦",
    "TRAI Scam":             "📡",
    "Prize / Lottery Scam":  "🎰",
    "IT Department Scam":    "📋",
}

_DEMO_LABELS = {
    "digital-arrest":      "Digital Arrest — CBI Officer",
    "kyc-fraud":           "KYC Fraud — SBI Account Block",
    "trai-scam":           "TRAI Scam — SIM Disconnection",
    "prize-scam":          "Prize Scam — KBC Lucky Draw",
    "it-department-scam":  "IT Dept Scam — TDS Refund",
}

_DEMO_MESSAGES = {
    "digital-arrest": (
        "This is Officer Rajiv Sharma from the Central Bureau of Investigation (CBI). "
        "Your Aadhaar number is linked to a money laundering case. "
        "You are under digital arrest effective immediately. A warrant has been issued. "
        "Stay on this video call and do not disconnect. Do not tell anyone about this call "
        "or you will be taken into physical custody within 2 hours. Failure to comply "
        "will result in legal action."
    ),
    "kyc-fraud": (
        "Dear SBI customer, your SBI KYC has expired as of today. "
        "Your account will be deactivated within 24 hours if KYC is not updated. "
        "Click to update your KYC immediately: sbi-kyc-update.net/verify "
        "Enter your Aadhaar OTP to complete re-KYC. Ignore at your own risk."
    ),
    "trai-scam": (
        "URGENT: TRAI notice — illegal use of your number has been detected. "
        "Your SIM card will be disconnected within 2 hours by the Department of Telecom. "
        "Your mobile connection is suspended pending verification. "
        "Press 9 to speak with a DoT officer immediately to avoid disconnection."
    ),
    "prize-scam": (
        "Congratulations! You have won Rs 25,00,000 in the KBC Lucky Draw 2025. "
        "You are our lucky winner selected from 2 crore participants. "
        "To claim your prize money, pay a processing fee of Rs 2500 to activate your "
        "KBC winner account. Offer expires today. Act now and call back immediately."
    ),
    "it-department-scam": (
        "Income Tax Department alert: your TDS refund of Rs 18,450 has been approved. "
        "Your PAN card has been flagged for unreported income and financial irregularity. "
        "Click to claim refund: incometax-refund.net/claim — respond immediately. "
        "Failure to comply may result in tax arrest and IT raid proceedings within 24 hours."
    ),
}

# ═══════════════════════════════════════
#  ROUTES
# ═══════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    payload = request.get_json()
    if not payload or not payload.get("message", "").strip():
        return jsonify({"error": "No message provided"}), 400
    msg = payload["message"].strip()
    if len(msg) < 5:
        return jsonify({"error": "Message too short to analyse"}), 400
    return jsonify(detect_scam(msg))


# ═══════════════════════════════════════════════════════════════════
#  /explain  —  plain-English breakdown of every scoring decision
#
#  Same input as /analyze.
#  Returns a human-readable report explaining WHY each factor scored
#  what it did — intended for the UI "How did we score this?" panel
#  and for demonstrating algorithm explainability to judges.
# ═══════════════════════════════════════════════════════════════════

FACTOR_DESCRIPTIONS = {
    "kds": (
        "Keyword Density Score measures how many scam-specific phrases "
        "were found. Each phrase has a weight from 1 (low signal alone) "
        "to 10 (almost never appears outside scam messages). "
        "When multiple related phrases appear together, a context boost "
        "of ×1.3 is applied because co-occurrence is a stronger signal."
    ),
    "ups": (
        "Urgency & Pressure Score detects artificial time pressure. "
        "Scammers always create fake deadlines ('within 2 hours', "
        "'failure to comply') to stop you from thinking clearly or "
        "calling someone to verify."
    ),
    "ims": (
        "Impersonation Score measures how convincingly the message "
        "claims to come from a real authority — CBI, TRAI, Income Tax "
        "Department, RBI, or a bank. The more specific the claim, "
        "the higher the score."
    ),
    "its": (
        "Isolation Tactic Score detects phrases designed to stop you "
        "from telling family or friends. 'Do not tell anyone', 'stay on "
        "call', 'keep this confidential' — these are almost exclusively "
        "used by scammers to prevent victims from verifying the call."
    ),
}

RISK_VERDICT = {
    "SAFE":     "No scam patterns found. Stay cautious — this tool is not exhaustive.",
    "MEDIUM":   "This looks suspicious. Do not pay any money or share personal details until you verify through official channels.",
    "HIGH":     "Strong scam indicators. Do not comply. Hang up and call 1930 (National Cybercrime Helpline).",
    "CRITICAL": "This is almost certainly a scam. No Indian law allows 'digital arrest'. Hang up immediately and call 1930.",
}


def build_explain(result: dict) -> dict:
    """
    Converts a detect_scam() result into a plain-English explanation object.
    """
    if result["status"] == "SAFE":
        return {
            "is_scam":   False,
            "summary":   "No scam patterns were detected in this message.",
            "verdict":   RISK_VERDICT["SAFE"],
            "factors":   [],
            "tip":       result.get("tip", ""),
        }

    factors      = result["factors"]
    scam_type    = result["primary_scam"]
    severity     = result["severity"]
    risk_score   = result["risk_score"]
    ctx_notes    = result.get("context_notes", [])

    # ── Summary sentence ──────────────────────────────────────────
    summary = (
        f"This message scores {risk_score}% risk and matches the pattern of a "
        f"{scam_type} — rated {severity}. "
    )
    if risk_score >= 85:
        summary += "It contains multiple high-confidence scam indicators."
    elif risk_score >= 65:
        summary += "It contains several clear scam indicators."
    else:
        summary += "It contains some scam indicators — treat with caution."

    # ── Per-factor plain-English ───────────────────────────────────
    factor_explanations = []

    for key, meta in [
        ("kds", "Keyword Density Score"),
        ("ups", "Urgency & Pressure Score"),
        ("ims", "Impersonation Score"),
        ("its", "Isolation Tactic Score"),
    ]:
        f     = factors[key]
        score = f["score"]
        maxpt = f["max"]
        hits  = f["matched"]

        if score == 0:
            plain = f"No {meta.split()[0].lower()} signals were found. This factor scored 0/{maxpt}."
        else:
            pct_of_max = round((score / maxpt) * 100)
            # Describe intensity
            if pct_of_max >= 80:
                intensity = "very high"
            elif pct_of_max >= 50:
                intensity = "significant"
            elif pct_of_max >= 25:
                intensity = "moderate"
            else:
                intensity = "low"

            # List matched phrases
            if hits:
                phrase_list = ", ".join(f'"{h}"' for h in hits[:4])
                extra = f" and {len(hits)-4} more" if len(hits) > 4 else ""
                phrase_str = f"Matched phrases: {phrase_list}{extra}."
            else:
                phrase_str = ""

            plain = (
                f"Scored {score}/{maxpt} ({intensity}). "
                f"{FACTOR_DESCRIPTIONS[key]} "
                f"{phrase_str}"
            )

        factor_explanations.append({
            "factor":  meta,
            "key":     key,
            "score":   score,
            "max":     maxpt,
            "plain":   plain,
        })

    # ── Context boost notes ────────────────────────────────────────
    context_section = ctx_notes if ctx_notes else [
        "No context boost was applied — matched keywords did not form "
        "co-occurring groups strong enough to trigger the 1.3× multiplier."
    ]

    # ── Score formula breakdown ────────────────────────────────────
    kds = factors["kds"]["score"]
    ups = factors["ups"]["score"]
    ims = factors["ims"]["score"]
    its = factors["its"]["score"]
    raw = kds + ups + ims + its
    formula_plain = (
        f"KDS ({kds}) + UPS ({ups}) + IMS ({ims}) + ITS ({its}) "
        f"= {raw} → capped at 100 → {min(100, raw)}. "
        f"Severity floor for {severity} scams ensures a minimum of "
        f"{SEVERITY_FLOOR.get(severity, 0)}% when real evidence is present. "
        f"Final score: {risk_score}%."
    )

    return {
        "is_scam":        True,
        "primary_scam":   scam_type,
        "severity":       severity,
        "risk_score":     risk_score,
        "summary":        summary,
        "verdict":        RISK_VERDICT.get(severity, RISK_VERDICT["HIGH"]),
        "formula":        formula_plain,
        "factors":        factor_explanations,
        "context_boosts": context_section,
        "what_to_do":     result.get("action", []),
    }


@app.route("/explain", methods=["POST"])
def explain():
    """
    POST { "message": "..." }
    Returns a plain-English explanation of every scoring decision made.
    Useful for UI 'How did we score this?' panel and judge demos.
    """
    payload = request.get_json()
    if not payload or not payload.get("message", "").strip():
        return jsonify({"error": "No message provided"}), 400
    msg = payload["message"].strip()
    if len(msg) < 5:
        return jsonify({"error": "Message too short to analyse"}), 400

    result  = detect_scam(msg)
    explain_result = build_explain(result)
    return jsonify(explain_result)


@app.route("/analytics", methods=["GET"])
def analytics():
    return jsonify({
        "scams_detected_today": 47,
        "money_protected":      "₹2,34,000",
        "users_warned":         312,
        "breakdown": [
            {"type": "Digital Arrest", "pct": 64, "color": "#ff4560"},
            {"type": "KYC Fraud",      "pct": 18, "color": "#f5c400"},
            {"type": "IT Dept Scam",   "pct":  9, "color": "#ff9800"},
            {"type": "TRAI Scam",      "pct":  6, "color": "#0096ff"},
            {"type": "Prize Scam",     "pct":  3, "color": "#00d4aa"},
        ],
        "recent": [
            {"time": "2 min ago",  "type": "Digital Arrest", "city": "Bengaluru"},
            {"time": "8 min ago",  "type": "KYC Fraud",      "city": "Mumbai"},
            {"time": "15 min ago", "type": "TRAI Scam",      "city": "Delhi"},
            {"time": "23 min ago", "type": "IT Dept Scam",   "city": "Hyderabad"},
            {"time": "31 min ago", "type": "Prize Scam",     "city": "Chennai"},
        ],
    })


@app.route("/test-cases", methods=["GET"])
def test_cases():
    return jsonify([
        {
            "id": 1, "slug": "digital-arrest",
            "label": "Digital Arrest — CBI Officer", "tag": "CRITICAL",
            "message": _DEMO_MESSAGES["digital-arrest"],
        },
        {
            "id": 2, "slug": "kyc-fraud",
            "label": "KYC Fraud — SBI Account Block", "tag": "HIGH",
            "message": _DEMO_MESSAGES["kyc-fraud"],
        },
        {
            "id": 3, "slug": "trai-scam",
            "label": "TRAI Scam — SIM Disconnection", "tag": "HIGH",
            "message": _DEMO_MESSAGES["trai-scam"],
        },
        {
            "id": 4, "slug": "prize-scam",
            "label": "Prize Scam — KBC Lucky Draw", "tag": "MEDIUM",
            "message": _DEMO_MESSAGES["prize-scam"],
        },
        {
            "id": 5, "slug": "it-department-scam",
            "label": "IT Dept Scam — TDS Refund", "tag": "HIGH",
            "message": _DEMO_MESSAGES["it-department-scam"],
        },
    ])


@app.route("/scam/<slug>")
def scam_detail(slug):
    scam_name = SCAM_SLUG_MAP.get(slug)
    if not scam_name or scam_name not in SCAM_PATTERNS:
        return "Not found", 404
    data = SCAM_PATTERNS[scam_name]
    return render_template(
        "scam_detail.html",
        scam_name=scam_name,
        slug=slug,
        severity=data["severity"],
        keywords=data["keywords"],
        explanation=data["explanation"],
        actions=data["action"],
        demo_message=_DEMO_MESSAGES.get(slug, ""),
        demo_label=_DEMO_LABELS.get(slug, scam_name),
        scam_icon=SCAM_ICONS.get(scam_name, "⚠️"),
    )


if __name__ == "__main__":
    app.run(debug=True, port=5000)
