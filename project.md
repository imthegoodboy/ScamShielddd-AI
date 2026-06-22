# 🛡️ ScamShield AI — Your Personal AI Fraud Investigator

This is not just a chatbot. It is an **AI-powered scam investigation app** that helps people determine whether a message, website, email, QR code, or job offer is safe or a scam.

Think of it like **VirusTotal + Truecaller + AI reasoning**, but focused on everyday users.

---

# The Problem

Every day people receive:

* WhatsApp messages
* SMS
* Emails
* Instagram DMs
* Job offers
* Payment requests
* QR codes
* Unknown websites

People often ask:

* "Is this real?"
* "Should I trust this?"
* "Can I click this link?"
* "Am I being scammed?"

Most people don't know.

ScamShield AI becomes their **AI investigator**.

---

# Main Idea

Instead of giving a simple answer, AI investigates and explains WHY something is dangerous.

For example:

User uploads:

> "Congratulations! You've won ₹50,000. Click here immediately."

ScamShield says:

```
🚨 HIGH RISK

Risk Score: 95%

Reasons:
✓ Urgency language detected
✓ Promise of free money
✓ Suspicious domain
✓ Common lottery scam pattern

Recommendation:
Don't click.
Block sender.
```

---

# User Flow

## Home Page

User sees:

```
Upload Screenshot
Paste Message
Check Website
Analyze Email
Scan QR Code
Check Job Offer
History
```

---

# 1. Screenshot Scanner

User uploads a screenshot from WhatsApp, SMS, Telegram, Instagram, etc.

Example:

```
"Pay ₹2000 to receive your interview letter."
```

---

### Behind the scenes

Screenshot

↓

OCR extracts text

↓

AI analyzes content

↓

Scam pattern detection

↓

Risk score generated

↓

Results page

---

Result:

```
⚠ Possible Job Scam

Risk Score: 88%

Reasons:
✓ Asking for money before hiring
✓ Urgency detected
✓ Similar scam patterns

Recommendation:
Do not pay.
```

---

# 2. Website Scanner

User pastes:

```
amaz0n-sale-offers.xyz
```

---

System checks:

### Domain age

Maybe created 3 days ago.

### HTTPS

Does SSL exist?

### Similarity to known brands

Amazon → amaz0n

### Suspicious keywords

sale
gift
free
urgent

---

Result:

```
Risk Score: 92%

⚠ New domain
⚠ Looks like Amazon
⚠ Known phishing pattern

Avoid opening.
```

---

# 3. QR Code Scanner

User uploads QR code.

System detects:

### Collect request?

### Fake payment?

### UPI scam patterns?

---

Result:

```
⚠ Receiving money never requires entering your PIN.

Risk Score: 80%
```

---

# 4. Email Analyzer

User uploads email screenshot or text.

System checks:

### Sender email

[paypal-help-support@gmail.com](mailto:paypal-help-support@gmail.com)

### Suspicious language

"Act now"

"Urgent"

"Verify immediately"

### Attachments

Dangerous files

---

Result:

```
Risk Score: 90%

Possible phishing email.
```

---

# 5. Job Offer Detector

This is very useful.

User pastes:

```
Amazon Work From Home
Registration fee ₹500
Salary ₹60,000/month
```

AI checks:

### Unrealistic salary

### Asking money before joining

### Fake company name

### Contact details

---

Result:

```
🚨 Job Scam

Risk Score: 95%

Never pay before employment.
```

---

# 6. Investment Scam Detector

User pastes:

```
Double your money in 7 days.
Guaranteed returns.
```

Result:

```
Ponzi scheme indicators detected.

Risk Score: 96%
```

---

# Architecture

```
User Input
      ↓
Image/Text/Link
      ↓
Tool Call
      ↓
OCR / URL Analysis
      ↓
AI Reasoning
      ↓
Risk Engine
      ↓
Structured Report
      ↓
User Review
      ↓
Save History
```

---

# Features

## Risk Score

```
Safe
25%

Suspicious
60%

Dangerous
95%
```

---

## Explain Why

Not just "scam".

Explain:

```
Reasons:

✓ Urgency language
✓ Asking money
✓ Fake domain
✓ Too-good-to-be-true offer
```

---

## Personal History

Store:

```
June 22

WhatsApp message
Risk 85%

Website
Risk 40%

Email
Risk 92%
```

Users can revisit reports later.

---

# Smart Recommendations

Instead of only warning:

Show actions.

```
✓ Block sender

✓ Ignore message

✓ Report to Cyber Crime

✓ Mark Safe
```

---

# Community Database (Future)

Suppose 500 users checked:

```
+91 98XXXXXX

Reported by 43 users

Fake Loan Scam
```

Now everyone benefits.

---

# AI Chat

User asks:

> Should I trust this message?

> Why is it dangerous?

> What should I do?

AI explains.

---

# Advanced Features

## Voice Mode

Grandparents can speak:

> Someone sent me this SMS. Is it safe?

AI replies with voice.

---

## Fake Customer Support Detector

Detect:

```
amazon-help@gmail.com

paytm-support123@gmail.com
```

---

## Deepfake Voice Warning

Future feature.

User uploads audio.

AI checks whether voice sounds AI-generated.

---

## URL Preview

Shows:

```
Created: 2 days ago

Country: Unknown

Risk Score: 87%
```

---

## Browser Extension

Whenever user visits a website:

```
⚠ Warning

This website is suspicious.
```

---

## Cyber Crime Report Generator

One-click report:

```
Victim details

Phone number

Scam message

Evidence screenshots

Timeline
```

PDF generated automatically.

---

# Typical User Flow

```
Home
 ↓
Upload Screenshot
 ↓
OCR Tool
 ↓
AI Investigation
 ↓
Risk Score
 ↓
Reasons
 ↓
Recommendations
 ↓
Save Report
 ↓
History
```

---

# Why This Idea Is Strong For Anna

Because Anna likes:

### Tool Calls

OCR

URL lookup

QR decoder

State

↓

### AI Reasoning

↓

### Structured UI

↓

### Human Review

↓

### Saved Memory

↓

### Useful Workflow

This is much closer to a real product than a chatbot.

---

If I were building for the Anna hackathon, I would actually make **ScamShield AI like "VirusTotal for normal people"**, with a beautiful card-based UI and a risk meter. I think this could genuinely compete for the prize because the usefulness is immediately obvious and the demo would be very easy to understand.
