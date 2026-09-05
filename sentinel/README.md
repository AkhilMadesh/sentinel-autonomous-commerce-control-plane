# SENTINEL — Autonomous Commerce Control Plane

> **AI proposes. SENTINEL decides. Policies constrain. Humans gate exceptions. Razorpay executes. Audit records everything.**

SENTINEL is an **AI-native commerce control plane** designed for agentic purchasing. It allows an AI Buyer to understand a customer's purchase intent while keeping the authority to spend money outside the model itself.

Instead of allowing an AI agent to directly trigger a payment, SENTINEL places a deterministic control layer between **AI intent** and **payment execution**. Every transaction is evaluated against identity, delegated authority, spending limits, merchant policies, risk, inventory, and approval requirements before Razorpay Test Mode can execute it.

---

## ✦ Why SENTINEL?

AI agents are becoming capable of discovering products, building carts, and initiating purchases. The missing layer is **trust and control**.

SENTINEL answers a simple question:

> **What should happen when an AI wants to spend money?**

The answer is not to give the model unrestricted payment access.

SENTINEL treats the AI as a **proposal engine**, while the control plane remains deterministic and auditable.

```text
┌──────────────┐
│   AI Buyer   │
│ understands  │
│ user intent  │
└──────┬───────┘
       │ structured intent
       ▼
┌──────────────────────┐
│       SENTINEL       │
│  Authorization Core  │
├──────────────────────┤
│ Identity             │
│ Delegation           │
│ Spending Limits      │
│ Policies             │
│ Risk                 │
│ Inventory            │
│ Human Approval       │
└──────────┬───────────┘
           │
      ┌────┴────┐
      ▼         ▼
   ALLOW    EXCEPTION
      │      / BLOCK
      ▼
┌──────────────┐
│   Razorpay   │
│  Test Mode   │
└──────┬───────┘
       ▼
┌──────────────┐
│ Audit Trail  │
│ + Analytics  │
└──────────────┘
```

---

## 🚀 Core Capabilities

### AI Buyer

- Converts natural-language purchase requests into structured purchase intent.
- Uses an LLM integration for intent extraction.
- Supports controlled catalog tools such as product search, product lookup, stock checks, and cart calculation.
- Keeps the AI separated from direct payment authority.
- Does not invent products outside the available merchant catalog.

### Deterministic Authorization Engine

Every proposed transaction is evaluated independently by SENTINEL.

| Control | Purpose |
|---|---|
| Identity | Verifies who is initiating the transaction |
| Delegation | Determines whether the agent is authorized to act |
| Spending limits | Enforces daily/monthly limits |
| Policies | Applies merchant-defined transaction rules |
| Risk | Evaluates transaction risk |
| Inventory | Confirms exact product availability |
| Approval | Routes exceptions to a human |
| Decision | Produces `ALLOW`, `MODIFY`, `APPROVAL_REQUIRED`, or `BLOCK` |

**The LLM cannot override these controls.**

---

## 💳 Razorpay Test Mode

SENTINEL integrates with Razorpay Test Mode for the payment execution layer.

The payment flow includes:

1. Create a server-side Razorpay order.
2. Present the payment through Razorpay Checkout.
3. Verify payment information server-side.
4. Validate order ID, amount, currency, and signature.
5. Finalize successful payments idempotently.
6. Update the exact purchased product's inventory.
7. Record the result in the audit trail.
8. Process Razorpay webhook events with signature verification.

> **No real money is required for the demo. Use Razorpay Test Mode credentials only.**

---

## 🛡️ Security & Reliability

SENTINEL is designed around the principle that **payment execution must be more trusted than AI output**.

- Deterministic authorization before payment execution
- Fresh authorization checks for approval flows
- Exact product-level inventory updates
- Idempotent payment finalization
- Server-side amount/currency/order validation
- Razorpay signature and webhook verification
- Idempotency support
- Rate limiting
- Chained SHA-256 audit records
- Audit integrity verification
- Development-only payment simulation
- No API secrets committed to the repository

---

## 📊 Audit & Analytics

Every important commerce action can be traced through the SENTINEL audit layer.

The system records events around:

- AI intent
- Authorization decisions
- Policy evaluation
- Approvals
- Payment execution
- Inventory changes
- Webhooks
- Security-sensitive actions

Analytics endpoints provide transaction and commerce visibility without bypassing the underlying authorization model.

---

## 🧰 Tech Stack

**Backend**
- Python
- Flask
- SQLite
- REST APIs

**AI**
- LLM-based intent extraction
- Structured intent processing
- Controlled commerce tools

**Payments**
- Razorpay Test Mode
- Razorpay Checkout
- Payment signature verification
- Webhooks

**Frontend**
- HTML
- CSS
- JavaScript
- Responsive fintech dashboard UI

**Security / Controls**
- Deterministic policy engine
- Delegated authorization
- Risk controls
- Idempotency
- Chained audit trail

---

## 🧪 First-Run Demo Data

SENTINEL automatically initializes a fresh SQLite database on first startup. The repository intentionally does **not** include a pre-populated database file, so judges can clone the project and get a clean, reproducible environment.

On first run, the application seeds a safe demonstration workspace with sample users, agents, policies, and products. The login screen exposes these demo roles for evaluation:

| Role | Username | Password |
|---|---|---|
| Admin | `admin` | `admin123` |
| Finance | `finance` | `finance123` |
| Operator | `operator` | `operator123` |
| Viewer | `viewer` | `viewer123` |

> These credentials are **demo-only application accounts** for local/buildathon evaluation. Do not reuse them for production deployments.

The generated `sentinel.db` remains local and is ignored by Git.

---

## ⚡ Quick Start

### 1. Clone the repository

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd SENTINEL
```

### 2. Create a virtual environment

**Windows**

```bash
python -m venv .venv
.venv\Scripts\activate
```

**macOS / Linux**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Copy `.env.example` to `.env`:

**Windows**

```bash
copy .env.example .env
```

**macOS / Linux**

```bash
cp .env.example .env
```

Then configure your own credentials locally.

```env
SECRET_KEY=your-random-secret
PORT=5000
DEVELOPMENT_MODE=false

RAZORPAY_KEY_ID=rzp_test_...
RAZORPAY_KEY_SECRET=...
RAZORPAY_WEBHOOK_SECRET=...

OPENAI_API_KEY=...
OPENAI_MODEL=gpt-4o-mini
```

> **Never commit `.env` or any API key to GitHub.** The repository intentionally contains `.env.example` instead.

### 5. Run SENTINEL

```bash
python app.py
```

Or use the included startup scripts:

```text
run.bat     # Windows
run.sh      # macOS / Linux
```

Open:

```text
http://localhost:5000
```

---

## 🔐 API Configuration

The repository does **not** contain live credentials.

For judging or local development, provide your own credentials through `.env`.

### Razorpay

Use **Razorpay Test Mode** credentials:

```env
RAZORPAY_KEY_ID=
RAZORPAY_KEY_SECRET=
RAZORPAY_WEBHOOK_SECRET=
```

### AI

Configure the LLM provider supported by the current application configuration:

```env
OPENAI_API_KEY=
OPENAI_MODEL=gpt-4o-mini
```

If no real AI credential is configured while `DEVELOPMENT_MODE=false`, the application does not silently pretend that an AI request succeeded.

---

## 🔄 Example Agentic Commerce Flow

A buyer can express an intent such as:

> **“Buy two wireless headphones under ₹5,000.”**

SENTINEL processes the request as:

```text
Natural Language Request
          ↓
       AI Buyer
          ↓
   Structured Intent
          ↓
     Catalog Lookup
          ↓
       Cart Build
          ↓
  ┌─────────────────────┐
  │ SENTINEL Evaluation  │
  │                     │
  │ Identity            │
  │ Delegation          │
  │ Limits              │
  │ Policy              │
  │ Risk                │
  │ Inventory           │
  └──────────┬──────────┘
             ↓
      Decision Engine
             ↓
   ┌─────────┼──────────┐
   ▼         ▼          ▼
 ALLOW    APPROVAL    BLOCK
   │          │
   │       Human Gate
   │          │
   └──────┬───┘
          ▼
    Razorpay Test Mode
          ↓
     Payment Verified
          ↓
    Inventory Updated
          ↓
       Audit Event
```

This separation is the core safety property of SENTINEL:

> **The AI can propose a purchase, but it cannot grant itself permission to spend.**

---

## 🧪 Testing

Run the Python test suite with:

```bash
pytest -q
```

The project also contains frontend-oriented tests under `tests/`.

For the strongest demonstration, test both successful and denied/exception paths:

- Allowed transaction
- Spending-limit violation
- Policy violation
- Insufficient inventory
- Approval-required transaction
- Blocked transaction
- Successful Razorpay Test Mode payment
- Duplicate payment/webhook handling
- Audit integrity verification

---

## 🔗 Razorpay Webhook

The backend exposes the Razorpay webhook endpoint at:

```text
/api/webhooks/razorpay
```

When using a local development server, expose the application through a secure public HTTPS tunnel/domain before registering the endpoint with Razorpay.

Example:

```text
https://YOUR-PUBLIC-DOMAIN/api/webhooks/razorpay
```

Keep the webhook secret in `.env` only.

---

## 📁 Project Structure

```text
SENTINEL/
├── app.py
├── requirements.txt
├── README.md
├── .env.example
├── .gitignore
├── run.bat
├── run.sh
├── test_sentinel.py
│
├── static/
│   ├── app.js
│   └── style.css
│
├── templates/
│   └── index.html
│
└── tests/
    ├── test_decision_engine.py
    └── test_frontend.js
```

---

## 🏆 Buildathon Positioning

SENTINEL is built for **agentic commerce**, where AI systems can act on behalf of buyers but commerce infrastructure still needs enforceable boundaries.

The project focuses on the control layer between **AI intent and real payment execution**:

```text
AI Buyer
   ↓
Intent
   ↓
SENTINEL
   ↓
Authorization + Policy + Risk + Human Gate
   ↓
Razorpay
   ↓
Auditable Commerce
```

The result is an agentic purchasing architecture where **autonomy is bounded, every money action is explainable, exceptions are gated, and payment execution remains controlled.**

---

## 👤 Author

**Akhil Gudise**

Built as an AI-native commerce control plane for the Razorpay AI Buildathon.

---

## ⚠️ Security Notice

This repository is intended for demonstration and buildathon evaluation.

- Use Razorpay **Test Mode** credentials.
- Never commit `.env`.
- Never expose API secrets in screenshots, README files, frontend code, or Git history.
- Rotate any credential that has accidentally been exposed.

---
