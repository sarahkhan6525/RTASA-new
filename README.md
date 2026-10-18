# RTASA -- Role-Based Threshold-Access Hybrid Encryption and Steganography with Tamper-Evident Audit Trails

A runnable implementation of the **RTASA** framework from the paper
*"Role-Based Threshold-Access Hybrid Encryption and Steganography with
Tamper-Evident Audit Trails: A Structured Review and an Evaluated
Framework"* (Khan, Razzaque, Khatib). RTASA composes five protection
layers that the paper's own review found no prior work combines:

| Tag | Layer | Mechanism | Where |
|---|---|---|---|
| **E** | Hybrid encryption | AES-256-GCM payload encryption | `rtasa/crypto_core.py` |
| **A** | Role-based access | RSA-OAEP share wrapping, bound to a role and a record id | `rtasa/rsa_wrap.py` |
| **T** | Threshold secret sharing | Feldman-verifiable Shamir (k, n) sharing of the session key, over the P-256 group order | `rtasa/shamir.py` |
| **S** | Steganographic concealment | LSB-matching embedding of wrapped shares into cover images | `rtasa/stego.py` |
| **L** | Tamper-evident logging | SHA-256 hash chain + per-entry ECDSA signatures + custodian-witnessed checkpoints | `rtasa/audit_log.py` |

Everything maps directly onto the paper's own notation: file docstrings
cite the exact equation or section (e.g. "eq. (5)", "Sec. IV-C") the code
implements, so you can read the paper side by side with the source.

## Layout

```
rtasa/            the five-layer cryptographic core (no DB, no web framework --
                   fully unit-testable on its own)
  curve.py          P-256 group constants (shared by T and L)
  crypto_core.py     AES-256-GCM + HKDF  (layer E, eq. 2)
  shamir.py          Shamir (k, n) sharing + Feldman VSS  (layer T, eq. 3/4/9)
  rsa_wrap.py        RSA-OAEP share wrapping + id binding  (layer A, eq. 5)
  stego.py           LSB-matching embed/extract  (layer S, eq. 6)
  audit_log.py       signed, checkpointed, witnessed audit log  (layer L, Sec. IV-C)
  keystore.py        role identities, RSA+ECDSA keys, credential+OTP auth
                     (Argon2id, lockout, TOTP provisioning -- see
                     "Enterprise security hardening" below)
  secrets_vault.py   AES-256-GCM envelope encryption for the role key
                     store at rest (master-key sourcing, seal/unseal)
  records.py         on-disk representation of an issued record + its carriers
  issuance.py        Sec. IV-B issuance pipeline, wires E+A+T+S+L together
  recovery.py        Sec. IV-D recovery pipeline (request / approve / recover)
  system.py          RTASASystem facade used by the CLI, tests, and the API

app/               FastAPI + SQLAlchemy backend around rtasa/
  main.py            FastAPI app (run with `uvicorn app.main:app --reload`);
                     also mounts webui/ at /ui when that folder exists, and
                     configures the rtasa.security JSON-lines log
  security_config.py RTASA_DEMO_MODE / RTASA_SECURITY_LOG flags
  models.py          SQLAlchemy ORM tables
  persistence.py     RTASASystem <-> DB round trip (seals/unseals the
                     sensitive key-store fields at the storage boundary)
  routers/           roles / records / recovery / audit endpoints

webui/index.html   the demo frontend (see "Web UI" below) -- single file,
                   no build step, served same-origin at /ui by app/main.py

carriers/          synthetic 768x512 grayscale cover-image generator
                   (stands in for the paper's 24 Kodak images, Sec. V-A)

scripts/demo.py               console walkthrough: the paper's own toy
                               (k,n)=(2,3) example over Z_17 (Sec. IV-D),
                               then the full real pipeline, then a live
                               tamper-detection demonstration
scripts/authenticator.py      a standalone simulated TOTP authenticator
                               device -- see "Enterprise security hardening"
scripts/benchmark_latency.py  reproduces Sec. V-C / Fig. 2 (issuance and
                               recovery latency vs. a plain-hybrid baseline,
                               across (k, n) settings)
scripts/run_steganalysis.py   reproduces Sec. V-D / Fig. 3 (RS analysis,
                               SPA, and a SPAM+LDA detector's AUC against
                               LSB matching vs. LSB replacement)

rtasa/steganalysis/   detectors used only by run_steganalysis.py -- never
                      imported by the RTASA pipeline itself:
  rs_analysis.py        RS (Regular-Singular) analysis, Fridrich/Goljan/Du 2001
  spa.py                Sample Pair Analysis, Dumitrescu/Wu/Wang 2003
  spam.py               SPAM-style pixel-difference features for a learned detector
  evaluate.py            the AUC sweep + Fig. 3-style chart

tests/             pytest suite reproducing the paper's own evaluation:
  test_end_to_end.py      Table III's 7 functional checks
  test_log_tampering.py   Table IV's 7 log attacks, plain chain vs RTASA
  test_steganalysis.py    worked-example cross-check for RS/SPA + sanity
                           checks that both stay near chance against real
                           LSB matching but catch LSB replacement
  test_keystore_security.py   Argon2id, lockout, TOTP provisioning,
                               encryption-at-rest round trip
  test_api_security.py        demo-mode gating, 429-on-lockout, and proof
                               that the database actually holds ciphertext
  test_crypto_core.py, test_shamir_feldman.py, test_rsa_wrap.py,
  test_stego.py, test_audit_log.py   unit tests per layer

cli.py             `python cli.py demo|covers|serve|test`
```

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Run the demo

```bash
python cli.py demo
# or: python -m scripts.demo
```

This prints the paper's toy example (and checks its numbers match: shares
(1,11)/(2,16)/(3,4), commitments 81/93, K=6), then issues and recovers a
real record through the full pipeline, then tampers with a log entry live
to show detection.

## Run the tests

```bash
python cli.py test
# or: pytest tests/ -v
```

All 79 tests pass, including a structural reproduction of every row of
Table III (functional checks) and Table IV (log-tampering detection), a
numeric cross-check of the RS/SPA steganalysis detectors against a worked
example from the published literature (see below), and the enterprise
security hardening tests (Argon2id, lockout, TOTP provisioning,
encryption-at-rest -- see "Enterprise security hardening" below).

## Run the backend

```bash
python cli.py serve
# then open http://127.0.0.1:8000/docs
```

A minimal walkthrough via the API (also see the Swagger UI):

1. `POST /roles` -- create a data-owner role, three custodian roles (each
   with a distinct `evaluation_point`, i.e. the Shamir x_i), and a
   requester role.
2. `GET /roles/{role_id}/otp` -- demo-mode-only convenience endpoint that
   returns a role's current OTP (403s when `RTASA_DEMO_MODE=0`). Or
   `GET /roles/{role_id}/otp/provisioning` -- an `otpauth://` URI + QR
   code to enroll the role's TOTP secret on a real authenticator app
   instead, the way an enterprise deployment actually should (see
   "Enterprise security hardening" below).
3. `POST /records/issue` -- encrypts a message, splits the key, wraps and
   embeds a share per custodian.
4. `POST /recovery/request`, then `POST /recovery/approve` (k times), then
   `POST /recovery/recover`.
5. `GET /audit/log` and `GET /audit/verify`.
6. `GET /records/{record_id}/carrier/{role_id}` -- the actual stego PNG
   for one custodian's share (used by the web UI's gallery, below).
7. `POST /audit/tamper-demo` -- a safe, non-destructive live demonstration
   of Table IV's tamper detection (see "Web UI" below).

## Web UI

`python cli.py serve`, then open **http://127.0.0.1:8000/ui/** -- a real
frontend (`webui/index.html`, vanilla HTML/CSS/JS, no build step) served
same-origin by the FastAPI app itself, on top of the exact same API calls
listed above. This is the thing to demo: a working website with a URL,
not just the Swagger docs.

It walks through the paper's own flow end to end, each step labelled with
the layer and section it exercises:

1. **Roles** -- one-click "quick-start" creates an owner, three
   custodians, and a requester, or add roles one at a time.
2. **Issue a record** -- encrypt, split, wrap and embed a message; the
   result includes a gallery of the *actual* carrier images, each with one
   custodian's wrapped share really embedded in its pixel LSBs (eq. 6) --
   not a mockup, these are fetched live from `/records/{id}/carrier/{role}`.
3. **Recover** -- start a recovery request, collect custodian approvals
   with a live progress bar, then reconstruct and decrypt once the
   threshold is met.
4. **Audit & tamper demo** -- view the signed hash-chained log, verify it,
   and run a one-click live tamper-detection demo (Table IV's "insider
   edits their own entry" row): it verifies a scratch, in-memory copy with
   one entry edited the way a log-host attacker without any signing key
   could, side by side with the real log's own clean verification. Nothing
   about your actual audit log is ever touched by this button.

The UI holds no state and does no cryptography of its own -- it is a thin
presentation layer calling the same routers the API section above
describes, so anything it shows is the real backend's real output.

### Presenting it live

A few controls in the header exist purely to make this easy to demo in
front of an audience (a thesis panel, say) without clicking through two
dozen individual buttons or losing your place:

- **"Run full automated demo"** -- one click plays through the entire
  lifecycle above end to end (roles, issuance with real carrier images,
  threshold recovery, audit verification, live tamper demo), narrated by
  a caption banner at the top of the page and paced with short pauses so
  it reads naturally to people watching rather than flashing by.
- **Progress stepper** -- the four nav tabs (Roles / Issue / Recover /
  Audit) pick up a checkmark as each stage completes, so the audience can
  see at a glance where the demo is.
- **"Clean presentation view"** -- on by default, this collapses dense
  technical output (the raw Feldman commitment hex) behind a "technical
  detail" disclosure you can expand on request, e.g. if someone on the
  panel asks to see the actual commitment values.
- **"Reset demo"** -- clears all result panels and form state so you can
  immediately run through it again (e.g. once during rehearsal, once live).

None of these change what the backend does -- they only affect how the
existing API responses are sequenced and displayed.

## Reproducing Sec. V-C (latency) and Sec. V-D (steganalysis)

Two scripts reproduce the paper's own performance/security evaluation
figures, rather than just asserting the system works:

```bash
python -m scripts.benchmark_latency            # Fig. 2: issuance/recovery latency
python -m scripts.run_steganalysis              # Fig. 3: detector AUC vs. embedding rate
# both accept --quick for a fast sanity check instead of the full paper-scale sweep
```

**Latency (`benchmark_latency.py`)** times issuance and recovery for a
1 MiB record across (k, n) in {(2,3), (3,5), (5,7), (7,10)}, against a
plain-hybrid (AES-GCM + single RSA-OAEP wrap, no T/S/L) baseline, 300
trials after 20 warm-up runs, matching Sec. V-A/V-C. On this machine the
baseline lands within a few tenths of a millisecond of the paper's own
numbers (0.29 ms / 0.76 ms); RTASA's own latency is the right order of
magnitude and follows the paper's qualitative shape (recovery cost rising
with k, S dominating issuance, T+A dominating recovery) but runs a few
times higher at the largest (7,10) setting than the paper's reported
range -- expected, since the paper times itself on "a shared two-vCPU
Xeon VM" and is explicit that its own numbers are partly pure-Python
elliptic-curve arithmetic (Sec. V-A, VI), i.e. hardware-sensitive by the
paper's own account.

**Steganalysis (`run_steganalysis.py`)** builds three detectors and
measures each one's AUC at distinguishing cover images from stego images,
across several embedding rates, for both LSB replacement and RTASA's
actual LSB matching:

* `rs_analysis.py` and `spa.py` implement RS analysis and Sample Pair
  Analysis. Both were checked against primary sources rather than
  memory -- RS analysis against the worked numeric example in Dumitrescu,
  Wu & Wang (2003) Sec. VII (`tests/test_steganalysis.py`), and SPA's
  quadratic (eq. 35) against the authors' own preprint. Where a source
  equation's exact coefficients couldn't be confirmed cleanly (RS's full
  quadratic rate-estimator), the module uses a documented, honestly-
  labeled simplification instead of a guessed formula -- see each file's
  own docstring for exactly what was verified and what wasn't.
* `spam.py` + `evaluate.py`'s shrinkage Fisher LDA stand in for the
  paper's learned SPAM-feature detector, but use a smaller, order-1,
  2-direction feature set rather than the published order-3, 8-direction
  SPAM construction (`spam.py`'s docstring explains why: that exact
  construction couldn't be verified from a primary source either, and a
  guessed 686-dimensional feature extractor is worse than an honestly
  smaller one).

Running it reproduces the paper's central qualitative claim well for the
two verified classical detectors: RS and SPA both detect LSB replacement
increasingly well as the embedding rate rises, and both stay near chance
against RTASA's real LSB matching at every rate tested -- consistent with
Sec. V-D's reported numbers (SPA ~0.86 AUC vs. replacement at 0.1 bpp;
RTASA at or below 0.53 AUC). The reduced SPAM+LDA detector reproduces
that pattern only at low, realistic embedding rates (RTASA's actual
payload -- one wrapped RSA-OAEP share -- is around 0.005 bpp on a 512x768
cover); at the higher stress-test rates in the sweep it climbs well above
chance against LSB matching too, which the paper's own (full) SPAM+LDA
result does not show. That gap is reported here rather than tuned away:
the most likely explanation is the smaller feature construction and the
small (24-image) synthetic sample this harness trains on, both named
above, not a flaw in RTASA's actual embedding. `run_steganalysis.py`
prints this caveat directly when it triggers.

Both scripts write a PNG chart (`benchmark_latency.png`,
`steganalysis_auc.png`) alongside the console table.

## Why a few things are simplified from a production system

This is a faithful, runnable prototype at the scale the paper's own
evaluation used (Sec. V-A: "about 340 lines of Python... 24 Kodak
images... a shared two-vCPU VM"), not a hardened production deployment:

* **Cover images** are synthetically generated (`carriers/generate_carriers.py`)
  rather than the actual (non-redistributable) Kodak suite, but at the
  same size, bit depth, and statistical character the paper's imperceptibility
  numbers depend on.
* **Credential-and-OTP authentication** (`rtasa/keystore.py`) is a local
  Argon2id passphrase hash + a standard-library HOTP/TOTP implementation
  with real device provisioning, not a full enterprise IdP (SSO/SAML/OIDC)
  -- see "Enterprise security hardening" below for exactly how far this
  goes and where the remaining gap to a full IdP is.
* **Key storage** (`RoleKeyStore`) is a JSON file / SQLite row -- now
  encrypted at rest (see below) -- not an HSM or cloud KMS.
* **The FastAPI backend keeps one process-wide `RTASASystem`** and persists
  it as a full snapshot after each mutating call -- adequate at the
  paper's own evaluation scale (40 records per (k, n) setting), not
  designed for high-concurrency production load.

Every one of these is called out at the point in the code where it
matters, with a comment pointing back at the relevant part of the paper.

## Enterprise security hardening

Everything below strengthens exactly the two mechanisms the paper itself
names -- *"credential-and-OTP authentication"* (Sec. IV-B/D) and *"a role
key store that only authenticated members can use"* (Sec. IV-A) -- rather
than adding anything outside them. No new entities, protocol steps, or
cryptographic primitives beyond what the paper already specifies; AES-256-GCM,
already layer E's own primitive (eq. 2), is reused as the key-store's
envelope cipher below instead of introducing a different one.

| Mechanism | Before | Now |
|---|---|---|
| Credential hashing | PBKDF2-HMAC-SHA256, 200k iterations | **Argon2id** (`rtasa/keystore.py`), the current OWASP-recommended choice -- memory-hard, far more GPU/ASIC-resistant than a pure-iteration KDF |
| Passphrase policy | min 6 chars, no other check | **Min 12 chars + a common-passphrase blocklist**, NIST SP 800-63B style (length over forced complexity rules) |
| OTP factor | server computes and hands back the live code on request | **Real TOTP provisioning**: `GET /roles/{id}/otp/provisioning` returns an `otpauth://` URI + QR code to enroll on an actual authenticator app (or `scripts/authenticator.py`, a standalone simulated device, for testing); the old convenience endpoint is gated behind `RTASA_DEMO_MODE` (default on) and **403s outright when off** |
| Brute-force resistance | none -- the gate could be hammered indefinitely | **Lockout after 5 consecutive failed attempts**, 60s cooldown, surfaced as HTTP 429; persisted per role so it survives a restart |
| Security visibility | nothing recorded | **Failed-auth / lockout events are logged** (`rtasa.security` logger -> `security_events.log`, JSON lines) -- deliberately a *conventional* log, kept separate from the paper's own signed audit chain (layer L): every entry there is signed by the acting role's own key (eq. 7), which a failed authentication attempt, by definition, cannot produce |
| Key-store storage | plaintext PEM/TOTP seed in the SQLite row | **Sealed at rest** (`rtasa/secrets_vault.py`): RSA/ECDSA private keys and the TOTP seed are AES-256-GCM-encrypted under a separate master key before they reach the database, bound to `(role_id, field)` the same way the paper binds `id` into eq. (2)/(5); public keys and the (already one-way) Argon2id hash are untouched |

### Demo mode vs. enterprise mode

`RTASA_DEMO_MODE` (default **on**) is the one switch that changes
behavior: on, `GET /roles/{id}/otp` hands back a live code so a thesis/demo
walkthrough works with nobody holding a real authenticator app; off, that
endpoint always 403s and the OTP factor can only come from a device
enrolled via the provisioning endpoint -- the posture an actual enterprise
deployment should run with. Everything else above (Argon2id, lockout,
encryption at rest, the passphrase policy) is **always on**, in both modes.

To see it behave like a real deployment:

```bash
RTASA_DEMO_MODE=0 python cli.py serve
```

Then enroll a role's OTP factor once:

```bash
curl -s http://127.0.0.1:8000/roles/owner/otp/provisioning | python3 -c \
  "import json,sys; print(json.load(sys.stdin)['otpauth_uri'])"
```

...scan that into Google/Microsoft/1Password Authenticator (it's a
standard `otpauth://` URI), or, for testing without a phone, feed it to
the simulated authenticator device:

```bash
python scripts/authenticator.py "otpauth://totp/RTASA:owner?secret=..."
```

which prints live 6-digit codes the server actually accepts -- computed
entirely offline, from nothing but that one URI, the same way a real
custodian's phone would. `GET /roles/{id}/otp` is now 403 for everyone,
including the server operator.

### Master key

Encryption-at-rest needs a 32-byte master key (the KEK), sourced in this
order:

1. `RTASA_MASTER_KEY` env var (base64, 32 bytes) -- how a real deployment
   should supply it, injected by a secrets manager, never committed
   alongside the database it protects.
2. A local `.rtasa_master.key` file, auto-created with `0600` permissions
   on first run if neither is set -- a zero-setup convenience for running
   the prototype, loudly flagged in the startup log as exactly that, and
   already in `.gitignore`.

Losing this key makes every role's private key material and TOTP seed
permanently unrecoverable from the database alone -- back it up like any
other production secret.

### What's still out of scope

This closes the specific gap the paper's own prototype documents ("Role
keys are stored in JSON/SQLite, not an HSM"; Sec. V-A) as far as is
reasonable without changing what the paper's prototype actually is. A
real enterprise rollout would still want: the role key store itself
moved into an HSM or cloud KMS rather than an application-level envelope
cipher; a full IdP (SSO/SAML/OIDC) instead of a local credential store, if
roles need to map onto an existing corporate directory; and the
production infrastructure concerns (containerization, a multi-writer
database, structured request logging, CI) that are a deliberately
separate piece of work from this one.
