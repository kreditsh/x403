# Test vectors

Fixed keys, fixed times, the same bytes for every implementation. `make.py` writes them; both SDKs' test suites read `expectations.json` and must give every result it names.

| File | What |
| --- | --- |
| `keys.json` | The authority's and the executor's P-256 pairs. Test keys only. |
| `payment.json`, `payment_other.json` | The payment the decision is for, and one it is not for. |
| `query.json` | A risk query signed by the executor as requester. |
| `decision.json` | A decision signed by the authority, bound to `payment.json` and to the executor. |
| `decision_tampered.json` | The same decision with a field changed after signing. |
| `decision_expired.json` | A decision past its expiry. |
| `receipt.json` | The executor's countersignature on the decision. |
| `local_decision.json` | The decision the executor signs itself on timeout. |
| `local_allowed.json` | A local decision that claims an allow, which must never verify. |
| `outcome.json` | A signed outcome report. |
| `expectations.json` | Each case: the file, the keys, where it is presented, and the result. |

Regenerate after any object change:

```
packages/python/.venv/bin/python test-vectors/make.py
```
