# Releasing

Two packages ship from this repo under the same name and the same version:
`agentgate-pdp` on PyPI (`agentgate/`) and `agentgate-pdp` on npm
(`sdk-typescript/`). They stay in lockstep on purpose — a receipt issued to one
client has to verify in the other, and a version skew between them is the kind
of thing nobody notices until an auditor's check fails.

## Before anything

```bash
pytest tests/ -q                      # 1,619 tests
cd sdk-typescript && npm test         # 32 tests, including Python parity
```

The parity suite is the one that matters here. `action_ref` is implemented
twice, and the two must agree byte for byte or dispatch checks fail silently by
refusing operations that were in fact authorized. If anything in
`core/receipts/` changed, regenerate the vectors from the code the server runs
and read the diff as a deliberate statement that digests changed:

```bash
cd sdk-typescript && npm run vectors  # rewrites test/vectors.json
git diff test/vectors.json
```

## Version

Bump all three together. They are checked against each other by nothing, which
is exactly why it is written down here:

| File | Field |
| --- | --- |
| `pyproject.toml` | `version` |
| `agentgate/__init__.py` | `__version__` |
| `sdk-typescript/package.json` | `version` |

## Credentials

**PyPI.** Create a token at <https://pypi.org/manage/account/token/>, scoped to
the `agentgate-pdp` project, then write `~/.pypirc`:

```ini
[pypi]
  username = __token__
  password = pypi-<your-token>
```

**npm.** `npm login`. Tokens expire; a 401 from `npm whoami` means the one in
`~/.npmrc` has lapsed, not that something is wrong with the package.

## Publish

```bash
# Python
python -m build                       # writes dist/
python -m twine check dist/agentgate_pdp-<version>*
python -m twine upload dist/agentgate_pdp-<version>*

# TypeScript
cd sdk-typescript
npm publish                           # prepublishOnly rebuilds and reruns tests
```

Both registries refuse to reuse a version number, so a bad release is a new
release, never a replacement. That is why `twine check` and `npm publish
--dry-run` come first.

## Afterwards

Confirm the artifact contains what you think it does. The 0.2.1 release sat on
PyPI for four months carrying only `__init__.py` and `exceptions.py` — no
`action_ref`, no `verify` — while the docs told readers to run
`python -m agentgate.verify`. The code had been correct in this repo the whole
time and was simply never released.

```bash
pip download agentgate-pdp==<version> --no-deps -d /tmp/check
unzip -l /tmp/check/agentgate_pdp-<version>-py3-none-any.whl
npm pack agentgate-pdp@<version> && tar -tzf agentgate-pdp-<version>.tgz
```

Then verify a real receipt end to end, which is the only check that exercises
the thing people are told they can do:

```bash
pip install "agentgate-pdp[verify]"
agentgate-verify receipt.json --public-key agentgate.pem --operation ran.json
```

It should exit 0 for the operation the receipt covers, and exit 1 with both
digests printed for anything else.
