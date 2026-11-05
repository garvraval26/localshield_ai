# LocalShield AI: ARM / Android deployment plan (ExecuTorch)

Status: **plan only. Nothing in this document has been built or tested on an Android device.**
Written 2026-10-27 from the official ExecuTorch and Arm documentation listed at the end.
Facts below are marked **[doc]** (stated by a source), **[estimate]** (my arithmetic, must be
measured) or **[unknown]** (the sources do not say; must be checked on a real device).

## 1. What runs where today

| Part | Laptop prototype (working) | Android target |
|---|---|---|
| UI | Streamlit | Native Android screen (Kotlin) |
| URL detector | scikit-learn model + rules | Same rules ported to Kotlin; model weights exported |
| SMS detector | scikit-learn TF-IDF + logistic regression + link checks | Same, ported |
| Explanation (Llama) | **Ollama, development only**, loopback HTTP | **ExecuTorch** `LlmModule` on the phone |
| History | SQLite file | Android SQLite |

Ollama is used on the laptop only because it is quick to set up. It is **not** the deployment
runtime. The Python code has an `ExecuTorchBackend` placeholder that raises a clear error; it was
never silently replaced by Ollama.

## 2. Why ExecuTorch

[doc] ExecuTorch ships an Android library (`executorch-android` AAR) with a Java/Kotlin LLM API in
`org.pytorch.executorch.extension.llm` (`LlmModule`, `LlmModuleConfig`, `LlmGenerationConfig`,
`LlmCallback`). It runs a serialized `.pte` model plus a tokenizer file, with no network.

[doc] The Android library comes in two ABI variants: `arm64-v8a` and `x86_64`. Phones need
`arm64-v8a`.

[doc] Android backends listed: XNNPACK (CPU), MediaTek NeuroPilot (NPU), Qualcomm AI Engine (NPU),
Vulkan (GPU). XNNPACK is the portable CPU choice and the one used in Arm's Llama 3.2 1B guide.

[doc] The LLM API is described as **experimental and subject to change**. Pin the exact
ExecuTorch version and re-check the documentation before building.

## 3. Model preparation (Llama 3.2 1B Instruct)

Following Arm's learning path (XNNPACK, CPU):

1. Request access on Meta's Llama download page and accept the licence and Responsible Use Guide.
   [doc] The download link is valid for 24 hours. **The Llama licence terms apply to this project;
   read them before distributing the app.**
2. Download the checkpoint (`consolidated.00.pth`, `params.json`, `tokenizer.model`).
3. Export with `examples.models.llama.export_llama` using the KV cache with SDPA, the XNNPACK
   backend, `-qmode 8da4w` (group size 64), `--embedding-quantize 4,32`, and a 1024-token
   maximum sequence/context length. [doc] The guide says Llama 3's larger vocabulary makes
   embedding quantization necessary.
4. Output is one `.pte` file. Copy it and `tokenizer.model` to the phone (the docs example uses
   `/data/local/tmp/`; a real app would ship or download them into app storage).

Exact flags are in the Arm guide; copy them from there for the version you install.

## 4. Android integration

[doc] Gradle: `implementation("org.pytorch:executorch-android:<version>")` (the 0.7.0 docs show
version 0.7.0; check the current release). Or use a local `executorch.aar` plus the `soloader` and
`fbjni` dependencies listed in the docs.

Calling pattern [doc]: create `LlmModule`, optionally call `load()`, then `generate(prompt, callback)`.
Generation **runs synchronously on the calling thread**, so it must run off the main thread
(a `HandlerThread` or `Executor`). `stop()` interrupts it. `resetContext()` clears the KV cache.

Our safety design carries over unchanged:
- The detector result is the authority. The model only explains it.
- The same system prompt, the same untrusted-input quoting, and the same response validator
  (ported to Kotlin) run before any explanation is shown.
- If the model is missing, slow, or its reply is rejected, show the fixed template explanation.
  The app must remain fully usable with detectors only.

## 5. What the sources do NOT tell us (must be measured)

- [unknown] Minimum Android version / API level.
- [unknown] Minimum RAM and free storage for Llama 3.2 1B on a phone.
- [unknown] Size of the exported `.pte` file. [estimate] 1.2 billion parameters at about 4 bits
  per weight is roughly 0.6 GB as an absolute lower bound; the real file will be larger because
  some layers are 8-bit and there is metadata. Do not quote this number as a result.
- [unknown] Tokens per second and time to the first token on a mid-range phone.
- [unknown] Battery and heat during a long explanation.

Plan: pick one real mid-range ARM phone, export the model, run the demo app from the ExecuTorch
examples repository, and record load time, memory use, tokens per second and the `.pte` size.
Report those measured numbers, not estimates.

## 6. Porting the detectors

- Export the SMS model's TF-IDF vocabulary, IDF weights, coefficients and thresholds to a JSON
  file; recompute the TF-IDF vector and score in Kotlin.
- Port the URL features, the lookalike rules, the known-site list and the SMS link checks.
- **Verification step:** run the same 200+ messages and URLs through the laptop model and the
  Android port and require matching scores (within rounding) and identical risk levels.
- The brand and known-site lists are plain data files and move over unchanged.

## 7. Risks

| Risk | Mitigation |
|---|---|
| 1B model too slow or too large on a low-end phone | Detectors-only mode; measured limits documented; optional smaller model if one is available |
| ExecuTorch LLM API changes (documented as experimental) | Pin the version; wrap it behind one adapter class |
| Port differs from the Python model | Score-matching test set (section 6) |
| Llama licence terms | Read and comply; do not bundle the model in a public repository |
| Weak explanations from a 1B model | Validator plus fixed fallback explanation |

## 8. Honest summary for the report

LocalShield AI is a working laptop prototype. The Android/ExecuTorch deployment is **researched and
planned, not built**. Before any claim that it runs on a phone, the steps in section 5 must be
completed and the measurements recorded.

## Sources

- ExecuTorch, "Running LLMs on Android": https://docs.pytorch.org/executorch/main/llm/run-on-android.html
- ExecuTorch, "Using ExecuTorch on Android" (0.7): https://docs.pytorch.org/executorch/0.7/using-executorch-android.html
- Arm Learning Path, "Prepare the Llama models" (Llama 3.2 1B, XNNPACK): https://learn.arm.com/learning-paths/mobile-graphics-and-gaming/build-llama3-chat-android-app-using-executorch-and-xnnpack/4-prepare-llama-models/