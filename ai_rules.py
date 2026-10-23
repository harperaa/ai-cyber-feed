"""AI-angle classification rules.  EDIT THIS FILE to tune what gets flagged.

classify(text, packages=(), cpes=()) -> None | [{"type": "cause|product|impact", "why": str}, ...]
(list is ordered by priority: cause > product > impact; None = no AI angle)

  cause   vuln discovered by AI / AI-assisted or AI-generated exploit / AI-written code flaw /
          AI agent or attack tooling                                         (highest priority)
  product vuln in AI/ML software: LLM runtimes & servers, ML frameworks, MCP servers, AI coding
          assistants/agents, vector DBs, AI vendor products, prompt injection / jailbreak / model supply chain
  impact  AI-related impact or abuse: attackers using AI, deepfake/AI phishing, AI supply chain,
          AI infrastructure exposed

Matching is case-insensitive except where a pattern uses (?-i:...) (e.g. the word "AI").
Regexes run on title + summary/description (+ product/package/CPE strings for CVE records).
MANUAL pins curated angles for specific CVE ids (shown in addition to heuristics).
"""
import re

AI = r"(?-i:\bAI\b)"                 # the word "AI" in capitals only (avoids 'ai' in other words)
def GAP(n):
    """up to n chars, not crossing a sentence end or newline (dots inside tokens like 5.6 are fine)"""
    return r"(?:(?!\.\s)[^\n]){0,%d}" % n


MODEL = (r"(?:" + AI + r"|llms?|chatgpt|gpt[- ]?[\w.]*|claude|gemini[\w ]{0,12}|codex|copilot|"
         r"frontier (?:ai )?models?|generative|large language models?|agentic|machine learning)")

# ---- cause: AI found the bug / AI-written exploit or code / AI attack tooling --------------------
CAUSE = [
    ("AI-assisted discovery/exploit", AI + r"[- ](?:assisted|powered|driven|generated|discovered|found|written|authored|built|enabled)\b(?!\s+(?:agents?|platforms?|apps?|applications?|workflows?|assistants?|tools?|products?|features?|services?|browsers?|chatbots?|search|ides?|coding)\b)"),
    ("found by AI", r"\b(?:found|discovered|uncovered|identified|detected|audited?|reported|weaponi[sz]ed|assisted)\b" + GAP(70) + r"\b(?:using|with|by|via|through|help of|thanks to)\b" + GAP(30) + r"\b" + MODEL + r"\b"),
    ("exploit built with AI", r"\b(?:built|developed|wrote|written|created|generated|crafted)\b" + GAP(40) + r"\b(?:exploits?|poc|proof[- ]of[- ]concept|exploit chain|full[- ]chain|malware|vulnerabilit\w+)\b" + GAP(40) + r"\b(?:using|with|by|via|through|help of|thanks to)\b" + GAP(30) + r"\b" + MODEL + r"\b"),
    ("AI-found vulnerability (reports)", r"\b(?:vulnerabilit\w+|bugs?|flaws?|zero[- ]?days?|exploits?|rce)\b" + GAP(50) + r"\b(?:found|discovered|uncovered|identified|built|developed)\b" + GAP(25) + r""
                                         r"\b(?:by|with|using)\b" + GAP(15) + r"\b" + MODEL + r"\b"),
    ("AI used to find/build vulns", r"\b(?:us(?:e|es|ed|ing)|leverag\w+|with the help of|powered by|thanks to)\b" + GAP(25) + r"\b" + MODEL + r"\b" + GAP(40) + r"\b(?:to (?:find|discover|hunt|uncover|identify|audit|exploit)|to (?:write|build|develop|craft|generate) (?:an? |the )?(?:exploit|poc|malware|ransomware|payload)|throughout|during (?:discovery|exploit)|for (?:discovery|vulnerability|exploit|bug))"),
    ("AI finds/uncovers vulns", AI + r"[- ](?:agents?|models?|systems?)?\s*(?:uncover|find|discover|hack|hunt|exploit|identif|detect)\w*\b" + GAP(60) + r"\b(?:vulnerabilit\w+|zero[- ]?days?|flaws?|bugs?|rce|cves?)\b"),
    ("AI-generated exploit/malware", r"\b(?:AI|LLM|llm)[- ](?:generated|written|authored|crafted)\b" + GAP(30) + r"\b(?:exploit|malware|code|payload|poc|ransomware)|"
                                     r"\b(?:exploit|malware|payload|poc|ransomware)\b" + GAP(25) + r"\b(?:generated|written|created|built)\b" + GAP(12) + r"\b(?:by|with|using)\b" + GAP(12) + r"\b" + MODEL + r"\b"),
    ("AI-powered attack tooling", r"\b(?:" + AI + r"|agentic|autonomous|llm)[- ]?(?:powered|driven|enabled|based)?[- ]?(?:malware|ransomware|attack|hacking|exploit(?:ation)? (?:tool|framework|agent)|offensive|pentest\w*|red[- ]team)\b"),
    ("frontier models used for exploit work", r"\bfrontier (?:ai )?models?\b|\bfull[- ]chain\b" + GAP(60) + r"\b(?:gpt|claude|gemini|llm|ai)\b"),
    ("AI vuln-research programs", r"\b(?:project glasswing|big sleep|codex security|patch the planet|xbow|aixcc|codemender|openai aardvark|mythos preview|vulnerability discovery (?:by|with) ai)\b"),
    ("AI agent ran the intrusion", r"\b(?:" + AI + r"|llm)[- ]?agents?\b" + GAP(25) + r"\b(?:ran|running|runs|conducted|conducting|performed|performing|carried out|executed|executing)\b" + GAP(20) + r"\b(?:intrusions?|attacks?|breach\w*|hacks?|compromises?|kill[- ]chain)\b"),
    ("AI coding tool leaked the secret", r"\b(?:claude code|copilot|codex|cursor agent|gemini cli|coding agent)\b" + GAP(30) + r"\b(?:embedded|leaked|exposed|logged|printed|echoed)\b" + GAP(30) + r"\b(?:tokens?|secrets?|credentials?|api keys?)\b"),
    ("AI system ran cyberattacks", r"\b(?:" + AI + r"|llm|agentic)[- ]?(?:systems?|tools?|swarms?|agents?)\b" + GAP(40) + r"\b(?:run|ran|runs|launch\w*|conduct\w*|carr(?:y|ied) out)\b" + GAP(15) + r"\b(?:cyber ?-?attacks?|attacks?|intrusions?|hacking campaigns?)\b"),
    ("AI model attacked a real target", r"\b(?:mythos|claude|gpt[- ]?[\w.]*|gemini|model)\b" + GAP(60) + r"\b(?:attack(?:ed|ing)|hack(?:ed|ing)|exploit(?:ed|ing))\b" + GAP(20) + r"\b(?:a )?real\b"),
    ("LLM-assisted vuln (re)discovery", r"\b(?:llm|" + AI + r")\b" + GAP(30) + r"\b(?:techniques?|methods?)\b" + GAP(40) + r"\b(?:discover|rediscover|found|find)\w*\b" + GAP(30) + r"\b(?:vulnerabilit\w+|bugs?|zero[- ]?days?|exploits?)\b"),
    ("AI model took unsanctioned actions", r"\b(?:mythos|claude|gpt[- ]?[\w.]*|gemini|(?:ai|frontier) models?)\b" + GAP(80) + r"\b(?:unsanctioned|unauthori[sz]ed|out[- ]of[- ]scope)\b" + GAP(15) + r"\b(?:actions?|attacks?|hacking|supply[- ]chain)\b"),
    ("attackers' AI agent tooling found", r"\b(?:crew|gang|attackers?|threat actors?|hackers?|operators?|group)\b" + GAP(20) + r"\b" + AI + r"[- ]agents?[- ](?:prompts?|tooling|scripts?|workflows?|playbooks?|exploits?)\b"),
    ("vibe-coded / AI-written code flaw", r"\bvibe[- ]?cod\w+|\b(?:" + AI + r"|llm)[- ]generated code\b|\bcode (?:written|generated) by (?:an? )?(?:" + AI + r"|llm|copilot|chatgpt|claude)\b|\bslopsquat\w*|\bhallucinated (?:package|dependenc)\w+"),
]

# ---- product: vulnerable AI/ML software ----------------------------------------------------------
# package names (GHSA / PyPI / npm / etc.); '*' suffix = prefix match
ML_PACKAGES = [
    "torch", "pytorch*", "tensorflow*", "keras", "transformers", "huggingface-hub", "huggingface_hub", "diffusers", "accelerate",
    "safetensors", "datasets", "tokenizers", "peft", "trl", "sentence-transformers", "onnx", "onnxruntime*", "tflite*",
    "langchain*", "langgraph*", "langsmith", "llama-index*", "llama_index*", "llamaindex*", "llama-cpp-python", "llama_cpp_python",
    "vllm", "sglang", "ollama*", "litellm", "lmdeploy", "text-generation-inference", "tritonclient*", "tritonserver", "bentoml",
    "mlflow*", "ray", "kserve", "kubeflow*", "gradio*", "streamlit", "jupyter*", "jupyterlab", "notebook", "ipython", "comfyui*",
    "openai", "anthropic", "google-generativeai", "google-genai", "cohere", "ai", "@ai-sdk/*", "autogen*", "crewai", "agno", "smolagents",
    "langflow*", "flowise*", "dify*", "open-webui", "open_webui", "n8n-nodes-langchain", "gpt4all", "localai", "ctransformers",
    "chromadb", "qdrant*", "weaviate*", "milvus*", "pymilvus", "pinecone*", "faiss*", "lancedb", "pgvector",
    "mcp", "fastmcp", "mcp-*", "@modelcontextprotocol/*", "*-mcp-server", "*mcp-server*", "deepspeed", "megatron*", "nemo*", "paddlepaddle",
    "scikit-learn", "xgboost", "lightgbm", "numpy-financial-ml", "wandb", "clearml", "gguf", "unsloth", "axolotl", "oobabooga*",
]
_PKG = [re.compile("^" + re.escape(p).replace(r"\*", ".*") + "$", re.I) for p in ML_PACKAGES]
# packages too generic to treat as AI on their own (only counted if the text also looks AI-ish)
GENERIC_PKGS = {"ai", "notebook", "ipython", "datasets", "tokenizers", "trl", "peft", "numpy-financial-ml", "scikit-learn", "xgboost", "lightgbm", "streamlit", "ray", "pgvector"}
# CPE vendor:product tokens
CPE_AI = re.compile(r"(?:ray-project:ray|mlflow:|pytorch:|tensorflow:|google:tensorflow|huggingface:|langchain:|llamaindex:|llama_index|ollama:|vllm|gradio|comfyui|"
                    r"openai:|anthropic:|nvidia:(?:triton|nemo|megatron|aistore|dgx|ai_)|jupyter:|chroma|qdrant|weaviate|milvus|gpt4all|bentoml|langflow|n8n:|"
                    r"onnx|paddlepaddle|keras|scikit-learn|lm-studio|open-webui)", re.I)

PRODUCT = [
    ("LLM runtime/server", r"\bollama\b|\bvllm\b|llama\.cpp|\bllama[- ]?cpp\b|\bllama[- ]?index\b|\bllamaindex\b|\blitellm\b|\blm studio\b|\bgpt4all\b|\blocalai\b|text[- ]generation[- ](?:webui|inference)|open[- ]?webui|\bsglang\b|\blmdeploy\b|\bgguf\b"),
    ("ML framework/platform", r"\bpytorch\b|\btensorflow\b|\bkeras\b|\bonnx\b|hugging ?face|\bhf hub\b|\btransformers (?:library|v?\d)|\blangchain\b|\blanggraph\b|\blangflow\b|\bflowise\b|\bdify\b|\bmlflow\b|\bkubeflow\b|"
                             r"\bgradio\b|\bcomfy ?ui\b|\bjupyter\w*\b|\bray-project\b|\bray (?:ai|dashboard|cluster|is an)\b|\banyscale\b|\bdeepspeed\b|\bmegatron\b|\bnvidia (?:triton|nemo|aistore|dgx|merlin|cuda toolkit)|"
                             r"\btriton inference\b|\bbentoml\b|\bkserve\b|\bpaddlepaddle\b|\bscikit-learn\b|\bcrewai\b|\bautogen\b|\bsmolagents\b|\bwandb\b|\bweights ?& ?biases\b"),
    ("MCP / agent tooling", r"\bmcp\b" + GAP(20) + r"\b(?:server|client|tool|sdk|gateway|inspector|advisor(?:y|ies)|vulnerabilit(?:y|ies))s?\b|\bmodel context protocol\b|\bmcp[- ]server|\bmcp\b(?= (?:server|servers))|"
                            r"\b" + AI + r"[- ](?:agents?|assistants?|coding|code assistant|copilots?|gateways?|models?|platform|framework|chatbots?|workflows?|apps?|sdk|infrastructure|clusters?)\b|"
                            r"\bagentic\b|\bllm[- ](?:agents?|apps?|applications?|gateways?|proxy|tools?)\b|\bautonomous agents?\b"),
    ("AI assistant/vendor product", r"\bchatgpt\b|\bopenai\b|\banthropic\b|\bclaude(?: code| desktop)?\b|\bgemini (?:cli|code assist|ai)\b|\bgoogle gemini\b|\bgithub copilot\b|\bcopilot (?:studio|chat|agent|for)\b|\bmicrosoft 365 copilot\b|"
                                   r"\bcursor (?:ide|editor|ai)\b|\bwindsurf\b|\bcline\b|\bopencode\b|\banysphere\b|programming with ai|\bai code editor\b|\bcodex (?:cli|agent)\b|\bperplexity\b|\bmistral\b|\bdeepseek\b|\bazure ai\b|\bai foundry\b|\bbedrock\b|\bsagemaker\b|\bvertex ai\b|\bwatsonx\b"),
    ("LLM/ML attack class", r"\bprompt[- ]injection\b|\b(?:llm|ai|chatgpt|model|chatbot|gpt)\W+jailbreak\w*|\bjailbreak\w*\W+(?:prompts?|attacks?|llm|models?|chatbots?)\b|\bllm\b|\blarge language models?\b|\bmodel (?:poisoning|supply[- ]chain|theft|extraction|backdoor)\b|\bpickle(?:d)? models?\b|\bdata poisoning\b|\badversarial (?:example|attack|input)s?\b|"
                           r"\bembedding (?:inversion|model)s?\b|\bsystem prompt (?:leak|extraction)\b|\bindirect prompt\b|\bgenerative ai\b|\bmachine learning\b|\bdeep learning\b|\bneural network\b|\bmodel serving\b|\binference (?:server|engine)\b"),
    ("vector DB", r"\bvector (?:database|db|store)s?\b|\bchroma ?db\b|\bqdrant\b|\bweaviate\b|\bmilvus\b|\bpinecone\b|\blancedb\b|\bfaiss\b"),
]

# ---- incident / breach vocabulary: ONE editable list, used by build.py (KW, REDDIT_KW, AI_SEC_KW, "Incident" tag)
# and by the AI "impact" breach rule below. Add a regex fragment here and every filter picks it up.
INCIDENT_TERMS = [
    r"\bbreach(?:ed|es|ing)?\b", r"\bhack(?:ed|er|ers|ing|s)?\b", r"\bcompromis(?:e|ed|es|ing)\b|\bcompromise\b",
    r"cyber ?-?attack(?:s|ed|ers?)?\b", r"\battack(?:ed|s)?\b[^.]{0,30}\b(?:platform|provider|users|customers|servers?|infrastructure)\b",
    r"\bintrusions?\b", r"unauthori[sz]ed (?:access|party|parties|third|actor|user|login)",
    r"data (?:theft|leaks?|exposure|breach\w*)|\bexfiltrat\w+", r"\bleak(?:ed|s|ing)?\b", r"\bexposed (?:data|secrets?|credentials?|keys?|tokens?|databases?|buckets?)",
    r"\bstolen\b|\bsteal(?:s|ing)?\b|\bstole\b|\btheft\b", r"credential (?:theft|stuffing|harvesting|dump)\w*", r"account takeovers?|\bATO\b",
    r"ransomware (?:attack|gang|group)s?|\bransom\w*", r"\bextortion\w*|\bextort\w*", r"\bdefac(?:ed|ement|ing)\b",
    r"supply[- ]chain (?:attack|compromise|breach)s?", r"\bbackdoor(?:ed|s)?\b", r"malicious (?:packages?|extensions?|npm|pypi|versions?|releases?)",
    r"\binfostealers?\b|\binfo-stealers?\b|\bmalware\b", r"\bincidents?\b",
    r"\b(?:rotate|revoke|reset)\b[^.]{0,30}\b(?:keys?|secrets?|credentials?|tokens?|passwords?|env(?:ironment)? vars?|variables)\b",
    r"\burges? (?:all )?(?:users|customers|developers)\b", r"\b(?:warns?|tells?) (?:users|customers|developers|devs)\b",
]
INCIDENT_PAT = "|".join(f"(?:{t})" for t in INCIDENT_TERMS)
INCIDENT_VERBS = r"(?:breach\w*|hack\w*|compromis\w+|cyber ?-?attack\w*|intrusion|unauthori[sz]ed|leak\w*|stolen|stole|steal\w*|exfiltrat\w+|data theft|extort\w*|backdoor\w*|revoke|rotate|takeover)"

# ---- impact: AI-related abuse / impact -----------------------------------------------------------
IMPACT = [
    ("attackers using AI", r"\b(?:attackers?|threat actors?|hackers?|criminals?|scammers?|apt\d*|groups?|malware)\b" + GAP(45) + r"\b(?:us(?:e|es|ed|ing)|leverag\w+|abus\w+|weaponi[sz]\w+|employ\w*|rely\w*|turn\w*)\b" + GAP(25) + r"\b" + MODEL + r"\b"),
    ("deepfake / AI phishing / scams", r"\bdeep ?fakes?\b|\bvoice[- ]clon\w+|\b" + AI + r"[- ](?:generated|voice|powered|written|enabled|driven)?[- ]?(?:phishing|scams?|fraud|impersonation|disinformation|lures?)\b|\b(?:phishing|scams?|fraud)\b" + GAP(30) + r"\b(?:using|with|via|powered by)\b" + GAP(12) + r"\b" + MODEL + r"\b"),
    ("AI supply chain", r"\b" + AI + r"[- ](?:supply[- ]chain|package|model)s?\b" + GAP(40) + r"\b(?:compromis\w+|malicious|backdoor\w*|hijack\w*|poison\w*|trojan\w*)|"
                        r"\b(?:malicious|compromised|backdoored|trojan\w*|poisoned)\b" + GAP(25) + r"\b(?:models?|checkpoints?|hugging ?face|pypi|npm)\b" + GAP(40) + r"\b(?:llm|ai|ml|model|agent|gateway)\w*|"
                        r"\b(?:llm|ai) (?:gateway|proxy|agent)\b" + GAP(60) + r"\b(?:compromis\w+|malicious|token leak|hijack\w*)"),
    ("AI infrastructure exposed / leaked secrets", r"\b(?:exposed|open|unauthenticated|unprotected|internet[- ]facing)\b" + GAP(25) + r"\b(?:ollama|llm|ai (?:server|infrastructure|cluster|endpoint)s?|gpu|inference|comfyui|jupyter|mlflow|ray)\b|"
                                                   r"\b" + AI + r"[- ](?:infrastructure|secrets|api keys?|credentials|tokens?|agents?)\b" + GAP(30) + r"\b(?:exposed|leak\w*|stolen|theft|drain\w*|exfiltrat\w+)\b|"
                                                   r"\b(?:drain|steal|hijack|abus)\w*\b" + GAP(30) + r"\b" + AI + r" agents?\b|\bdistillation attack\b|\bllmjacking\b|\bAPI keys? (?:for|to) (?:openai|anthropic|llm)"),
    ("Railway platform breach (AI inference keys at risk)", r"\brailway(?:\.com|\.app)?\b" + GAP(80) + r"\b(?:breach\w*|hack\w*|compromis\w+|cyber ?-?attack\w*|incident|intrud\w+|unauthori[sz]ed|leak\w*|stolen|drain\w*|rotat\w+|revoke\w*|secrets?|credentials?)\b|"
                                                   r"\b(?:breach\w*|hack\w*|compromis\w+|cyber ?-?attack\w*|intrud\w+|unauthori[sz]ed|rotat\w+|revoke\w*)\b" + GAP(80) + r"\brailway(?:\.com|\.app)?\b"),
    ("breach touching AI provider / inference keys", r"\b" + INCIDENT_VERBS + r"\b" + GAP(80) + r"\b(?:openai|anthropic|hugging ?face|mistral|cohere|replicate|together ?ai|groq|inference (?:providers?|keys?|platforms?|endpoints?)|(?:ai|llm|model) (?:providers?|platforms?|vendors?|labs?)|(?:openai|anthropic|llm|ai|inference|model) (?:api )?(?:keys?|credentials|tokens))\b|"
                                                   r"\b(?:openai|anthropic|hugging ?face|mistral|cohere|replicate|together ?ai|groq|inference (?:providers?|platforms?)|(?:ai|llm|model) (?:providers?|platforms?|vendors?|labs?))\b" + GAP(60) + r"\b" + INCIDENT_VERBS + r"\b"),
]

# Hand-curated angles for specific CVE ids (use for things heuristics cannot know). type, why, optional source url
MANUAL = {
    "CVE-2026-109618": [("cause", "PHP2Shell was found and weaponised with AI help: Wiz Research used Wiz Atlas, Gemini 4 Argon and GPT-5.6-Sol; Calif used an LLM audit (php2shell.com)")],
    "CVE-2026-109619": [("cause", "PHP2Shell was found and weaponised with AI help: Wiz Research used Wiz Atlas, Gemini 4 Argon and GPT-5.6-Sol; Calif used an LLM audit (php2shell.com)")],
}

# Per-feed fallback: items from these feeds are AI-security items even if no keyword matched
FEED_DEFAULT = {"OWASP GenAI": "product", "Embrace The Red": "product", "Simon Willison (prompt injection)": "product"}

# exact package names used for the dedicated GHSA "affects=" query (build.py); wildcards/generic names excluded
ML_QUERY_PACKAGES = sorted({p for p in ML_PACKAGES if "*" not in p and p not in GENERIC_PKGS - {"ray"}})

_C = [(lbl, re.compile(rx, re.I)) for lbl, rx in CAUSE]
_P = [(lbl, re.compile(rx, re.I)) for lbl, rx in PRODUCT]
_I = [(lbl, re.compile(rx, re.I)) for lbl, rx in IMPACT]
SEC_CTX = re.compile(r"vulnerab|insecure|flaw|exploit|\bcve\b", re.I)
RANK = {"cause": 3, "product": 2, "impact": 1}


def _snip(m, text):
    s = text[max(0, m.start() - 15): m.end() + 15].replace("\n", " ").strip()
    return s[:90]


def _pkg_hit(packages):
    for p in packages or ():
        name = p[1] if isinstance(p, (list, tuple)) else str(p).split(":", 1)[-1]
        n = name.lower()
        for rx in _PKG:
            if rx.match(n):
                return name
    return None


def classify(text, packages=(), cpes=(), cve_ids=(), feed=None):
    text = text or ""
    out = {}

    def add(t, why):
        out.setdefault(t, why)

    for cid in cve_ids or ():
        for t, why in MANUAL.get(cid, []):
            add(t, why)
    for lbl, rx in _C:
        m = rx.search(text)
        if m and lbl.startswith("vibe") and not SEC_CTX.search(text):
            continue
        if m:
            add("cause", f"{lbl}: “{_snip(m, text)}”")
            break
    for lbl, rx in _P:
        m = rx.search(text)
        if m:
            add("product", f"{lbl}: “{_snip(m, text)}”")
            break
    if "product" not in out:
        hit = _pkg_hit(packages)
        if hit and (hit.lower() not in GENERIC_PKGS or any(r.search(text) for _, r in _P)):
            add("product", f"AI/ML package: {hit}")
        else:
            for c in cpes or ():
                if CPE_AI.search(c):
                    add("product", f"AI/ML product (CPE): {c}")
                    break
    for lbl, rx in _I:
        m = rx.search(text)
        if m:
            add("impact", f"{lbl}: “{_snip(m, text)}”")
            break
    if not out and feed and feed in FEED_DEFAULT:
        add(FEED_DEFAULT[feed], f"AI-security source: {feed}")
    if not out:
        return None
    return [{"type": t, "why": out[t]} for t in sorted(out, key=lambda k: -RANK[k])]


def rank(angles):
    return max((RANK[a["type"]] for a in angles or []), default=0)
