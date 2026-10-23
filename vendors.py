"""Vendor / package tagging rules.

Each rule: (display name, regex matched against a lowercase haystack made of
CPE vendor:product strings, KEV vendor/product, GHSA package names and the
description). Regexes use word-ish boundaries to limit false positives.
CPE-style tokens look like  "microsoft:windows_11" so we also match those.
"""
import re

RULES = [
    ("Microsoft", r"\bmicrosoft\b|\bwindows (server|10|11)\b|\bexchange server\b|\bsharepoint\b|\bazure\b|\bms office\b"),
    ("Google/Chrome/Android", r"\bgoogle\b|\bchrome\b|\bchromium\b|\bandroid\b|\bv8\b|\bskia\b"),
    ("Apple", r"\bapple\b|\bmacos\b|\bios\b|\bipados\b|\bsafari\b|\bwebkit\b|\bwatchos\b|\btvos\b|\bvisionos\b"),
    ("Cisco", r"\bcisco\b"),
    ("Fortinet", r"\bfortinet\b|\bfortios\b|\bfortigate\b|\bfortiweb\b|\bfortimanager\b|\bfortianalyzer\b|\bfortiproxy\b|\bfortisiem\b|\bfortiswitch\b|\bfortiguard\b|\bforticlient"),
    ("Palo Alto", r"\bpalo ?alto\b|\bpan-os\b|\bglobalprotect\b|\bcortex xdr\b|\bpaloaltonetworks\b"),
    ("Ivanti", r"\bivanti\b|\bpulse ?secure\b|\bpulse connect\b|\bmobileiron\b"),
    ("VMware/Broadcom", r"\bvmware\b|\bbroadcom\b|\besxi\b|\bvcenter\b|\bvmware tools\b|\bspring (framework|boot)\b|\bspringframework\b"),
    ("Oracle", r"\boracle\b|\bweblogic\b|\bmysql\b|\bjava se\b|\bglassfish\b"),
    ("Adobe", r"\badobe\b|\bacrobat\b|\bcoldfusion\b|\bmagento\b|\bphotoshop\b"),
    ("Citrix", r"\bcitrix\b|\bnetscaler\b|\bcloud software group\b"),
    ("SAP", r"\bsap\b|\bsap se\b|\bnetweaver\b"),
    ("Linux Kernel", r"\blinux kernel\b|\blinux:linux_kernel\b|\bin the linux kernel\b|\bkernel\.org\b"),
    ("OpenSSL", r"\bopenssl\b"),
    ("Apache", r"\bapache\b|\btomcat\b|\bhttpd\b|\bstruts\b|\bactivemq\b|\bkafka\b|\bsolr\b|\bairflow\b"),
    ("nginx", r"\bnginx\b"),
    ("OpenSSH", r"\bopenssh\b"),
    ("Log4j", r"\blog4j\b|\blog4shell\b"),
    ("Atlassian", r"\batlassian\b|\bconfluence\b|\bjira\b|\bbitbucket\b|\bbamboo\b"),
    ("GitLab", r"\bgitlab\b"),
    ("GitHub", r"\bgithub:|\bgithub enterprise\b"),
    ("WordPress", r"\bwordpress\b|\bwoocommerce\b"),
    ("Docker/Kubernetes", r"\bdocker\b|\bmoby\b|\bcontainerd\b|\brunc\b|\bkubernetes\b|\bkubelet\b|\bkube-apiserver\b|\bk8s\b|\bhelm\b|\bingress-nginx\b"),
    ("Mozilla", r"\bmozilla\b|\bfirefox\b|\bthunderbird\b"),
    ("Jenkins/Grafana", r"\bjenkins\b|\bgrafana\b"),
    ("Red Hat", r"\bred ?hat\b|\bopenshift\b"),
    ("SolarWinds", r"\bsolarwinds\b"),
    ("Zoom", r"\bzoom (workplace|client|meeting|video|rooms)|\bzoom:zoom|\bzoom video\b"),
    ("Veeam", r"\bveeam\b"),
    ("SonicWall", r"\bsonicwall\b"),
    ("F5", r"\bf5\b|\bbig-ip\b"),
    ("Juniper", r"\bjuniper\b|\bjunos\b"),
    ("Zyxel/TP-Link/D-Link", r"\bzyxel\b|\btp-?link\b|\bd-?link\b"),
    ("Samsung/Qualcomm/MediaTek", r"\bsamsung\b|\bqualcomm\b|\bmediatek\b"),
    ("Intel/AMD/NVIDIA", r"\bintel\b|\bamd\b|\bnvidia\b"),
    ("Progress/MOVEit", r"\bmoveit\b|\bprogress software\b|\bwhatsup gold\b"),
    ("Node.js/Python/PHP", r"\bnode\.?js\b|\bpython:python\b|\bcpython\b|\bphp:php\b|\bphp group\b"),
    ("curl/libs", r"\bcurl\b|\blibcurl\b|\bzlib\b|\blibxml2\b|\blibwebp\b|\bglibc\b|\bsqlite\b"),
]
COMPILED = [(n, re.compile(rx, re.I)) for n, rx in RULES]

# Popular packages on npm / PyPI / etc. (matched by exact lowercase package name)
POPULAR_PACKAGES = {
    "npm": {"react", "react-dom", "next", "express", "lodash", "axios", "webpack", "vite", "vue", "angular",
            "@angular/core", "typescript", "moment", "jquery", "socket.io", "ws", "minimatch", "semver",
            "node-fetch", "tar", "nuxt", "svelte", "electron", "body-parser", "jsonwebtoken", "cookie",
            "path-to-regexp", "serialize-javascript", "undici", "postcss", "babel", "@babel/core",
            "dompurify", "handlebars", "ejs", "pug", "mongoose", "sequelize", "prisma", "@prisma/client",
            "nodemailer", "multer", "passport", "koa", "fastify", "@nestjs/core", "got", "request", "yargs",
            "glob", "braces", "micromatch", "form-data", "follow-redirects", "send", "serve-static", "qs"},
    "pip": {"django", "flask", "requests", "urllib3", "numpy", "pandas", "pillow", "cryptography", "jinja2",
            "fastapi", "starlette", "sqlalchemy", "tensorflow", "torch", "pytorch", "scikit-learn", "pyyaml",
            "aiohttp", "werkzeug", "setuptools", "pip", "celery", "paramiko", "lxml", "scrapy", "transformers",
            "langchain", "gradio", "mlflow", "ansible", "pydantic", "tornado", "certifi", "idna", "twisted",
            "apache-airflow", "jupyter", "notebook", "ray", "streamlit", "djangorestframework"},
    "go": {"golang.org/x/net", "golang.org/x/crypto", "github.com/gin-gonic/gin", "k8s.io/kubernetes"},
    "maven": {"org.springframework:spring-core", "org.springframework.boot:spring-boot",
              "org.apache.logging.log4j:log4j-core", "org.apache.tomcat:tomcat-embed-core"},
    "rubygems": {"rails", "rack", "nokogiri", "devise"},
    "composer": {"laravel/framework", "symfony/symfony", "wordpress/wordpress"},
    "nuget": set(),
    "rust": {"tokio", "hyper", "openssl"},
}
ECO_LABEL = {"npm": "npm popular", "pip": "PyPI popular", "go": "Go popular", "maven": "Maven popular",
             "rubygems": "RubyGems popular", "composer": "Composer popular", "rust": "Rust popular"}


def tag_vendors(haystack, ecosystem_pkgs=()):
    """haystack: text; ecosystem_pkgs: iterable of (ecosystem, package name)."""
    tags = []
    hs = haystack.lower()
    for name, rx in COMPILED:
        if rx.search(hs):
            tags.append(name)
    for eco, pkg in ecosystem_pkgs:
        eco = (eco or "").lower()
        pkg = (pkg or "").lower()
        if pkg in POPULAR_PACKAGES.get(eco, ()):
            lab = ECO_LABEL.get(eco)
            if lab and lab not in tags:
                tags.append(lab)
    return tags
