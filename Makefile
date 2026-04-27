# CodeGuard Benchmark v3
# ======================
# Professional SAST tool comparison framework
#
# Quick start:
#   make setup      # Clone vulnerable apps + install tools
#   make run        # Run all tool scanners
#   make evaluate   # Evaluate results against ground truth
#   make report     # Generate full report
#   make all        # setup + run + evaluate + report

PYTHON := python3
APPS_DIR := apps
RUNNERS_DIR := runners
EVALUATOR := evaluator/evaluate.py

.PHONY: all setup run evaluate report clean help

help:
	@echo "CodeGuard Benchmark v3"
	@echo ""
	@echo "Usage:"
	@echo "  make setup       Clone all vulnerable test apps"
	@echo "  make run         Run all SAST tool scanners"
	@echo "  make evaluate    Evaluate results against ground truth"
	@echo "  make all         Full pipeline: setup + run + evaluate"
	@echo ""
	@echo "Individual runners:"
	@echo "  make run-codeguard   Run CodeGuard scanner"
	@echo "  make run-semgrep     Run Semgrep CE"
	@echo "  make run-bandit      Run Bandit (Python only)"
	@echo "  make run-snyk        Run Snyk Code (requires auth)"
	@echo ""
	@echo "Maintenance:"
	@echo "  make clean       Remove reports and output"
	@echo "  make clean-apps  Remove cloned apps"

all: setup run evaluate

# ── Setup: clone vulnerable apps ──────────────────────────────────────────

setup: setup-submodules setup-extras

setup-submodules:
	@echo "==> Initializing git submodules..."
	git submodule update --init --recursive

setup-extras:
	@echo "==> Cloning additional test apps..."
	@mkdir -p $(APPS_DIR)
	@[ -d $(APPS_DIR)/juice-shop ] || git clone --depth=1 https://github.com/juice-shop/juice-shop.git $(APPS_DIR)/juice-shop
	@[ -d $(APPS_DIR)/railsgoat ] || git clone --depth=1 https://github.com/OWASP/railsgoat.git $(APPS_DIR)/railsgoat
	@# Netflix-Skunkworks/vulnpy was removed from GitHub. The 8 trigger
	@# files are reconstructed locally and committed under apps/vulnpy/.
	@[ -d $(APPS_DIR)/vulnpy ] || echo "  apps/vulnpy missing — restore from git history (in-repo)"
	@[ -d $(APPS_DIR)/xvwa ] || git clone --depth=1 https://github.com/s4n7h0/xvwa.git $(APPS_DIR)/xvwa
	@[ -d $(APPS_DIR)/vulnerable-node ] || git clone --depth=1 https://github.com/cr0hn/vulnerable-node.git $(APPS_DIR)/vulnerable-node
	@[ -d $(APPS_DIR)/pixi ] || git clone --depth=1 https://github.com/DevSlop/Pixi.git $(APPS_DIR)/pixi
	@echo "==> All apps ready."

# ── Run: execute all scanners ─────────────────────────────────────────────

run: run-codeguard run-semgrep run-bandit
	@echo ""
	@echo "==> All scanners complete. Run 'make evaluate' to compare."

# Default benchmark run is rules-only. AI triage / AI review are
# decision-helpful in production but distort metrics on synthetic
# benchmark corpora (lesson/challenge code reads as "example → FP" to
# the model, dropping real TPs). Use `make run-codeguard-ai` to
# include them when you want a feel-test number.
run-codeguard:
	@echo ""
	@echo "==> Running CodeGuard (rules-only)..."
	$(PYTHON) $(RUNNERS_DIR)/run_codeguard.py

run-codeguard-ai:
	@echo ""
	@echo "==> Running CodeGuard with AI triage + review..."
	@set -a; [ -f ../codeguard-worker/.env ] && . ../codeguard-worker/.env; set +a; \
		$(PYTHON) $(RUNNERS_DIR)/run_codeguard.py --with-ai

run-semgrep:
	@echo ""
	@echo "==> Running Semgrep CE..."
	$(PYTHON) $(RUNNERS_DIR)/run_semgrep.py

run-bandit:
	@echo ""
	@echo "==> Running Bandit..."
	$(PYTHON) $(RUNNERS_DIR)/run_bandit.py

run-snyk:
	@echo ""
	@echo "==> Running Snyk Code..."
	$(PYTHON) $(RUNNERS_DIR)/run_snyk.py

# ── Evaluate ──────────────────────────────────────────────────────────────

evaluate:
	@echo ""
	@echo "==> Evaluating results..."
	$(PYTHON) $(EVALUATOR) --tools codeguard semgrep bandit

evaluate-all:
	$(PYTHON) $(EVALUATOR) --tools codeguard semgrep bandit snyk

# ── Clean ─────────────────────────────────────────────────────────────────

clean:
	rm -rf reports/codeguard/*.json reports/semgrep/*.json reports/bandit/*.json reports/snyk/*.json
	rm -rf evaluator/output/*

clean-apps:
	rm -rf $(APPS_DIR)/juice-shop $(APPS_DIR)/railsgoat $(APPS_DIR)/vulnpy
	rm -rf $(APPS_DIR)/xvwa $(APPS_DIR)/vulnerable-node $(APPS_DIR)/pixi
