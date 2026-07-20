.PHONY: help install generate-diagrams generate-dashboard generate-report clean

help:
	@echo "Available commands:"
	@echo "  make install               - Install Python dependencies"
	@echo "  make generate-diagrams     - Generate Mermaid diagrams locally"
	@echo "  make generate-dashboard    - Generate Excalidraw dashboard locally"
	@echo "  make generate-report       - Generate complete security report"
	@echo "  make clean                 - Clean generated files"

install:
	@echo "Installing dependencies..."
	pip install -r requirements.txt || true
	pip install click jinja2 markdown

generate-diagrams:
	@echo "Generating Mermaid diagrams..."
	mkdir -p diagrams/mermaid
	python scripts/generate-mermaid-diagrams.py \
		--input parsed-data/ \
		--output diagrams/mermaid/

generate-dashboard:
	@echo "Generating Excalidraw dashboard..."
	mkdir -p diagrams/excalidraw
	python scripts/generate-excalidraw-dashboard.py \
		--input parsed-data/ \
		--output diagrams/excalidraw/

generate-report: generate-diagrams generate-dashboard
	@echo "Generating security report..."
	python scripts/generate-security-report.py \
		--mermaid diagrams/mermaid \
		--excalidraw diagrams/excalidraw \
		--output security-report.md

generate-all: install generate-report
	@echo "All visualizations generated!"

clean:
	@echo "Cleaning generated files..."
	rm -rf diagrams/
	rm -f security-report.md
	rm -rf parsed-data/
	rm -rf __pycache__/
	rm -rf *.pyc
