.PHONY: help generate-diagrams generate-dashboard generate-report clean

help:
	@echo "Available commands:"
	@echo "  make generate-diagrams    - Generate Mermaid diagrams locally"
	@echo "  make generate-dashboard   - Generate Excalidraw dashboard locally"
	@echo "  make generate-report      - Generate complete security report"
	@echo "  make clean               - Clean generated files"

generate-diagrams:
	@echo "📊 Generating Mermaid diagrams..."
	python scripts/generate-mermaid-diagrams.py \
		--input /tmp/artifacts \
		--output diagrams/mermaid

generate-dashboard:
	@echo "🎨 Generating Excalidraw dashboard..."
	python scripts/generate-excalidraw-dashboard.py \
		--input /tmp/artifacts \
		--output diagrams/excalidraw

generate-report: generate-diagrams generate-dashboard
	@echo "📝 Generating security report..."
	python scripts/generate-security-report.py \
		--mermaid diagrams/mermaid \
		--excalidraw diagrams/excalidraw \
		--output security-report.md

clean:
	@echo "🧹 Cleaning generated files..."
	rm -rf diagrams/
	rm -f security-report.md
	rm -rf __pycache__/
	rm -rf *.pyc
