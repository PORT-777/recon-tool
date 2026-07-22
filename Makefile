.PHONY: install run clean

install:
	pip install -e .

venv:
	python3 -m venv venv && . venv/bin/activate && pip install -e .

run:
	./recon -d example.com -b all

clean:
	rm -rf venv/ __pycache__/ *.pyc *.json *.html screenshots/
