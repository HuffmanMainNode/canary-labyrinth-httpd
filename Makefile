PYTHON ?= python3

.PHONY: test

test:
	$(PYTHON) -m unittest discover -v
