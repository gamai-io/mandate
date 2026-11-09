.PHONY: test demo

test:
	PYTHONPATH=. python3 tests/test_mandate.py

demo:
	PYTHONPATH=. ./bin/mandate check --intent examples/intent.json
	PYTHONPATH=. ./bin/mandate propose --intent examples/intent.json
