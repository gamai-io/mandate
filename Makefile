.PHONY: test demo

test:
	PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_*.py'

demo:
	PYTHONPATH=. ./bin/mandate check --intent examples/intent.json
	PYTHONPATH=. ./bin/mandate propose --intent examples/intent.json
