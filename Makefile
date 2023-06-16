test:
	flake8 && pytest --cov=nx

check: test

wheel: test
	pip wheel --no-cache-dir --no-deps "nx-workers @ file://$(PWD)/"

install:
	pip install -e .[dev]

deploy: wheel
	bash deploy.sh

.PHONY: test check wheel install deploy
