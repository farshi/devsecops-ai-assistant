SHELL := /bin/bash

help:
	@echo "make help"
	@echo "make tree"
	@echo "make claude"

tree:
	@find . -maxdepth 3 | sort

claude:
	claude
