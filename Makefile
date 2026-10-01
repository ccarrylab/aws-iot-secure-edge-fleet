.PHONY: infra-init infra-apply test-agent test-guard publish-dry clean

# Infrastructure
infra-init:
	cd infrastructure && terraform init
infra-apply:
	cd infrastructure && terraform apply -var="environment=dev" -auto-approve

# Testing
test-agent:
	cd device-agent && pip install -r requirements.txt pytest pytest-cov && pytest

test-guard:
	sh device-agent/tests/t_ota_boot_guard.sh

# Tooling
publish-dry:
	./publish_release.py --version 1.0.0 --build-dir ./device-agent --dry-run --bucket my-ota-bucket --thing-group my-fleet

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	rm -rf .pytest_cache
