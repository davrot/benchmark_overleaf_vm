.DEFAULT_GOAL := help
.PHONY: help admin test down setup testuser integration-tests admin-login-test integration ci

help: ## Show this help
	@echo "Available targets (use 'make <target>'):"
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":"} {split($$2,parts,"##"); printf "  %-25s %s\n", $$1, parts[2] }'



admin: ## Create the Overleaf admin user with credentials configured in ../production/make_overleaf_admin_user.bash
	@echo "Creating admin user..."
	bash ../production/make_overleaf_admin_user.bash

test: ## Run Go tests in this folder
	@echo "Running Go tests..."
	cd $(CURDIR) && go test ./... -v

down: ## Tear down the stack
	@echo "Tearing down production stack..."
	cd ../production && docker compose down || true



# User-facing alias: run full setup (stop/clean, bring services up, create admin)
setup: ## Run full setup: stop+clean, start services, create admin (user-friendly)
	@echo "Running setup (stop+clean, start services, create admin)..."
	cd $(CURDIR) && go test ./... -run 'TestEnv_|TestServices_|TestAdmin_' -v





# Run only integration subtests (e.g., admin login and downstream tests)
integration-tests: ## Run integration subtests (TestIntegration_Subtests)
	@echo "Running integration subtests (TestIntegration_Subtests)..."
	cd $(CURDIR) && go test ./... -run TestIntegration_Subtests -v

# Create a test user via admin, extract email from mailsink, set password and verify login
testuser: ## Create a test user and verify login (TestMakeTestUser)
	@echo "Creating test user and verifying login..."
	cd $(CURDIR) && go test -count=1 ./... -run TestMakeTestUser -v

testuser-clean: ## Delete the test user and verify login fails (TestTestUserClean)
	@echo "Deleting test user and verifying cleanup..."
	cd $(CURDIR) && go test -count=1 ./... -run TestTestUserClean -v

testproject: ## Create initial project for test user (TestCreateInitialProject)
	@echo "Creating initial project for test user..."
	cd $(CURDIR) && go test -count=1 ./... -run TestCreateInitialProject -v

testproject-clean: ## Trash projects named Test1/Test2 and verify they are removed (TestProjectClean)
	@echo "Cleaning up test projects..."
	cd $(CURDIR) && go test -count=1 ./... -run TestProjectClean -v

# Combined cycle targets
testuser-cycle: ## Run testuser -> testuser-clean
	@echo "Running testuser then testuser-clean..."
	@$(MAKE) testuser || exit 1
	@$(MAKE) testuser-clean || exit 1

testproject-cycle: ## Ensure testuser exists, create project, then clean projects
	@echo "Ensuring testuser, creating project, then cleaning projects..."
	@$(MAKE) testuser || exit 1
	@$(MAKE) testproject || exit 1
	@$(MAKE) testproject-clean || exit 1

test-cycle: ## Run full testuser cycle then project cycle
	@echo "Running full test cycle: testuser-cycle then testproject-cycle..."
	@$(MAKE) testuser-cycle || exit 1
	@$(MAKE) testproject-cycle || exit 1

# Run just the admin login subtest for quick debugging
admin-login-test: ## Run only the admin login subtest
	@echo "Running admin login subtest..."
	cd $(CURDIR) && go test ./... -run TestIntegration_Subtests/admin:_login_accepted -v

# Full integration flow: setup -> integration-tests -> down
# Set NO_TEARDOWN=1 to skip automatic teardown for debugging.
integration: ## Perform a full integration run: setup, run integration tests, tear down
	@$(MAKE) setup integration-tests
	@if [ -z "$(NO_TEARDOWN)" ]; then \
		$(MAKE) down; \
	else \
		echo "NO_TEARDOWN set; leaving stack running for debugging"; \
	fi

# Alias for CI
ci: ## Alias for CI
	@$(MAKE) integration
