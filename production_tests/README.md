Integration tests for Overleaf production stack

Usage:

- Start a fresh stack and run integration tests:

  make integration

- If you want to keep the stack running for debugging, set NO_TEARDOWN=1:

  NO_TEARDOWN=1 make integration

Available make targets (partial):

- `make setup` - run setup sequence: stop+clean, start services, create admin
- `make testuser` - create a test user and verify login (`TestMakeTestUser`)
- `make testuser-clean` - delete the test user and verify login fails (`TestTestUserClean`)
- `make testuser-cycle` - run `testuser` then `testuser-clean`
- `make testproject` - create initial project for test user (`TestCreateInitialProject`)
- `make testproject-clean` - trash Test1/Test2 and verify removal (`TestProjectClean`)
- `make testproject-cycle` - run `testproject` then `testproject-clean`
- `make integration-tests` - run integration subtests (administration/login flows)
- `make admin-login-test` - run only the admin login subtest

Notes:
- The integration tests use HTTPS to `https://overleaf.local`. The test client resolves `overleaf.local` to `127.0.0.1` and skips TLS verification.
- Some tests may rely on `setNewPasswordUrl` returned by the API rather than mailsink emails for speed and reliability.
- The tests use the credentials defined in `test_config.go` (Admin and Test user) to centralize configuration.

Debugging:
- Set `TESTHELPERS_DEBUG=1` to enable additional header logging from the HTTP helpers.

Formatting and linting:

    gofmt -s -w .
    go vet ./...

Full run (recommended):

    make setup
    make testuser
    make testproject
    make testuser-clean
    make testproject-clean

If you need faster cycles during development, consider setting `NO_TEARDOWN=1` to leave the stack running after `make integration`.