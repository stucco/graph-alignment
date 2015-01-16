This project is a dependency of Stucco, and should not normally need to be run independently.  Stucco will install and use this project as needed.

When running the tests, first make sure that Titan is installed, and that the Titan path is correctly specified at the beginning of the `start-test-server.sh` and `stop-test-server.sh` scripts.

The test server can be launched with `sudo ./start-test-server.sh > /dev/null` and stopped with `sudo ./stop-test-server.sh` .

Once the test server is up, test can be run with `mvn test` .