This project is a dependency of Stucco, and should not normally need to be run independently.  Stucco will install and use this project as needed.

For development, this project can be installed and built with `./setup.sh`

Note that this will build the project (and dependencies) without running the tests.  

To run the tests, first make sure that Titan is installed, and that the Titan path is correctly specified at the beginning of the `start-test-server.sh` and `stop-test-server.sh` scripts.

The test server can be launched with `sudo ./start-test-server.sh > /dev/null` and stopped with `sudo ./stop-test-server.sh` .

Once the test server is up, test can be run with `mvn test` .