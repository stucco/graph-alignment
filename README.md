This project is a dependency of Stucco, and should not normally need to be run independently.  Stucco will install and use this project as needed.

# Setup for Testing with Tinkergraph

run `./install-tinkergraph-test-server.sh` to download and install a rexster/tinkergraph instance in this directory.

This instance can be started/stopped with the `start-test-server.sh` and `stop-test-server.sh` scripts.

# Setup for Testing with Titan in-memory instance

First, make sure that Titan is installed, and that the Titan path is correctly specified at the beginning of the `start-titan-test-server.sh` and `stop-titan-test-server.sh` scripts.

The test server can be launched with `sudo ./start-titan-test-server.sh > /dev/null` and stopped with `sudo ./stop-titan-test-server.sh` .

# Running the tests

Once either test server is up, the tests can be run with `mvn test`.