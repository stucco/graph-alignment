This project is a dependency of Stucco, and should not normally need to be run independently.  Stucco will install and use this project as needed.

# Setup for Testing with Titan in-memory instance

First, make sure that Titan is installed, and that the Titan path is correctly specified at the beginning of the `start-titan-test-server.sh` and `stop-titan-test-server.sh` scripts.

The test server can be launched with `sudo ./start-titan-test-server.sh > /dev/null` and stopped with `sudo ./stop-titan-test-server.sh` .

# Setup for Testing with Tinkergraph (Not supported)

*This was added for some earlier testing, but is not maintained, and may not work.*

run `./install-tinkergraph-test-server.sh` to download and install a rexster/tinkergraph instance in this directory.

This instance can be started/stopped with the `start-test-server.sh` and `stop-test-server.sh` scripts.

For extra debugging output, add a `log4j.properties` file to the `rexster-server` directory, and modify the `start-test-server.sh`. script to invoke rexster with `/bin/rexster.sh --start -d`  (The `log4j.properties` file is described in the rexster documentation.)

# Running the tests

Once either test server is up, the tests can be run with `mvn test`.