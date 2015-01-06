This project is a dependency of Stucco, and should not normally need to be run independently.  Stucco will install and use this project as needed.

For development, this project can be installed and built with `./setup.sh`

Note that this will build the project (and dependencies) without running the tests.  
The tests can be run with simply `mvn test`, however these tests require a running Titan instance (version 0.5.x).  
**Running the tests will clear the current Titan database contents!**  Use with caution!