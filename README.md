This project is a dependency of Stucco, and should not normally need to be run independently.  Stucco will install and use this project as needed.

### Running the tests

* Make sure that the graph-db-connection repo is available to maven.  (The .travis.yml file demonstrates an example of this.)

* Like the other stucco components, you will need to set the STUCCO\_DB\_TYPE and STUCCO\_DB\_CONFIG environment variables.  If not using INMEMORY DB, you will need to modify the config files as needed.

* The tests can be run with `mvn test`.
