#!/bin/sh

mvn -q --non-recursive scm:checkout -Dmodule.name=alignment-study
cd alignment-study
mvn -q clean install -Dmaven.test.skip=true
cd ..
mvn clean package -Dmaven.test.skip=true