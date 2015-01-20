#!/bin/bash

TITAN_DIR="/usr/local/titan-0.5.3-hadoop2/bin"
cd $TITAN_DIR

#This is based on rexster.sh, included in the titan bin dir

# This script is tested mostly under Linux and Mac OS X, but it 
# can also run through Cygwin.
#
# When running through Cygwin, Java file paths and CLASSPATH require
# special handling.  Cygwin uses *NIX style paths, but Java is outside
# Cygwin's control and uses Windows style paths.  Any CLASSPATH or 
# file paths strings provided to Java must be sent through the utility
# command `cygpath --path --windows`.

set_unix_paths() {
	CP="$(echo ../conf ../lib/*.jar . | tr ' ' ':')"
	CP="$CP:$(find -L ../ext/ -name "*.jar" | tr '\n' ':')"
	export CLASSPATH="$CP"
	PUBLIC=../public/
	LOG_DIR=../log
}

convert_unix_paths_to_win_paths() {
	export CLASSPATH="$(echo $CLASSPATH | cygpath --windows --path -f -)"
	PUBLIC="$(echo $PUBLIC | cygpath --windows --path -f -)"
	LOG_DIR="$(echo $LOG_DIR | cygpath --windows --path -f -)"
}

set_unix_paths
case "`uname`" in
    CYGWIN*) convert_unix_paths_to_win_paths ;;
esac

# Find Java
if [ "$JAVA_HOME" = "" ] ; then
    JAVA="java"
else
    JAVA="$JAVA_HOME/bin/java"
fi

# Launch the application
"$JAVA" $JAVA_OPTIONS com.tinkerpop.rexster.Application -x -rp 7183
# Return the program's exit code
exit $?