package gov.ornl.stucco;

import gov.ornl.stucco.alignment.AlignDB;
import gov.ornl.stucco.alignment.AlignPostgresql;

public abstract class AlignFactory {

	public static enum Type {
		TITAN,
		INMEMORY,
		ORIENTDB,
		NEO4J,
		POSTGRESQL
	}

	public static Align getAlign() {
		String type = System.getenv("STUCCO_DB_TYPE");
		if (type == null) {
			throw (new NullPointerException("Missing environment variable STUCCO_DB_TYPE"));
		} 

		switch (Type.valueOf(type)) {
	    case INMEMORY:
	        return new AlignDB();
	    case NEO4J:
	        break;
	    case ORIENTDB: 
	        return new AlignDB();
	    case TITAN:
	        break;
	    case POSTGRESQL:
	        return new AlignPostgresql();
	    default:
	        break;
		}

		return null;
	}
}