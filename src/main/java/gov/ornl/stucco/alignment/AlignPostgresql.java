package gov.ornl.stucco.alignment;

import gov.ornl.stucco.Align;
import gov.ornl.stucco.DBConnectionJson;

import org.json.JSONObject;  

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Aligning JSON graph with existing graph inside of Postgresql server.
 *
 * @author Maria Vincent
 */ 

public class AlignPostgresql implements Align {
	private static final int VERTEX_RETRIES = 2;
	private static final int EDGE_RETRIES = 2;
	private boolean SEARCH_FOR_DUPLICATES = false;
	private boolean ALIGN_VERT_PROPS = false;
	private DBConnectionJson connection = null;

	private Logger logger = null;

	public AlignPostgresql() {
		logger = LoggerFactory.getLogger(AlignPostgresql.class);
		connection = new DBConnectionJson();
	}

	public void setSearchForDuplicates(boolean search) {
		SEARCH_FOR_DUPLICATES = search;
	}

	public void setAlignVertProps(boolean align) {
		ALIGN_VERT_PROPS = align;
	}
	
	/* 
	 *	for test purpose only 
	 */
	public DBConnectionJson getConnection() {
		return connection;
	}

	public boolean load(JSONObject newGraphSection) {
		connection.bulkLoadGraph(newGraphSection);

		return true;
	}
}