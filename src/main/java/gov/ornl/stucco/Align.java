package gov.ornl.stucco;

import org.json.JSONObject;

public interface Align {

	public void setSearchForDuplicates(boolean search);

	public void setAlignVertProps(boolean align);

	public boolean load(JSONObject newGraphSection);

	/* 
	 *	for test purpose only 
	 */
	public DBConnectionJson getConnection();
}