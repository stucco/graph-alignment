package alignment.alignment_v2;

import java.io.*;
//import java.nio.file.Files;
import java.util.*;

import org.apache.commons.configuration.Configuration;
//import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.yaml.snakeyaml.Yaml;

public class ConfigFileLoader {

	//private static final String CONFIG_FILE = "alignment.yaml";
	private static final String CONFIG_FILE = "stucco_schema.json";
	String path = null;

	public ConfigFileLoader(){
		this.path = CONFIG_FILE;
	}

	public ConfigFileLoader(String path){
		this.path = path;
	}

	public Map<String, Map<String, Object>> getVertexConfig(String configHeading){
		//return getVertexConfigFromYaml(configHeading);
		return getVertexConfigFromJsonSchema(configHeading);
	}
	
	private Map<String, Map<String, Object>> getVertexConfigFromYaml(String configHeading) {

		ArrayList<Object> array = null;

		Yaml yamlReader = new Yaml();
		InputStream stream = ConfigFileLoader.class.getClassLoader().getResourceAsStream(path);
		Map<String, Map<String, Object>> configMap = (Map<String, Map<String, Object>>) yamlReader.load(stream);
		Map<String, Map<String, Object>> vertexConfigMap = new HashMap<String, Map<String, Object>>();

		Map<String, Object> map = (Map<String, Object>) configMap.get("vertices");

		Map<String, Object> vertMap = (Map<String, Object>) map.get(configHeading);
		Map<String, Object> propMap = null;
		for (String s1 : vertMap.keySet())	{
			propMap = (HashMap<String, Object>)vertMap.get(s1);
			vertexConfigMap.put(s1, propMap);
		}

		return vertexConfigMap;
	}
	
	//returns a map of prop names to merge methods, for each vert name
    private Map<String, Map<String, Object>> getVertexConfigFromJsonSchema(String vertexName){
    	InputStream stream = ConfigFileLoader.class.getClassLoader().getResourceAsStream(path);
    	JSONTokener j = new JSONTokener(stream);
    	JSONObject ontology = new JSONObject(j); 

    	HashMap<String, Map<String, Object>> vertexConfigMap = new HashMap<String, Map<String, Object>>();
    	JSONObject definitions = ontology.getJSONObject("definitions");
    	
    	HashMap<String, Object> propConfig = null;
    	JSONObject currVert = definitions.getJSONObject(vertexName);
    	JSONArray items = currVert.getJSONArray("allOf");
    	
    	for(int i=0; i<items.length(); i++){
    		JSONObject item = items.getJSONObject(i);
    		if(item.has("properties")){
    			JSONObject currProps = item.getJSONObject("properties");
        		Iterator<String> k = currProps.keys();
        		while(k.hasNext()){
        			String prop = k.next();
        			propConfig = new HashMap<String, Object>();
        			
        			String comparisonFunction = currProps.getJSONObject(prop).optString("comparisonFunction");
        			if(comparisonFunction == null || comparisonFunction == "")
        				comparisonFunction = "none";
        			propConfig.put("comparisonFunction", comparisonFunction);
        			
        			Double comparisonWeight = currProps.getJSONObject(prop).optDouble("comparisonWeight");
        			if(comparisonWeight == null || comparisonWeight == Double.NaN)
        				comparisonWeight = 0.0;
        			propConfig.put("comparisonWeight", comparisonWeight);
        			
        			String resolutionFunction = currProps.getJSONObject(prop).optString("resolutionFunction");
        			if(resolutionFunction == null || resolutionFunction == "")
        				resolutionFunction = "keepNew";
        			propConfig.put("resolutionFunction", resolutionFunction);
        			
        			vertexConfigMap.put(prop, propConfig);
        		}
    		}
    	}
    	return vertexConfigMap;
	}
	
	public static Configuration dbConfigFromFile(String configFilePath){
		File configFile = new File(configFilePath);
		Map<String, Object> fullConfigMap = configMapFromFile(configFile);
		Map<String, Object> dbConfigMap = (Map<String, Object>) fullConfigMap.get("database_connection");
		PropertiesConfiguration dbConfig = new PropertiesConfiguration();
		for(String key : dbConfigMap.keySet()){
			dbConfig.addProperty( key, dbConfigMap.get(key));
		}
		return dbConfig;
	}
	
	public static Map<String, Object> configMapFromFile(File configFile){
		Map<String, Object> configMap = null;
		try {
			Yaml yaml = new Yaml();
			InputStream stream = new FileInputStream(configFile);
			
			configMap = (Map<String, Object>) yaml.load( stream );
			
			//config.load(configFile);
		
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return configMap;
	}
}


