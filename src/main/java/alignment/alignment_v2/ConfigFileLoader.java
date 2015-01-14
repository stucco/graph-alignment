package alignment.alignment_v2;

import java.io.*;
import java.util.*;

import org.yaml.snakeyaml.Yaml;

public class ConfigFileLoader {

	private static final String CONFIG_FILE = "alignment.yaml";
	String path = null;

	public ConfigFileLoader(){
		this.path = CONFIG_FILE;
	}

	public ConfigFileLoader(String path){
		this.path = path;
	}

	public Map<String, Map<String, Object>> getVertexConfig(String configHeading) {

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
}


