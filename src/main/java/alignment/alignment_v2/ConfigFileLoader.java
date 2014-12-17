package alignment.alignment_v2;

import java.io.*;
import java.util.*;

import org.yaml.snakeyaml.Yaml;

public class ConfigFileLoader {

		private static final String CONFIG_FILE = "alignment.yaml";
		
		public Map<String, Map<String, Object>> getConfig(String configHeading) {
				
			ArrayList<Object> array = null;
			
			Yaml yamlReader = new Yaml();
			Map<String, Map<String, Object>> configMap = (Map<String, Map<String, Object>>) yamlReader.load(ConfigFileLoader.class.getClassLoader().getResourceAsStream(CONFIG_FILE));
			Map<String, Map<String, Object>> innerMap = new HashMap<String, Map<String, Object>>();
			
			for (String key : configMap.keySet())	{ 
				Map<String, Object> map = (Map<String, Object>) configMap.get(key);
				if (map.get(configHeading) != null)	{
					array = (ArrayList<Object>) map.get(configHeading);
					
					for (int i = 0; i < array.size(); i++){
						Map<String, Object> subMap = (Map<String, Object>) array.get(i);
						for (String s1 : subMap.keySet())	{
							innerMap.put(s1, (HashMap<String, Object>)subMap.get(s1));
						}
					}

				}
			}
			return innerMap;
		}
}


