package alignment.alignment_v2;

import java.io.*;
import java.util.*;

import org.yaml.snakeyaml.Yaml;

public class ConfigFileLoader {

		private static final String CONFIG_FILE = "alignment.yaml";
		
		public ArrayList <Object> getConfig(String configHeading) {
				
			ArrayList<Object> array = null;
			
			Yaml yamlReader = new Yaml();
			Map<String, Map<String, Object>> configMap = (Map<String, Map<String, Object>>) yamlReader.load(ConfigFileLoader.class.getClassLoader().getResourceAsStream(CONFIG_FILE));
			
			for (String key : configMap.keySet())	{ 
				Map<String, Object> map = (Map<String, Object>) configMap.get(key);
				if (map.get(configHeading) != null)	{
					array = (ArrayList<Object>) map.get(configHeading);
					/*	for (int i = 0; i < array.size(); i++){
						Map<String, Object> subMap = (Map<String, Object>) array.get(i);
						for (String s1 : subMap.keySet())	{
							System.out.println (s1 + " + " + subMap.get(s1));
							Map<String, Object> secondSubMap = (Map<String, Object>) subMap.get(s1);
							for (String s2 : secondSubMap.keySet())	{
								System.out.println(s2 + " " + secondSubMap.get(s2));
							}
						}
					}
				*/
				}
			}
			
			return array;
		}
}


