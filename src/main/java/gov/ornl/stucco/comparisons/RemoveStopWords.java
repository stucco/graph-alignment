package gov.ornl.stucco.comparisons;

//in constructor function takes a file with stop words
import java.util.Collections;
import java.util.Set;
import java.util.HashSet;

import java.io.FileNotFoundException;
import java.io.IOException;

import org.apache.commons.io.LineIterator;
import org.apache.commons.io.IOUtils;

public abstract class RemoveStopWords {
	private static final String _stop_words_file = "StopWords.txt";
	private static Set<String> hm;
	static {
		try {
			LineIterator iterator = IOUtils.lineIterator(RemoveStopWords.class.getClassLoader().getResourceAsStream(_stop_words_file), "UTF-8");
			try {
				Set<String> set = new HashSet<String>();
				while (iterator.hasNext()) {
					set.add(iterator.next());
				}
				hm = Collections.unmodifiableSet(set);
			} finally {
				iterator.close();
			}
		}	catch (FileNotFoundException e)	{
			e.printStackTrace();
		} catch (IOException e)	{
			e.printStackTrace();
		} 
	}

	public static boolean containsString (String str)	{	
		return hm.contains(str);
	}
}
