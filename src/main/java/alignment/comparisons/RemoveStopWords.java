package alignment.comparisons;

//in constructor function takes a file with stop words

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.*;

public class RemoveStopWords {

	private BufferedReader br;
	private Set<String> hm;

	public RemoveStopWords(String file)	{

		try	{
			br = new BufferedReader (new FileReader (file));	
			String str = new String();
			hm = new HashSet<String>();

			while ((str = br.readLine()) != null)	{
				hm.add(str);
			}

		} catch (FileNotFoundException e)	{
			e.printStackTrace();
		} catch (IOException e)	{
			e.printStackTrace();
		}
	}

	boolean containsString (String str)	{	
		return hm.contains(str);
	}
}
