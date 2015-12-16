package alignment.alignment_v2;

public class Constraint {

	/*
	 * T.gt - greater than
	 * T.gte - greater than or equal to
	 * T.eq - equal to
	 * T.neq - not equal to
	 * T.lte - less than or equal to
	 * T.lt - less than
	 * T.in - contained in a list
	 * T.notin - not contained in a list
	 */
	public enum Condition{
		gt, gte, eq, neq, lte, lt, in, notin
	}
	public String condString(Condition c){
		if(c == Condition.eq) return "T.eq";
		if(c == Condition.neq) return "T.neq";
		if(c == Condition.gt) return "T.gt";
		if(c == Condition.gte) return "T.gte";
		if(c == Condition.lt) return "T.lt";
		if(c == Condition.lte) return "T.lte";
		if(c == Condition.in) return "T.in";
		if(c == Condition.notin) return "T.notin";
		return null;
	}
	
	public Condition cond;
	
	public String prop;
	public Object val;
	
	public Constraint(String property, Condition condition, Object value){
		this.prop = property;
		this.cond = condition;
		this.val = value;
	}
	
}
