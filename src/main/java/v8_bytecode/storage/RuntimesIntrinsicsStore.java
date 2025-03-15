package v8_bytecode.storage;

//import static java.util.Map.entry;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

import v8_bytecode.RuntimeFuncArg;

public final class RuntimesIntrinsicsStore implements Serializable {
	private final List<List<RuntimeFuncArg>> allArgs;
	private final List<String> names;
	private final Map<Integer, Integer> intrinsicsToRuntimes;
	
	public RuntimesIntrinsicsStore(final List<String> names, final List<List<RuntimeFuncArg>> allArgs, Map<Integer, Integer> intrinsicsToRuntimes) {
		this.allArgs = allArgs;
		this.names = names;
		this.intrinsicsToRuntimes = intrinsicsToRuntimes;
	}
	
	public List<RuntimeFuncArg> getArgs(int index) {
		return allArgs.get(index);
	}
	
	public List<String> getNames() {
		return names;
	}
	
	public int getNamesCount() {
		return names.size();
	}
	
	public String getRuntimeName(int index) {
		return names.get(index);
	}
	
	public int getIntrinsicsCount() {
		return intrinsicsToRuntimes.size();
	}
	
	public String getIntrinsicName(int index) {
		return String.format("_%s", names.get(intrinsicsToRuntimes.get(index) - names.size()));
	}
}
