package v8_bytecode.storage;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import generic.stl.Pair;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import v8_bytecode.RootObject;
import v8_bytecode.structs.ArrayStruct;
import v8_bytecode.structs.ConstantPoolStruct;
import v8_bytecode.structs.ScopeInfoStruct;
import v8_bytecode.structs.SharedFunctionInfoStruct;
import v8_bytecode.structs.TupleStruct;

public final class SharedFunctionStore implements Serializable {
	private String name;
	private long offset;
	private int size;
	private ScopeInfoStore outerScope;
	private ConstantPoolStore cp;
	
	private final Map<String, ScopeInfoStore> scopes;
	
    // Default constructor for placeholder use
    public SharedFunctionStore(Program program) {
        // fields will be updated later
    	this.scopes = new HashMap<>();
    }
	
    // Regular constructor for full initialization.
    public SharedFunctionStore(String initName, long initOffset, int initSize, 
                               ScopeInfoStore initScopeInfo, ScopeInfoStore initOuterScope, 
                               ConstantPoolStore initCp, Program program) {
        this.name = initName;
        this.offset = initOffset;
        this.size = initSize;
        this.outerScope = initOuterScope;
        this.cp = initCp;
        this.scopes = new HashMap<>();
        this.scopes.put("_context", initScopeInfo);
    }
    
    // Update method to fill in fields for a placeholder.
    public void update(String newName, long newOffset, int newSize, 
                       ScopeInfoStore newScopeInfo, ScopeInfoStore newOuterScope, 
                       ConstantPoolStore newCp) {
        this.name = newName;
        this.offset = newOffset;
        this.size = newSize;
        this.outerScope = newOuterScope;
        this.cp = newCp;
        this.scopes.clear();
        this.scopes.put("_context", newScopeInfo);
    }
    

	public static SharedFunctionStore fromStruct(final SharedFunctionInfoStruct struct, final Program program) {
		final Object cached = CacheManager.get(struct);
		if (cached instanceof SharedFunctionStore) {
			return (SharedFunctionStore) cached;
		}
		// Cache placeholder immediately
		//final SharedFunctionStore placeholder = new SharedFunctionStore(null, 0, 0, null, null, null, program);
		//CacheManager.put(struct, placeholder);
		
	    // Create a placeholder instance and cache it
	    SharedFunctionStore placeholder = new SharedFunctionStore(program);
	    CacheManager.put(struct, placeholder);
		
		final ScopeInfoStruct scopeInfo1s = struct.getScopeInfo();
		final Object scopeInfo2s = struct.getOuterScope();
		
		final ScopeInfoStore siStore = ScopeInfoStore.fromStruct(scopeInfo1s);
		final ScopeInfoStore osiStore = ScopeInfoStore.fromStruct(scopeInfo2s);
		
		final ConstantPoolStruct cpStruct = struct.getConstantPool();
		final ConstantPoolStore cp;
		if (cpStruct != null) {
			final List<Pair<Object, Address>> cpItems = cpStruct.getItems();
			
			final List<ConstantPoolItemStore> items = new ArrayList<>();
			for (final Pair<Object, Address> item : cpItems) {
				if (item.second == null) {
					continue;
				}
				Object obj = null;
				
				if (item.first instanceof SharedFunctionInfoStruct) {
					final SharedFunctionInfoStruct sfObj = (SharedFunctionInfoStruct)item.first;
					obj = fromStruct(sfObj, program);
				} else if (item.first instanceof ScopeInfoStruct) {
					obj = ScopeInfoStore.fromStruct(item.first);
				} else if (item.first instanceof ArrayStruct) {
					obj = ArrayStore.fromStruct((ArrayStruct) item.first);
				} else if (item.first instanceof TupleStruct) {
					obj = TupleStore.fromStruct((TupleStruct) item.first);
				} else if (item.first instanceof String ||
						item.first instanceof Integer ||
						item.first instanceof Long ||
						item.first instanceof Double ||
						item.first instanceof RootObject) {
					obj = item.first;
				} else {
					//System.out.println(item.first);
				}
				
				final ConstantPoolItemStore cpItem = new ConstantPoolItemStore(obj, item.second.getOffset());
				items.add(cpItem);
			}
			
			cp = new ConstantPoolStore(items);
		} else {
			cp = null;
		}
		
		//return new SharedFunctionStore((String)struct.getName(), struct.getAddress().getOffset(), struct.getSize(), siStore, osiStore, cp, program);
		//SharedFunctionStore result = new SharedFunctionStore((String)struct.getName(), struct.getAddress().getOffset(), struct.getSize(), siStore, osiStore, cp, program); // added
		//CacheManager.put(struct, result); // added
		
		//placeholder.update((String)struct.getName(), struct.getAddress().getOffset(), struct.getSize(), siStore, osiStore, cp);
		
		Address addr = struct.getAddress();
		long offset = (addr != null) ? addr.getOffset() : 0; // default to 0
		placeholder.update((String)struct.getName(), offset, struct.getSize(), siStore, osiStore, cp);
		return placeholder;
	}

	public String getName() {
		return name;
	}

	public long getAddress() {
		return offset;
	}
	
	public boolean contains(long addr) {
		return (addr >= offset) && (addr < (offset + size)); 
	}

	public ScopeInfoStore getScopeInfo(final String reg) {
		return scopes.get(reg);
	}
	
	public ScopeInfoStore getOuterScopeInfo() {
		return outerScope;
	}
	
	public void pushScopeInfo(final String reg, final ScopeInfoStore scope) {
		scopes.put(reg, scope);
	}

	public ScopeInfoStore popScopeInfo(final String reg) {
		return scopes.remove(reg);
	}

	public ConstantPoolStore getConstantPool() {
		return cp;
	}
	
	public String debugString() {
	    StringBuilder sb = new StringBuilder();
	    sb.append("SharedFunctionStore {");
	    sb.append("\n  name: ").append(name != null ? name : "null");
	    sb.append("\n  offset: ").append(offset);
	    sb.append("\n  size: ").append(size);
	    sb.append("\n  outerScope: ").append(outerScope != null ? outerScope.toString() : "null");
	    sb.append("\n  constantPool: ").append(cp != null ? cp.toString() : "null");
	    if (scopes != null && !scopes.isEmpty()) {
	        sb.append("\n  scopes:");
	        for (Map.Entry<String, ScopeInfoStore> entry : scopes.entrySet()) {
	            sb.append("\n    ").append(entry.getKey()).append(": ");
	            sb.append(entry.getValue() != null ? entry.getValue().toString() : "null");
	        }
	    }
	    sb.append("\n}");
	    return sb.toString();
	}

}
