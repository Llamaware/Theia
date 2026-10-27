package v8_bytecode;

import java.nio.charset.StandardCharsets;

import ghidra.program.model.lang.ConstantPool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import v8_bytecode.allocator.NwjcParser;
import v8_bytecode.allocator.ObjectsAllocator;
import v8_bytecode.enums.RootsEnum;
import v8_bytecode.enums.TypeOfEnum;
import v8_bytecode.storage.ArrayStore;
import v8_bytecode.storage.TupleStore;
import v8_bytecode.structs.JsLiterals;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import v8_bytecode.storage.RuntimesIntrinsicsStore;
import v8_bytecode.storage.ScopeInfoStore;
import v8_bytecode.storage.SharedFunctionStore;
import v8_bytecode.storage.FuncsStorage;
import v8_bytecode.storage.InstructionsStorage;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;

public class V8_ConstantPool extends ConstantPool {
	private final FuncsStorage funcsStorage;
	
	private MessageLog2 log = new MessageLog2();
	
	private final FlatProgramAPI fpa;
	private final DataTypeManager mgr;

	/** JS text of a literal boilerplate used by the CreateObjectLiteral/CreateArrayLiteral at {@code address}. */
	private String literalAt(long address, int index) {
		final Instruction ins = fpa.getInstructionAt(fpa.toAddr(address));
		final String mnemonic = (ins != null) ? ins.getMnemonicString() : "";
		final String map = mnemonic.startsWith("CreateObjectLiteral") ? JsLiterals.OBJECT_LITERALS
				: mnemonic.startsWith("CreateArrayLiteral") ? JsLiterals.ARRAY_LITERALS : null;
		final long slot = funcsStorage.getConstItemAddress(fpa.toAddr(address), index);
		if (map == null || slot < 0) {
			return null;
		}
		try {
			// the constant pool slot holds a pointer to the allocated boilerplate
			final long target = fpa.getCurrentProgram().getMemory().getInt(fpa.toAddr(slot)) & 0xFFFFFFFFL;
			return JsLiterals.lookup(fpa.getCurrentProgram(), target, map);
		} catch (MemoryAccessException e) {
			return null;
		}
	}

	/** The fixed slots at the start of every V8 6.5 context. */
	private static final String[] CONTEXT_HEADER = { "closure", "previous", "extension", "native_context" };

	/** A number printed verbatim as its token, for values that do not fit a 4-byte constant. */
	private static void setTokenRecord(Record res, String token) {
		res.tag = ConstantPool.POINTER_FIELD;
		res.type = IntegerDataType.dataType;
		res.token = token;
	}

	public V8_ConstantPool(Program program) {
		fpa = new FlatProgramAPI(program);
		
		mgr = program.getDataTypeManager();

		funcsStorage = FuncsStorage.load(program);
	}

	@Override
	public Record getRecord(long[] ref) {
		Record res = new Record();
		//String tmp = "";
		//int tmpLen = 0;
		long address = ref[0];
		int index = (int) ref[1];
		int indexType = (int) ref[2];
		
		// System.out.println(String.format("%04X %04X", address, index));
		log.appendMsg(String.format("address: %04X index: %04X", address, index));
		log.appendMsg("indexType: " + indexType);
		switch (indexType) {
		case 0: { // constant pool
			final Object cpItem = funcsStorage.getConstItem(fpa.toAddr(address), index);
			
			if (cpItem instanceof String) {
				res.tag = ConstantPool.STRING_LITERAL;
				res.type = new PointerDataType(CharDataType.dataType);
				res.byteData = ((String)cpItem).getBytes(StandardCharsets.UTF_8);
			} else if (cpItem instanceof Integer) {
		          res.tag = ConstantPool.PRIMITIVE;
		          res.type = IntegerDataType.dataType;
		          res.value = (Integer)cpItem;
		          res.token = "int";
			} else if (cpItem instanceof Long) {
				// operands are 4 bytes wide, so 8-byte values are printed as tokens
				setTokenRecord(res, Long.toString((Long) cpItem));
			} else if (cpItem instanceof Double) {
				final double d = (Double) cpItem;
				setTokenRecord(res, d == Math.rint(d) && !Double.isInfinite(d) && Math.abs(d) < 1e21
						? Long.toString((long) d) : Double.toString(d));
			} else if (cpItem instanceof RootObject && RootStrings.get(((RootObject) cpItem).getName()) != null) {
				res.tag = ConstantPool.STRING_LITERAL;
				res.type = new PointerDataType(CharDataType.dataType);
				res.byteData = RootStrings.get(((RootObject) cpItem).getName()).getBytes(StandardCharsets.UTF_8);
			} else if (cpItem instanceof RootObject) {
				res.tag = ConstantPool.PRIMITIVE;
				res.type = mgr.getRootCategory().getDataType(RootsEnum.NAME);
				res.value = funcsStorage.getRoots().fromString((RootObject)cpItem);
				res.token = ((RootObject)cpItem).getName();
			} else if (cpItem instanceof SharedFunctionStore) {
			    final Address funcAddr = fpa.toAddr(((SharedFunctionStore)cpItem).getAddress());
			    log.appendMsg("SharedFunctionStore.getAddress() returned: " + funcAddr);
			    Function func = fpa.getFunctionAt(funcAddr);
			    if (func == null) {
			        log.appendMsg("Error: No function found at address: " + funcAddr);
			        log.appendMsg("cpItem: " + ((SharedFunctionStore)cpItem).debugString());
			        res.token = "NoFunctionFound";
			    } else {
			        log.appendMsg("Found function: " + func.getName() + " at address: " + funcAddr);
			        res.token = func.getName();
			    }
			    res.tag = ConstantPool.POINTER_METHOD;
			    // Ensure that type is not null
			    if (res.type == null) {
			         res.type = new PointerDataType(VoidDataType.dataType);
			    }
			}
			else if ((cpItem instanceof ArrayStore || cpItem instanceof TupleStore) && literalAt(address, index) != null) {
				setTokenRecord(res, literalAt(address, index));
				res.type = new PointerDataType(VoidDataType.dataType);
			}
			else if (cpItem instanceof ArrayStore){
				res.tag = ConstantPool.POINTER_FIELD;
				res.type = mgr.getRootCategory().getDataType(((ArrayStore)cpItem).getName());
				res.token = ((ArrayStore)cpItem).getName();
			} else if (cpItem instanceof ScopeInfoStore) {
				res.tag = ConstantPool.POINTER_FIELD;
				res.type = mgr.getRootCategory().getDataType(((ScopeInfoStore)cpItem).getName());
				res.token = ((ScopeInfoStore)cpItem).getName();
			} else {
				//System.out.println(cpItem);
			}
		} break;
		case 1: // intrinsics
		case 2: { // runtimes
			final RuntimesIntrinsicsStore runsIntrsStore = funcsStorage.getRuntimesIntrinsicsStore();
			res.tag = ConstantPool.POINTER_METHOD;
			res.type = new PointerDataType(VoidDataType.dataType);			
			res.token = (indexType == 1) ? runsIntrsStore.getIntrinsicName(index) : runsIntrsStore.getRuntimeName(index);
		} break;
		case 3: { // context slot
		    if (index < CONTEXT_HEADER.length) { // Context::MIN_CONTEXT_SLOTS in V8 6.5
		        res.tag = ConstantPool.POINTER_FIELD;
		        res.type = new PointerDataType(VoidDataType.dataType);
		        res.token = CONTEXT_HEADER[index];
		        break;
		    }
		    final InstructionsStorage instrStorage = InstructionsStorage.load(fpa.getCurrentProgram(), address);
		    
		    if (instrStorage == null) {
		        break;
		    }
		    
		    res.tag = ConstantPool.POINTER_METHOD;
		    res.type = new PointerDataType(VoidDataType.dataType);
		    
		    if (instrStorage.getScopeInfo() != null) {
		        final var contextVar = instrStorage.getScopeInfo().getContextVar(index);
		        if (contextVar != null) {
		            res.token = contextVar.getName();
		        } else {
		            res.token = "nullContextVar";
		            log.appendMsg("Warning: getContextVar(" + index + ") returned null");
		        }
		    } else {
		        res.token = "nullScopeInfo";
		        log.appendMsg("Warning: instrStorage.getScopeInfo() returned null");
		    }
		} break;
		case 4: { // TestTypeOf literal: compared with the result of typeof, so its string
			final Enum typeOf = (Enum) mgr.getRootCategory().getDataType(TypeOfEnum.NAME);
			final String name = typeOf.getName(index);
			if (name != null) {
				res.tag = ConstantPool.STRING_LITERAL;
				res.type = new PointerDataType(CharDataType.dataType);
				res.byteData = name.toLowerCase().getBytes(StandardCharsets.UTF_8);
			}
		} break;
		case 5: {
			final Object cpItem = funcsStorage.getConstItem(fpa.toAddr(address), index);
			
			final long val;
			if (cpItem instanceof Integer) {
				val = NwjcParser.smiToInt((int)cpItem, ObjectsAllocator.getPointerSize(fpa.getCurrentProgram()));
			} else if (cpItem instanceof Long) {
				val = NwjcParser.smiToInt((long)cpItem, ObjectsAllocator.getPointerSize(fpa.getCurrentProgram()));
			} else {
				break;
			}
			
			res.tag = ConstantPool.PRIMITIVE;
	        res.type = LongLongDataType.dataType;
	        res.value = val;
	        res.token = "longlong";
		} break;
		}
		// DecompileCallback.getCPoolRef encodes the token and type of every record;
		// a missing one crashes the decompile.
		if (res.type == null) {
			res.type = new PointerDataType(VoidDataType.dataType);
		}
		if (res.token == null) {
			log.appendMsg(String.format("Unresolved constant pool item %d (type %d) at %04X", index, indexType, address));
			res.token = String.format("cpool_%d", index);
		}
		if (LogWriter.isDebug()) {
			LogWriter.writeLog(log, "cpool.log");
		}
		return res;
	}
}
