package v8_bytecode.structs;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import generic.stl.Pair;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import v8_bytecode.ReservObject;
import v8_bytecode.allocator.ConstantPoolsAllocator;
import v8_bytecode.allocator.IAllocatable;
import v8_bytecode.allocator.ObjectsAllocator;

public final class ConstantPoolStruct implements IAllocatable {

	private final Structure s;
	
	private final int funcIndex;
	private final int count;
	private final List<Pair<Object, Address>> items;
	private final int size;
	
	private final ConstantPoolsAllocator cpAllocator;
	
	public ConstantPoolStruct(final ReservObject obj, int funcIndex, final ObjectsAllocator allocator) throws Exception {
		int pointerSize = allocator.getPointerSize();
		
		cpAllocator = new ConstantPoolsAllocator(allocator);

		this.funcIndex = funcIndex;
		
		allocator.getMonitor().setMessage(String.format("Creating ConstantPool for function #%d", funcIndex));
		
		s = new StructureDataType(String.format("ConstantPool_%d", funcIndex), 0);
		
		count = obj.getSmiInt(ArrayStruct.getArrayLengthOffset(pointerSize));
		s.add(DWordDataType.dataType, -1, "Count", null);
		
		items = new ArrayList<>();
		for (int i = 0; i < count; ++i) {
			final Object cpObj = allocator.prepareForAlloc(obj.getAlignedObject(ArrayStruct.getArrayHeaderSize(pointerSize) + i * pointerSize));
			items.add(new Pair<>(cpObj, null));
			
			allocator.addStructureField(s, cpObj, String.format("Item%d", i));
		}
		
		size = s.getLength();
	}
	
	@Override
	public Address allocate(final ObjectsAllocator allocator, final TaskMonitor monitor) throws Exception {
		monitor.setMessage(String.format("Allocating %s...", this.getClass().getSimpleName()));
		
		Address result = cpAllocator.allocateNew(this, size);
		
		cpAllocator.allocate(count);
		
		for (int i = 0; i < items.size(); ++i) {
			final Object cpObj = items.get(i).first;
			
			Address itemAlloc;
			if (cpObj instanceof String) {
				itemAlloc = allocator.allocateInStrings(cpObj);
				cpAllocator.allocate(itemAlloc);
			} else {
				itemAlloc = cpAllocator.allocate(cpObj);
			}
			
			items.set(i, new Pair<>(cpObj, itemAlloc));
		}
		
		allocator.setDataStruct(result, this);
		
		return result;
	}
	
	public List<Pair<Object, Address>> getItems() {
		return items;
	}
	
	public Object getConstItem(int index) {
		return items.get(index).first;
	}
	
	public Address getConstItemAddress(int index) {
		return items.get(index).second;
	}

	@Override
	public int hashCode() {
		return Objects.hash(funcIndex);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		ConstantPoolStruct other = (ConstantPoolStruct) obj;
		return funcIndex == other.funcIndex;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return s;
	}

	public int getFunctionIndex() {
		return funcIndex;
	}
	
	@Override
	public String toString() {
	    StringBuilder sb = new StringBuilder();
	    sb.append("ConstantPoolStruct {");
	    sb.append("\n  funcIndex: ").append(funcIndex);
	    sb.append("\n  count: ").append(count);
	    sb.append("\n  size: ").append(size);
	    sb.append("\n  items:");
	    for (int i = 0; i < items.size(); i++) {
	        Pair<Object, Address> item = items.get(i);
	        sb.append("\n    [").append(i).append("]: ");
	        sb.append("Value: ").append(getSummary(item.first));
	        sb.append(", Address: ").append(item.second != null ? item.second.toString() : "null");
	    }
	    sb.append("\n}");
	    return sb.toString();
	}

	private String getSummary(Object obj) {
	    if (obj == null) return "null";
	    // Instead of recursing, print a summary depending on the type
	    if (obj instanceof ConstantPoolStruct) {
	        ConstantPoolStruct cps = (ConstantPoolStruct) obj;
	        return "ConstantPoolStruct (funcIndex: " + cps.getFunctionIndex() + ")";
	    } else if (obj instanceof BytecodeStruct) {
	        BytecodeStruct bs = (BytecodeStruct) obj;
	        return "BytecodeStruct (length: " + bs.getLength() + ")";
	    } else if (obj instanceof SharedFunctionInfoStruct) {
	        SharedFunctionInfoStruct sfis = (SharedFunctionInfoStruct) obj;
	        return "SharedFunctionInfoStruct (name: " + sfis.getName() + ")";
	    } else {
	        // Fallback: print class name and hash code
	        return obj.getClass().getSimpleName() + "@" + Integer.toHexString(obj.hashCode());
	    }
	}



}
