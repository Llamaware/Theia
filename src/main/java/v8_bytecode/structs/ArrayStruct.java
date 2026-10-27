package v8_bytecode.structs;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import v8_bytecode.ReservObject;
import v8_bytecode.allocator.ArraysAllocator;
import v8_bytecode.allocator.IAllocatable;
import v8_bytecode.allocator.ObjectsAllocator;

public final class ArrayStruct implements IAllocatable {

	private final Structure s;
	
	private final ReservObject rObj;
	private final int index;
	private final int count;
	private final List<Object> items;
	private final int size;
	
	private final String name;
	
	private final ArraysAllocator arrAllocator;
	private final int pointerSize;
	
	public final int kArrayLengthOffset;
	public final int kArrayHeaderSize;
	
	public ArrayStruct(final ReservObject obj, final ObjectsAllocator allocator) throws Exception {
		this(obj, allocator, false);
	}

	/**
	 * @param doubles true for a FixedDoubleArray, whose elements are raw 8-byte doubles
	 *                (holes are a NaN bit pattern) instead of tagged values
	 */
	public ArrayStruct(final ReservObject obj, final ObjectsAllocator allocator, boolean doubles) throws Exception {
		pointerSize = allocator.getPointerSize();
		
		// start offsets initializing
		kArrayLengthOffset = ObjectsAllocator.kMetaMap + pointerSize;
		kArrayHeaderSize = kArrayLengthOffset + pointerSize;
		// end offsets initializing
		
		rObj = obj;
		arrAllocator = new ArraysAllocator(allocator);

		index = allocator.getCreatedArraysSize();
		allocator.addToCreatedArrays(obj);
		
		allocator.getMonitor().setMessage(String.format("Creating Array #%d", index));
		
		name = String.format("Array_%d", index);
		s = new StructureDataType(name, 0);
		
		count = obj.getSmiInt(kArrayLengthOffset);
		s.add(DWordDataType.dataType, -1, "Count", null);
		
		items = new ArrayList<>();
		for (int i = 0; i < count; ++i) {
			final Object cpObj;
			if (doubles) {
				final long off = kArrayHeaderSize + i * 8L;
				cpObj = ObjectsAllocator.twoIntsToDouble(obj.getInt(off), obj.getInt(off + 4));
			} else {
				cpObj = allocator.prepareForAlloc(obj.getAlignedObject(kArrayHeaderSize + i * pointerSize));
			}
			items.add(cpObj);
			
			allocator.addStructureField(s, cpObj, String.format("Item%d", i));
		}
		
		size = s.getLength();
	}
	
	public static int getArrayHeaderSize(int pointerSize) {
		return getArrayLengthOffset(pointerSize) + pointerSize;
	}
	
	public static int getArrayLengthOffset(int pointerSize) {
		return ObjectsAllocator.kMetaMap + pointerSize;
	}
	
	@Override
	public Address allocate(final ObjectsAllocator allocator, final TaskMonitor monitor) throws Exception {
		monitor.setMessage(String.format("Allocating %s...", this.getClass().getSimpleName()));
		
		Address result = arrAllocator.allocateNew(this, size);
		
		arrAllocator.allocate(count);
		
		for (final Object cpObj : items) {
			if (cpObj instanceof String) {
				arrAllocator.allocate(allocator.allocateInStrings(cpObj));
			} else {
				arrAllocator.allocate(cpObj);
			}
		}
		
		allocator.setDataStruct(result, this);
		JsLiterals.record(allocator.getProgram(), result, JsLiterals.ARRAY_LITERALS, getArrayLiteral());
		JsLiterals.record(allocator.getProgram(), result, JsLiterals.OBJECT_LITERALS, getObjectLiteral());
		return result;
	}
	
	public String getName() {
		return name;
	}

	/** These elements as an array literal. */
	public String getArrayLiteral() {
		return JsLiterals.array(items, pointerSize);
	}

	/** This object literal boilerplate (key/value pairs) as an object literal. */
	public String getObjectLiteral() {
		return JsLiterals.object(items, pointerSize);
	}

	@Override
	public int hashCode() {
		return Objects.hash(rObj);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		ArrayStruct other = (ArrayStruct) obj;
		return Objects.equals(this.rObj, other.rObj);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return s;
	}
}
