package v8_bytecode;

import java.util.Objects;
import java.util.SortedMap;
import java.util.TreeMap;

import v8_bytecode.allocator.NwjcParser;
import v8_bytecode.allocator.ObjectsAllocator;


public final class ReservObject {
	private final int kPointerSize;
	private final long size;
	private long _offset = 0L;
	private long lastAddAddress = 0L;
	private SortedMap<Long, Object> objects = new TreeMap<>();
	
	private final StringBuilder debugLog = new StringBuilder(); // added
	private static long nextId = 1; // Static counter to keep track of the next ID
	private final long id; // Instance-specific ID
	
	public ReservObject(long size, int pointerSize) {
		kPointerSize = pointerSize;
		this.size = size;
		this.id = nextId++; // Assign the next available ID and increment the counter
	}
	
	public Object getLastObject() {
		return objects.get(lastAddAddress);
	}
	
	public void setOffset(long offset) {
		this._offset = offset;
	}

	public long getOffset() {
		return _offset;
	}
	
	public Object getAlignedObject(long offset) {
		final Object obj = objects.get(offset);
		
		if (kPointerSize == 4) {
			return obj;
		}
		
		if (obj instanceof Integer) {
			final long obj2 = (int)objects.get(offset + 4);
			return obj2 << 32L;
		}
		
		return obj;
	}
	
	public int getInt(long offset) {
		return (int)objects.get(offset);
	}
	
	//public int getSmiInt(long offset) {
	//	final int obj1 = (int)objects.get(offset);
	//	
	//	if (kPointerSize == 4) {
	//		return NwjcParser.smiToInt(obj1, kPointerSize);
	//	}
	//	
	//	final long obj2 = (int)objects.get(offset + 4);
	//	return NwjcParser.smiToInt(obj2 << 32L, kPointerSize);
	//}
	
	public int getSmiInt(long offset) {
	    // Retrieve the raw value at the given offset.
	    Object rawObj = objects.get(offset);
	    if (!(rawObj instanceof Number)) {
	        throw new IllegalStateException("Expected a number at offset " + offset + ", but got: " + rawObj);
	    }
	    int rawValue = ((Number) rawObj).intValue();
	    
	    if (kPointerSize == 4) {
	        // For 32-bit, untag by shifting right by 1.
	        return NwjcParser.smiToInt(rawValue, kPointerSize);
	    } else if (kPointerSize == 8) {
	        // For 64-bit, ensure we get the number from the upper half.
	        Object nextObj = objects.get(offset + 4);
	        if (!(nextObj instanceof Number)) {
	            throw new IllegalStateException("Expected a number at offset " + (offset + 4) + ", but got: " + nextObj);
	        }
	        int nextValue = ((Number) nextObj).intValue();
	        // Shift the next value into the high 32 bits.
	        long shifted = ((long) nextValue) << 32;
	        return NwjcParser.smiToInt(shifted, kPointerSize);
	    } else {
	        throw new IllegalStateException("Unsupported pointer size: " + kPointerSize);
	    }
	}
	
	public void addObject(long address, Object object) {
		lastAddAddress = address;
		
		if (object instanceof byte[]) {
			int[] objs = ObjectsAllocator.bytesToInts((byte[])object, 0);
			for (int i = 0; i < objs.length; ++i) {
				objects.put(address + i * 4, objs[i]);
				debugLog.append(String.format("Writing INT %d = %d\n", address + i * 4, objs[i])); // added
			}
		} else {
			objects.put(address, object);
			debugLog.append(String.format("Writing %d = %s\n", address, object.toString())); // added
		}
	}

	public long getSize() {
		return size;
	}

	@Override
	public int hashCode() {
		//return Objects.hash(objects, size);
		return System.identityHashCode(this);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		ReservObject other = (ReservObject) obj;
		return Objects.equals(objects, other.objects) && size == other.size;
	}
	
	@Override
	public String toString() {
	    StringBuilder sb = new StringBuilder();
	    
	    for (final var item : objects.entrySet()) {
	        Object value = item.getValue();
	        
	        if (value == this) { // Self-reference
	            sb.append(String.format("%04X, (self)\n", item.getKey()));
	        } else if (value instanceof ReservObject) { // Detect nested ReservObject
	            sb.append(String.format("%04X, (ReservObject@%X)\n", item.getKey(), System.identityHashCode(value)));
	        } else {
	            sb.append(String.format("%04X, %s\n", item.getKey(), String.valueOf(value)));
	        }
	    }
	    
	    return sb.toString();
	}
	
	public int getObjectCount() { // new
	    return objects.size();
	}
	
	public Iterable<Long> getObjectOffsets() { // new
	    return objects.keySet();
	}
	
	public String getDebugLog() { // new
	    return debugLog.toString();
	}
	
	public String getId() { // new
	    return String.format("ReservObject@%d[size=%d]", id, size);
	}

}
