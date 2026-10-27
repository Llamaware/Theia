package v8_bytecode.storage;

import java.io.Serializable;
import java.util.List;

public final class ConstantPoolStore implements Serializable {

	private final List<ConstantPoolItemStore> items;
	
	public ConstantPoolStore(final List<ConstantPoolItemStore> items) {
		this.items = items;
	}
	
	/** @return the item, or null if {@code index} is outside this constant pool */
	public Object getConstItem(int index) {
		return (index >= 0 && index < items.size()) ? items.get(index).getItem() : null;
	}
	
	/** @return the item's address, or -1 if {@code index} is outside this constant pool */
	public long getConstItemAddress(int index) {
		return (index >= 0 && index < items.size()) ? items.get(index).getAddress() : -1;
	}
}
