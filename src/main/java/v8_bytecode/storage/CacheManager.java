package v8_bytecode.storage;

import java.util.IdentityHashMap;
import java.util.Map;

import v8_bytecode.RootObject;

public class CacheManager {
	private static final Map<Object, Object> cache = new IdentityHashMap<>();

	public static Object get(Object key) {
		if (key == null || key instanceof RootObject) {
			return null; // Don't cache null or RootObject
		}
		return cache.get(key);
	}

	public static void put(Object key, Object value) {
		if (key == null || key instanceof RootObject || value == null) {
			return; // Ignore caching null or RootObject
		}
		cache.put(key, value);
	}

	public static void clear() {
		cache.clear();
	}
}
