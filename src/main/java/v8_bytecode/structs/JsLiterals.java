package v8_bytecode.structs;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.util.exception.DuplicateNameException;
import v8_bytecode.RootObject;
import v8_bytecode.RootStrings;
import v8_bytecode.allocator.NwjcParser;

/**
 * JS source text for the literal boilerplates in constant pools, so CreateObjectLiteral and
 * CreateArrayLiteral can show what they create. In V8 6.5 an object literal's boilerplate is a
 * FixedArray of key/value pairs (computed values are UninitializedValue and set by the stores
 * that follow), and an array literal's is a Tuple2 of elements kind and constant elements.
 * The text is kept in string property maps at the boilerplate's address.
 */
public final class JsLiterals {
	public static final String OBJECT_LITERALS = "TheiaObjectLiterals";
	public static final String ARRAY_LITERALS = "TheiaArrayLiterals";

	private static final Pattern IDENTIFIER = Pattern.compile("[A-Za-z_$][A-Za-z0-9_$]*");
	private static final Map<String, String> ODDBALLS = Map.of("UndefinedValue", "undefined", "NullValue", "null",
		"TrueValue", "true", "FalseValue", "false", "TheHoleValue", "", "NanValue", "NaN",
		"InfinityValue", "Infinity", "MinusInfinityValue", "-Infinity", "MinusZeroValue", "-0");
	private static final int MAX_LENGTH = 2000;

	private JsLiterals() {
	}

	/** "[a, b, c]" for constant elements; holes stay empty, as in JS. */
	public static String array(List<Object> items, int pointerSize) {
		StringBuilder sb = new StringBuilder("[");
		for (int i = 0; i < items.size(); i++) {
			if (i > 0) {
				sb.append(", ");
			}
			sb.append(value(items.get(i), pointerSize));
			if (sb.length() > MAX_LENGTH) {
				return sb.append(", ...]").toString();
			}
		}
		return sb.append(']').toString();
	}

	/** "{key: value, ...}" for the constant properties of an object literal boilerplate. */
	public static String object(List<Object> items, int pointerSize) {
		StringBuilder sb = new StringBuilder("{");
		boolean first = true;
		for (int i = 0; i + 1 < items.size(); i += 2) {
			final Object v = items.get(i + 1);
			if (v instanceof RootObject r && r.getName().equals("UninitializedValue")) {
				continue; // a computed value, stored by the code after the literal
			}
			sb.append(first ? "" : ", ").append(key(items.get(i), pointerSize)).append(": ").append(value(v, pointerSize));
			first = false;
			if (sb.length() > MAX_LENGTH) {
				return sb.append(", ...}").toString();
			}
		}
		return sb.append('}').toString();
	}

	private static String key(Object k, int pointerSize) {
		final String s = (k instanceof RootObject r) ? RootStrings.get(r.getName()) : (k instanceof String str ? str : null);
		if (s != null) {
			return IDENTIFIER.matcher(s).matches() ? s : quote(s);
		}
		return "[" + value(k, pointerSize) + "]";
	}

	private static String value(Object item, int pointerSize) {
		if (item instanceof String s) {
			return quote(s);
		}
		if (item instanceof Integer i) {
			return Integer.toString(NwjcParser.smiToInt(i, pointerSize));
		}
		if (item instanceof Long l) {
			return Integer.toString(NwjcParser.smiToInt(l, pointerSize));
		}
		if (item instanceof Double d) {
			return (d == Math.rint(d) && !Double.isInfinite(d) && Math.abs(d) < 1e21) ? Long.toString(d.longValue())
					: Double.toString(d);
		}
		if (item instanceof RootObject r) {
			final String s = RootStrings.get(r.getName());
			if (s != null) {
				return quote(s);
			}
			return ODDBALLS.getOrDefault(r.getName(), r.getName());
		}
		if (item instanceof ArrayStruct a) {
			return a.getObjectLiteral(); // nested object literal boilerplate
		}
		if (item instanceof TupleStruct t) {
			return t.getArrayLiteral(); // nested array literal boilerplate
		}
		if (item instanceof SharedFunctionInfoStruct f) {
			return String.valueOf(f.getName());
		}
		return "undefined /* " + (item == null ? "null" : item.getClass().getSimpleName()) + " */";
	}

	private static String quote(String s) {
		StringBuilder sb = new StringBuilder("\"");
		for (char c : s.toCharArray()) {
			switch (c) {
				case '"' -> sb.append("\\\"");
				case '\\' -> sb.append("\\\\");
				case '\n' -> sb.append("\\n");
				case '\r' -> sb.append("\\r");
				case '\t' -> sb.append("\\t");
				default -> {
					if (c < 0x20) {
						sb.append(String.format("\\u%04x", (int) c));
					}
					else {
						sb.append(c);
					}
				}
			}
		}
		return sb.append('"').toString();
	}

	public static void record(Program program, Address addr, String mapName, String text) {
		final PropertyMapManager mgr = program.getUsrPropertyManager();
		try {
			StringPropertyMap map = mgr.getStringPropertyMap(mapName);
			if (map == null) {
				map = mgr.createStringPropertyMap(mapName);
			}
			map.add(addr, text);
		} catch (DuplicateNameException e) {
			// created concurrently: cannot happen within one transaction
		}
	}

	/** @return the literal recorded for the boilerplate at {@code offset}, or null */
	public static String lookup(Program program, long offset, String mapName) {
		final StringPropertyMap map = program.getUsrPropertyManager().getStringPropertyMap(mapName);
		return (map != null) ? map.getString(program.getAddressFactory().getDefaultAddressSpace().getAddress(offset)) : null;
	}
}
