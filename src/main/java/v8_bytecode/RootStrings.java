package v8_bytecode;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.framework.Application;
import ghidra.util.Msg;
import v8_bytecode.allocator.NwjcParser;

/**
 * JS values of the read-only string roots (length_string is "length"), from the "Value"
 * fields that the fork tooling's gen_root_strings.py adds to v8_roots.json.
 */
public final class RootStrings {
	private static Map<String, String> values;

	private RootStrings() {
	}

	/** @return the JS string the root stands for, or null if it is not a string root */
	public static synchronized String get(final String rootName) {
		if (values == null) {
			values = new HashMap<>();
			try {
				File file = Application.getModuleDataFile("v8_roots.json").getFile(false);
				for (JsonElement item : NwjcParser.jsonArrayFromFile(file.getAbsolutePath())) {
					JsonObject obj = item.getAsJsonObject();
					if (obj.has("Value")) {
						values.put(obj.get("Name").getAsString(), obj.get("Value").getAsString());
					}
				}
			} catch (IOException e) {
				Msg.error(RootStrings.class, "Cannot read root string values", e);
			}
		}
		return values.get(rootName);
	}

	/** @return the JS string the root stands for, or its root name if it is not a string root */
	public static String jsName(final RootObject root) {
		final String value = get(root.getName());
		return (value != null) ? value : root.getName();
	}
}
