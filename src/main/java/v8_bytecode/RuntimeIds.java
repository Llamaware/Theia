package v8_bytecode;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import com.google.gson.JsonElement;

import ghidra.framework.Application;
import ghidra.util.Msg;
import v8_bytecode.allocator.NwjcParser;

/**
 * Runtime::FunctionId of a V8 runtime function by name, from v8_funcs.json (Runtime::FunctionId
 * order), for p-code that calls the runtime without naming the function in its operands.
 */
public final class RuntimeIds {
	private static Map<String, Integer> ids;

	private RuntimeIds() {
	}

	/** @return the id of Runtime::k{@code name}, or -1 if this V8 version has no such function */
	public static synchronized int get(final String name) {
		if (ids == null) {
			ids = new HashMap<>();
			try {
				File file = Application.getModuleDataFile("v8_funcs.json").getFile(false);
				int id = 0;
				for (JsonElement item : NwjcParser.jsonArrayFromFile(file.getAbsolutePath())) {
					String key = item.getAsJsonObject().get("Name").getAsString();
					ids.putIfAbsent(key.startsWith("k") ? key.substring(1) : key, id++);
				}
			} catch (IOException e) {
				Msg.error(RuntimeIds.class, "Cannot read runtime function ids", e);
			}
		}
		return ids.getOrDefault(name, -1);
	}
}
