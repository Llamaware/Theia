package v8_bytecode;
import java.io.File;
import java.util.Date;

import ghidra.framework.Application;

public class LogWriter {

	static final String BUILD_NAME = "v1.0 \"Skyclad Observer\"";

	// Per-call logs (p-code injection, constant pool lookups) run inside every decompile,
	// so they are only written when Ghidra is started with -Dtheia.debug=true.
	private static final boolean DEBUG = Boolean.getBoolean("theia.debug");

	public static String buildName() {
		return BUILD_NAME;
	}

	public static boolean isDebug() {
		return DEBUG;
	}

	/** Logs live in &lt;Ghidra user settings dir&gt;/Theia, which is always writable. */
	public static File getLogDirectory() {
		File base;
		try {
			base = Application.getUserSettingsDirectory();
		} catch (Exception | Error e) {
			base = new File(System.getProperty("java.io.tmpdir"));
		}
		File theiaDir = new File(base, "Theia");
		theiaDir.mkdirs();
		return theiaDir;
	}

	public static String writeLog(MessageLog2 log, String fileName){
		// Called from concurrent analysis/decompiler threads; header swap + write must be atomic.
		synchronized (LogWriter.class) {
			synchronized (log) {
				return writeLogLocked(log, fileName);
			}
		}
	}

	private static String writeLogLocked(MessageLog2 log, String fileName){
		String resultPath = new File(getLogDirectory(), fileName).getPath();
		String firstMessage = log.getFirstMsg();
		if (firstMessage.contains("Log written by Theia")) {
			log.deleteFirstMsg();
		}
		log.prependMsg("---Log written by Theia - " + buildName() + " at " + new Date() + "---");
		log.writeToFile(resultPath);
		return resultPath;
	}
}
