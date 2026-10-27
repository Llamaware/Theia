// Print Theia's stored constant pool items for every function.
// Usage (postScript): ProbeCpool.java <output_file>
// @category Theia.Harness

import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import v8_bytecode.storage.FuncsStorage;
import v8_bytecode.storage.SharedFunctionStore;

public class ProbeCpool extends GhidraScript {
	@Override
	public void run() throws Exception {
		FuncsStorage fs = FuncsStorage.load(currentProgram);
		try (PrintWriter pw = new PrintWriter(getScriptArgs()[0], "UTF-8")) {
			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				pw.println(f.getName() + " @ " + f.getEntryPoint());
				for (int i = 0; i < 64; i++) {
					Object item = fs.getConstItem(f.getEntryPoint(), i);
					if (item == null && fs.getConstItemAddress(f.getEntryPoint(), i) == -1) {
						break;
					}
					String desc = String.valueOf(item);
					if (item instanceof SharedFunctionStore sfs) {
						desc = "SFI offset=0x" + Long.toHexString(sfs.getAddress()) + " " + sfs.debugString().replace('\n', ' ');
					}
					pw.println("  [" + i + "] " + (item == null ? "null" : item.getClass().getSimpleName()) + " " + desc);
				}
			}
		}
	}
}
