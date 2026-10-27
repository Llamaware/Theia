// Run Theia's ContextTracker on the analyzed program and print the scope of every context-slot access.
// Usage (postScript): ProbeContexts.java <output_file>
// @category Theia.Harness

import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import v8_bytecode.ContextTracker;
import v8_bytecode.storage.FuncsStorage;
import v8_bytecode.storage.ScopeInfoStore;

public class ProbeContexts extends GhidraScript {
	@Override
	public void run() throws Exception {
		ContextTracker t = new ContextTracker(currentProgram, FuncsStorage.load(currentProgram),
			currentProgram.getMemory(), monitor);
		try (PrintWriter pw = new PrintWriter(getScriptArgs()[0], "UTF-8")) {
			pw.println(t.summary());
			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				pw.println(f.getName() + " body=" + f.getBody().getNumAddresses());
			}
			for (Instruction ins : currentProgram.getListing().getInstructions(true)) {
				if (ins.getMnemonicString().contains("ContextSlot")) {
					ScopeInfoStore s = t.getSlotScope(ins.getAddress());
					pw.println(ins.getAddress() + " " + ins + " -> " + (s == null ? "null" : s.getName()));
				}
			}
		}
	}
}
