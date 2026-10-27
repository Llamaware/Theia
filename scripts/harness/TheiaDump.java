// Headless dump of a Theia-loaded program: disassembly + decompilation of every function.
// Usage (postScript): TheiaDump.java <output_file> [nodecomp]
// Output is deterministic (sorted by address, no timestamps) so runs can be diffed.
// @category Theia.Harness

import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.PrettyPrinter;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Variable;

public class TheiaDump extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 1) {
			throw new IllegalArgumentException("usage: TheiaDump.java <output_file>");
		}
		File out = new File(args[0]);
		boolean decompile = args.length < 2 || !args[1].equals("nodecomp");
		out.getParentFile().mkdirs();

		List<Function> funcs = new ArrayList<>();
		currentProgram.getFunctionManager().getFunctions(true).forEach(funcs::add);
		funcs.sort(Comparator.comparing(Function::getEntryPoint));

		int errorBookmarks = 0;
		StringBuilder bookmarks = new StringBuilder();
		var it = currentProgram.getBookmarkManager().getBookmarksIterator(BookmarkType.ERROR);
		while (it.hasNext()) {
			Bookmark b = it.next();
			errorBookmarks++;
			bookmarks.append("  ").append(b.getAddress()).append(" [").append(b.getCategory())
					.append("] ").append(b.getComment());
			byte[] raw = new byte[8];
			try {
				int n = currentProgram.getMemory().getBytes(b.getAddress(), raw);
				bookmarks.append(" | bytes:");
				for (int i = 0; i < n; i++) {
					bookmarks.append(String.format(" %02x", raw[i] & 0xff));
				}
			}
			catch (Exception e) {
				// address outside initialized memory
			}
			bookmarks.append('\n');
		}

		DecompInterface ifc = new DecompInterface();
		ifc.setOptions(new DecompileOptions());
		ifc.openProgram(currentProgram);

		int decompFailures = 0;
		try (PrintWriter pw = new PrintWriter(out, "UTF-8")) {
			pw.println("### program: " + currentProgram.getName());
			pw.println("### language: " + currentProgram.getLanguageID());
			pw.println("### functions: " + funcs.size());
			pw.println("### instructions: " + currentProgram.getListing().getNumInstructions());
			pw.println("### error bookmarks: " + errorBookmarks);
			pw.print(bookmarks);
			Options analysisOpts = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
			List<String> enabled = new ArrayList<>();
			for (String opt : analysisOpts.getOptionNames()) {
				if (!opt.contains(".") && analysisOpts.getType(opt) == OptionType.BOOLEAN_TYPE &&
					analysisOpts.getBoolean(opt, false)) {
					enabled.add(opt);
				}
			}
			Collections.sort(enabled);
			pw.println("### enabled analyzers: " + String.join(", ", enabled));

			for (Function f : funcs) {
				monitor.checkCancelled();
				pw.println();
				pw.println("==== FUNCTION " + f.getName() + " @ " + f.getEntryPoint());
				pw.println("---- signature [" + f.getSignatureSource() + "] " + f.getPrototypeString(true, true));
				for (Variable v : f.getLocalVariables()) {
					pw.println("---- local " + v.getName() + " " + v.getVariableStorage() + " firstUse=0x"
						+ Integer.toHexString(v.getFirstUseOffset()));
				}
				pw.println("---- disassembly");
				InstructionIterator ii = currentProgram.getListing().getInstructions(f.getBody(), true);
				while (ii.hasNext()) {
					Instruction ins = ii.next();
					pw.println("  " + ins.getAddress() + "  " + ins);
				}
				if (!decompile) {
					continue;
				}
				pw.println("---- decompiled");
				DecompileResults res = ifc.decompileFunction(f, 60, monitor);
				if (res == null || !res.decompileCompleted() || res.getDecompiledFunction() == null) {
					decompFailures++;
					pw.println("  <DECOMPILE FAILED: " + (res == null ? "null" : res.getErrorMessage()) + ">");
				}
				else {
					// Same text as the decompiler window: getC() would mangle tokens such as 0.5
					pw.println(new PrettyPrinter(f, res.getCCodeMarkup(), null).print().getC().strip());
				}
			}
			pw.println();
			pw.println("### decompile failures: " + decompFailures);
		}
		finally {
			ifc.dispose();
		}
		println("TheiaDump: " + funcs.size() + " functions, " + decompFailures + " decompile failures -> " + out);
	}
}
