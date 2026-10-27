// Dump the decompiler's ClangToken tree for one function: class, text, p-code op, paren ids.
// Usage (postScript): ProbeTokens.java <output_file> <function_name>
// @category Theia.Harness

import java.io.PrintWriter;

import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangSyntaxToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class ProbeTokens extends GhidraScript {
	private PrintWriter pw;

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		DecompInterface ifc = new DecompInterface();
		ifc.openProgram(currentProgram);
		try (PrintWriter out = new PrintWriter(args[0], "UTF-8")) {
			pw = out;
			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				if (f.getName().equals(args[1])) {
					DecompileResults res = ifc.decompileFunction(f, 60, monitor);
					dump(res.getCCodeMarkup(), 0);
				}
			}
		}
		ifc.dispose();
	}

	private void dump(ClangNode node, int depth) {
		String pad = "  ".repeat(depth);
		if (node instanceof ClangToken tok) {
			String extra = "";
			if (tok instanceof ClangSyntaxToken s) {
				extra = " open=" + s.getOpen() + " close=" + s.getClose();
			}
			pw.println(pad + tok.getClass().getSimpleName() + " '" + tok.getText() + "'"
				+ (tok.getPcodeOp() != null ? " op=" + tok.getPcodeOp().getMnemonic() + "@" + tok.getPcodeOp().getSeqnum().getTarget() : "")
				+ extra);
		}
		else {
			pw.println(pad + "<" + node.getClass().getSimpleName() + ">");
			ClangTokenGroup g = (ClangTokenGroup) node;
			for (int i = 0; i < g.numChildren(); i++) {
				dump(g.Child(i), depth + 1);
			}
		}
	}
}
