// Print every code unit in an address range: labels, raw bytes, p-code op count, try-region
// context (tryBegin) and pre-comments.
// Usage (postScript): ProbeListing.java <output_file> <start_hex> <end_hex>
// @category Theia.Harness

import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.symbol.Symbol;

public class ProbeListing extends GhidraScript {
	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		Address start = toAddr(Long.parseLong(args[1], 16));
		Address end = toAddr(Long.parseLong(args[2], 16));
		try (PrintWriter pw = new PrintWriter(args[0], "UTF-8")) {
			for (CodeUnit cu : currentProgram.getListing().getCodeUnits(currentProgram.getAddressFactory().getAddressSet(start, end), true)) {
				StringBuilder sb = new StringBuilder();
				for (Symbol s : currentProgram.getSymbolTable().getSymbols(cu.getAddress())) {
					sb.append(s.getName()).append(": ");
				}
				String pre = cu.getComment(CodeUnit.PRE_COMMENT);
				StringBuilder bytes = new StringBuilder();
				for (byte b : cu.getBytes()) {
					bytes.append(String.format("%02x ", b));
				}
				String extra = "";
				if (cu instanceof ghidra.program.model.listing.Instruction ins) {
					var reg = currentProgram.getProgramContext().getRegister("tryBegin");
					var v = reg != null ? currentProgram.getProgramContext().getValue(reg, cu.getAddress(), false) : null;
					extra = "  {pcode=" + ins.getPcode().length + (v != null ? " tryBegin=" + v : "") + "}";
				}
				pw.println(cu.getAddress() + "  " + sb + cu + "   [" + bytes.toString().trim() + "]" + extra + (pre != null ? "   // " + pre : ""));
			}
		}
	}
}
