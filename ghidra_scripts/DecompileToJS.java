//Decompile functions as JavaScript instead of C.
//Rewrites the decompiler's token tree using what Theia's p-code means: property loads and
//stores, method calls with their receiver, constructors, JS literals and operators. Temporaries
//the decompiler introduced and uses once are folded into the expression that uses them.
//Run it with the cursor in a function to print that function, or headless to write every
//function to a file:  -postScript DecompileToJS.java <output_file>
//@author Llamaware
//@category Theia

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.decompiler.ClangBreak;
import ghidra.app.decompiler.ClangFuncProto;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangOpToken;
import ghidra.app.decompiler.ClangReturnType;
import ghidra.app.decompiler.ClangStatement;
import ghidra.app.decompiler.ClangSyntaxToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.ClangTypeToken;
import ghidra.app.decompiler.ClangVariableDecl;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Symbol;

public class DecompileToJS extends GhidraScript {

	/** Calls whose first register operand is the receiver (this) of the callee. */
	private static final Set<String> RECEIVER_CALLS = Set.of("CallProperty", "CallProperty0", "CallProperty1",
		"CallProperty2", "CallAnyReceiver", "CallWithSpread");

	/** Calls of V8 runtime functions and intrinsics, written with V8's %Name natives syntax. */
	private static final Set<String> RUNTIME_CALLS = Set.of("CallRuntime", "CallRuntimeForPair",
		"InvokeIntrinsic", "ThrowReferenceErrorIfHole", "ThrowSuperNotCalledIfHole",
		"ThrowSuperAlreadyCalledIfNotHole", "StaDataPropertyInLiteral");

	/** Registers holding V8's oddballs, which Theia's p-code uses as constants. */
	private static final Map<String, String> ODDBALLS = Map.of("True", "true", "False", "false",
		"Undefined", "undefined", "Null", "null", "TheHole", "__hole__");

	private static final Pattern IDENTIFIER = Pattern.compile("[A-Za-z_$][A-Za-z0-9_$]*");

	@Override
	protected void run() throws Exception {
		DecompInterface ifc = new DecompInterface();
		ifc.openProgram(currentProgram);
		try {
			String[] args = getScriptArgs();
			if (args.length > 0) {
				try (PrintWriter pw = new PrintWriter(args[0], "UTF-8")) {
					for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
						monitor.checkCancelled();
						pw.println(render(ifc, f));
						pw.println();
					}
				}
			}
			else {
				Function f = getFunctionContaining(currentAddress);
				if (f == null) {
					printerr("No function at " + currentAddress);
					return;
				}
				println(render(ifc, f));
			}
		}
		finally {
			ifc.dispose();
		}
	}

	private String render(DecompInterface ifc, Function f) {
		DecompileResults res = ifc.decompileFunction(f, 60, monitor);
		if (res == null || !res.decompileCompleted() || res.getCCodeMarkup() == null) {
			return "// " + f.getName() + ": decompilation failed" +
				(res != null ? ": " + res.getErrorMessage() : "");
		}
		return new JsWriter(f, res.getCCodeMarkup()).write();
	}

	/** A rendered piece of output: an original decompiler token, or an expression built from several. */
	private static final class Tok {
		final ClangToken src;
		final String text;
		/** Usable as an operand without parentheses. */
		final boolean atomic;
		/** For a property load: what was loaded from, so a call through it can keep its receiver. */
		HighVariable memberOf;
		/** For ToBoolean(x) rendered as !!x: the operand x. */
		Tok truthOf;
		/** For a folded temporary: the variable it replaced. */
		HighVariable standsFor;

		Tok(ClangToken src) {
			this(src, src.getText(), true);
		}

		Tok(ClangToken src, String text, boolean atomic) {
			this.src = src;
			this.text = text;
			this.atomic = atomic;
		}

		Tok(String text, boolean atomic) {
			this(null, text, atomic);
		}

		boolean is(String s) {
			return text.equals(s);
		}

		boolean blank() {
			return text.isBlank();
		}
	}

	/** A single-use temporary whose assignment is held back so its use can absorb it. */
	private static final class Pending {
		final Varnode out;
		final ClangBreak lineBreak;
		final List<Tok> statement;
		final Tok value;
		/** Receivers folded into this member load; written first if this one is written out. */
		final List<Pending> carried = new ArrayList<>();

		Pending(Varnode out, ClangBreak lineBreak, List<Tok> statement, Tok value) {
			this.out = out;
			this.lineBreak = lineBreak;
			this.statement = statement;
			this.value = value;
		}
	}

	private final class JsWriter {
		private final Function function;
		private final ClangTokenGroup root;
		private final List<String> locals = new ArrayList<>();
		private final List<Pending> pending = new ArrayList<>();
		private final StringBuilder out = new StringBuilder();
		private ClangBreak lineBreak;
		/** Receivers the last rendered use site folded into a member load. */
		private final List<Pending> lastCarried = new ArrayList<>();

		JsWriter(Function function, ClangTokenGroup root) {
			this.function = function;
			this.root = root;
		}

		String write() {
			List<ClangToken> tokens = new ArrayList<>();
			flatten(root, tokens);
			int open = indexOfText(tokens, "{", 0);
			int close = lastIndexOfText(tokens, "}");
			if (open < 0 || close <= open) {
				return "// " + function.getName() + ": unexpected decompiler output";
			}
			List<ClangToken> body = tokens.subList(open + 1, close);
			for (int i = 0; i < body.size();) {
				i = writeItem(body, i);
			}
			flush(pending.size());

			StringBuilder sb = new StringBuilder();
			sb.append("function ").append(function.getName()).append('(');
			List<String> params = new ArrayList<>();
			for (Parameter p : function.getParameters()) {
				if (!p.getName().equals("this")) {
					params.add(p.getName());
				}
			}
			sb.append(String.join(", ", params)).append(") {");
			String text = out.toString();
			Set<String> used = new LinkedHashSet<>();
			for (String name : locals) {
				if (Pattern.compile("(?<![\\w$.])" + Pattern.quote(name) + "(?![\\w$])").matcher(text).find()) {
					used.add(name);
				}
			}
			if (!used.isEmpty()) {
				sb.append("\n  let ").append(String.join(", ", used)).append(';');
			}
			text = text.replaceFirst("\\n\\s*return;$", "");
			text = text.replaceAll("\\n\\s*/\\* WARNING: (?:Removing unreachable block|Switch is manually overridden)[^*]*\\*/", "");
			// Theia ends a throw with a return so the decompiler knows it does not continue
			text = text.replaceAll("\\breturn (throw\\b)", "$1");
			text = text.replaceAll("(\\n\\s*throw [^\\n]*;)\\n\\s*return\\b[^\\n]*;", "$1");
			text = tryCatch(text);
			// the loader's markers of try regions, redundant once the regions are written as try/catch
			text = text.replaceAll("\\n\\s*/\\* (?:try \\{|\\}) // \\S+_handler_\\d+ (?:start|end) \\*/", "");
			text = switchCases(text);
			sb.append(text).append("\n}");
			return sb.toString();
		}

		/** V8's internal variables (.result, .iterator, ...) are not valid JS names. */
		private String jsName(String name) {
			return name.startsWith(".") ? "$" + name.substring(1) : name;
		}

		/**
		 * Theia gives the first instruction of a try region a branch to its handler, which the
		 * decompiler shows as "if (ExceptionThrown()) { handler } else { try body }". Write it as
		 * try/catch, naming the exception after the CreateCatchContext of the handler.
		 */
		private String tryCatch(String text) {
			String marker = "if (ExceptionThrown()) {";
			for (int at = text.indexOf(marker); at >= 0; at = text.indexOf(marker, at + 1)) {
				int handlerOpen = at + marker.length() - 1;
				int handlerClose = matchBrace(text, handlerOpen);
				if (handlerClose < 0) {
					continue;
				}
				String handler = text.substring(handlerOpen + 1, handlerClose);
				String body = "";
				int end = handlerClose + 1;
				Matcher m = Pattern.compile("\\G\\s*else \\{").matcher(text);
				if (m.find(end)) {
					int bodyOpen = m.end() - 1;
					int bodyClose = matchBrace(text, bodyOpen);
					if (bodyClose < 0) {
						continue;
					}
					body = text.substring(bodyOpen + 1, bodyClose);
					end = bodyClose + 1;
				}
				else {
					// the handler leaves the function, so the try body is the code after it, up to the
					// loader's end marker of the region or else the end of the enclosing block
					int bodyEnd = regionEnd(text, at, end);
					body = text.substring(end, bodyEnd).replace("\n", "\n  ") + "\n" +
						text.substring(text.lastIndexOf('\n', at) + 1, at);
					end = bodyEnd;
				}
				String name = "$exception";
				Matcher ctx = Pattern.compile("\\n\\s*(?:_context = )?CreateCatchContext\\([^\\n]*?CaughtException\\(\\), \"([^\"]+)\"[^\\n]*;")
						.matcher(handler);
				if (ctx.find()) {
					name = ctx.group(1);
					handler = handler.substring(0, ctx.start()) + handler.substring(ctx.end());
				}
				handler = handler.replace("CaughtException()", name);
				handler = handler.replaceAll("\\n\\s*" + Pattern.quote(name) + ";", "");
				String indent = text.substring(text.lastIndexOf('\n', at) + 1, at);
				String rewritten = "try {" + body + (body.isEmpty() ? "\n" + indent : "") + "} catch (" + name + ") {" + handler + "}";
				text = text.substring(0, at) + rewritten + text.substring(end);
			}
			return text;
		}

		/**
		 * Where the try body that starts at {@code from} ends: before the loader's end marker of the
		 * region whose start marker precedes {@code at}, or before the end of the enclosing block.
		 */
		private int regionEnd(String text, int at, int from) {
			int block = matchBrace(text, from, 1);
			int blockEnd = (block >= 0) ? text.lastIndexOf('\n', block) : text.length();
			Matcher start = Pattern.compile("/\\* try \\{ // (\\S+_handler_\\d+) start \\*/\\s*$").matcher(text.substring(0, at));
			if (start.find()) {
				int marker = text.indexOf("/* } // " + start.group(1) + " end */", from);
				if (marker >= 0 && marker < blockEnd) {
					return text.lastIndexOf('\n', marker);
				}
			}
			return Math.max(blockEnd, from);
		}

		private int matchBrace(String text, int open) {
			return matchBrace(text, open, 0);
		}

		/**
		 * Index of the brace closing the one at {@code open} (with {@code depth} 0), or of the first
		 * unmatched closing brace after {@code open} (with depth 1); skips strings and comments.
		 */
		private int matchBrace(String text, int open, int depth) {
			for (int i = open; i < text.length(); i++) {
				char c = text.charAt(i);
				if (text.startsWith("/*", i)) {
					int endComment = text.indexOf("*/", i + 2);
					i = (endComment < 0) ? text.length() : endComment + 1;
				}
				else if (text.startsWith("//", i)) {
					int endLine = text.indexOf('\n', i);
					i = (endLine < 0) ? text.length() : endLine;
				}
				else if (c == '"' || c == '\'') {
					for (i++; i < text.length() && text.charAt(i) != c; i++) {
						if (text.charAt(i) == '\\') {
							i++;
						}
					}
				}
				else if (c == '{') {
					depth++;
				}
				else if (c == '}' && --depth == 0) {
					return i;
				}
			}
			return -1;
		}

		/**
		 * The decompiler labels the cases of a SwitchOnSmiNoFeedback by target address (the table is
		 * an override written by Theia's analyzer); use the switch value and its case numbers instead.
		 */
		private String switchCases(String text) {
			Matcher sw = Pattern.compile("switch \\(SwitchOnSmiNoFeedback\\((\\d+), ([^()]+)\\)\\)").matcher(text);
			StringBuilder sb = new StringBuilder();
			int last = 0;
			while (sw.find()) {
				int table = Integer.parseInt(sw.group(1));
				int base = switchBase(table);
				int open = text.indexOf('{', sw.end());
				int close = open >= 0 ? matchBrace(text, open) : -1;
				if (close < 0) {
					continue;
				}
				String cases = text.substring(open, close + 1);
				Matcher c = Pattern.compile("case 0x([0-9a-f]+):").matcher(cases);
				StringBuilder cb = new StringBuilder();
				while (c.find()) {
					Integer index = caseIndex(Long.parseLong(c.group(1), 16));
					c.appendReplacement(cb, index != null ? "case " + (index + base) + ":" : Matcher.quoteReplacement(c.group()));
				}
				c.appendTail(cb);
				sb.append(text, last, sw.start()).append("switch (").append(sw.group(2)).append(") ").append(cb);
				last = close + 1;
			}
			return sb.append(text.substring(last)).toString();
		}

		/** The case value base (third operand) of this function's SwitchOnSmiNoFeedback reading table {@code table}. */
		private int switchBase(int table) {
			for (Instruction ins : currentProgram.getListing().getInstructions(function.getBody(), true)) {
				if (ins.getMnemonicString().startsWith("SwitchOnSmiNoFeedback") && ins.getScalar(0) != null &&
					ins.getScalar(0).getValue() == table && ins.getScalar(2) != null) {
					return (int) ins.getScalar(2).getSignedValue();
				}
			}
			return 0;
		}

		/** N for the "case_N" label the jump table override put at {@code offset}, or null. */
		private Integer caseIndex(long offset) {
			for (Symbol s : currentProgram.getSymbolTable().getSymbols(toAddr(offset))) {
				if (s.getName().matches("case_\\d+")) {
					return Integer.parseInt(s.getName().substring(5));
				}
			}
			return null;
		}

		/** Flattens the token tree, leaving out the prototype and the local declarations. */
		private void flatten(ClangNode node, List<ClangToken> tokens) {
			if (node instanceof ClangFuncProto || node instanceof ClangReturnType) {
				return;
			}
			if (node instanceof ClangVariableDecl decl) {
				for (int i = 0; i < decl.numChildren(); i++) {
					if (decl.Child(i) instanceof ClangVariableToken v) {
						locals.add(jsName(v.getText()));
					}
				}
				tokens.add(null); // marks the declaration, so its ';' can be dropped
				return;
			}
			if (node instanceof ClangToken tok) {
				if (!tokens.isEmpty() && tokens.get(tokens.size() - 1) == null) {
					if (tok.getText().equals(";")) {
						tokens.remove(tokens.size() - 1);
						return;
					}
					if (tok.getText().isEmpty()) {
						return;
					}
					tokens.remove(tokens.size() - 1);
				}
				tokens.add(tok);
				return;
			}
			ClangTokenGroup group = (ClangTokenGroup) node;
			for (int i = 0; i < group.numChildren(); i++) {
				flatten(group.Child(i), tokens);
			}
		}

		/** Writes the statement, keyword or token at {@code i}; returns the index after it. */
		private int writeItem(List<ClangToken> body, int i) {
			ClangToken tok = body.get(i);
			if (tok == null) {
				return i + 1;
			}
			ClangStatement stmt = statementOf(tok);
			if (stmt != null) {
				int end = i;
				while (end < body.size() && body.get(end) != null && statementOf(body.get(end)) == stmt) {
					end++;
				}
				int semi = end;
				while (semi < body.size() && body.get(semi) != null && body.get(semi).getText().isEmpty()) {
					semi++;
				}
				if (semi < body.size() && body.get(semi) != null && body.get(semi).getText().equals(";")) {
					end = semi + 1;
				}
				writeStatement(stmt, toks(body.subList(i, end)));
				return end;
			}
			if (tok instanceof ClangBreak br) {
				lineBreak = br;
				return i + 1;
			}
			String text = tok.getText();
			if (text.equals("if") || text.equals("switch") || text.equals("while") || text.equals("for")) {
				int open = nextSignificant(body, i + 1);
				if (open >= 0 && body.get(open).getText().equals("(")) {
					int close = matchClose(body, open);
					List<Tok> cond = toks(body.subList(open + 1, close));
					// a loop condition runs on every iteration: never fold earlier statements into it
					boolean fold = text.equals("if") || text.equals("switch");
					List<Tok> rendered = fold ? useSite(cond) : rewrite(cond);
					if (!fold) {
						flush(pending.size());
					}
					emit(new Tok(text + " (" + join(trim(rendered)) + ")", true));
					return close + 1;
				}
			}
			if (!tok.getText().isBlank()) {
				flush(pending.size());
			}
			emit(rewrite(List.of(new Tok(tok))).get(0));
			return i + 1;
		}

		private void writeStatement(ClangStatement stmt, List<Tok> tokens) {
			if (writesContextRegister(stmt) || isUserop(stmt, "SetPendingMessage")) {
				lineBreak = null; // context push/pop bookkeeping: no JS equivalent
				return;
			}
			ClangBreak br = lineBreak;
			Varnode temp = singleUseTemporary(stmt, tokens);
			// a statement that is itself held back keeps the earlier held-back ones in order
			List<Tok> rendered = useSite(tokens, temp == null);
			if (temp != null) {
				int eq = indexOf(rendered, "=");
				int end = rendered.size();
				while (end > eq && (rendered.get(end - 1).is(";") || rendered.get(end - 1).blank())) {
					end--;
				}
				List<Tok> rhs = trim(rendered.subList(eq + 1, end));
				Tok value = rhs.size() == 1 ? rhs.get(0) : new Tok(join(rhs), false);
				Pending held = new Pending(temp, br, rendered, value);
				held.carried.addAll(lastCarried);
				pending.add(held);
				lineBreak = null;
				return;
			}
			String text = join(rendered);
			if (text.equals("return undefined;")) {
				rendered = List.of(new Tok("return;", true));
			}
			emit(rendered);
		}

		/**
		 * Renders a statement or condition. Pending temporaries it uses are folded in as long as
		 * they form the most recent run of pending assignments (so evaluation order is kept);
		 * the others are written out first.
		 */
		private List<Tok> useSite(List<Tok> tokens) {
			return useSite(tokens, true);
		}

		private List<Tok> useSite(List<Tok> tokens, boolean flushRest) {
			Set<Varnode> uses = new HashSet<>();
			for (Tok t : tokens) {
				if (t.src instanceof ClangVariableToken v && v.getVarnode() != null) {
					uses.add(v.getVarnode());
				}
			}
			int keep = pending.size();
			while (keep > 0 && uses.contains(pending.get(keep - 1).out)) {
				keep--;
			}
			Map<Varnode, Pending> folded = new HashMap<>();
			for (Pending p : pending.subList(keep, pending.size())) {
				folded.put(p.out, p);
			}
			pending.subList(keep, pending.size()).clear();
			if (flushRest) {
				flush(pending.size());
			}

			lastCarried.clear();
			List<Tok> substituted = new ArrayList<>();
			for (Tok t : tokens) {
				Pending p = (t.src instanceof ClangVariableToken v) ? folded.get(v.getVarnode()) : null;
				if (p == null) {
					substituted.add(t);
					continue;
				}
				Tok value = new Tok(p.value.src, p.value.text, p.value.atomic);
				value.memberOf = p.value.memberOf;
				value.truthOf = p.value.truthOf;
				value.standsFor = ((ClangVariableToken) t.src).getHighVariable();
				substituted.add(value);
				if (p.out.getDescendants().hasNext() && countUses(p.out) == 2) {
					lastCarried.add(p);
				}
			}
			return rewrite(substituted);
		}

		private int countUses(Varnode vn) {
			int n = 0;
			for (Iterator<PcodeOp> it = vn.getDescendants(); it.hasNext(); it.next()) {
				n++;
			}
			return n;
		}

		/** True for a statement made of the CALLOTHER {@code name}, e.g. V8's pending message bookkeeping. */
		private boolean isUserop(ClangStatement stmt, String name) {
			PcodeOp op = stmt.getPcodeOp();
			return op != null && op.getOpcode() == PcodeOp.CALLOTHER &&
				name.equals(currentProgram.getLanguage().getUserDefinedOpName((int) op.getInput(0).getOffset()));
		}

		private boolean writesContextRegister(ClangStatement stmt) {
			PcodeOp op = stmt.getPcodeOp();
			Varnode written = (op != null) ? op.getOutput() : null;
			if (written == null || !written.isRegister()) {
				return false;
			}
			Register reg = currentProgram.getLanguage().getRegister(written.getAddress(), written.getSize());
			return reg != null && reg.getName().equals("_context");
		}

		/** The output of a statement "tmp = expr;" whose temporary is read exactly once, or null. */
		private Varnode singleUseTemporary(ClangStatement stmt, List<Tok> tokens) {
			PcodeOp op = stmt.getPcodeOp();
			Varnode vn = (op != null) ? op.getOutput() : null;
			if (vn == null) {
				return null;
			}
			int first = nextSignificant(tokens, 0);
			if (first < 0 || !(tokens.get(first).src instanceof ClangVariableToken lhs) ||
				lhs.getVarnode() != vn) {
				return null;
			}
			int eq = nextSignificant(tokens, first + 1);
			if (eq < 0 || !tokens.get(eq).is("=")) {
				return null;
			}
			HighVariable high = vn.getHigh();
			HighSymbol sym = (high != null) ? high.getSymbol() : null;
			if (sym != null && (sym.isNameLocked() || sym.isParameter())) {
				return null; // a JS variable or parameter, not a decompiler temporary
			}
			List<PcodeOp> uses = new ArrayList<>();
			vn.getDescendants().forEachRemaining(uses::add);
			if (uses.size() == 2 && isReceiverOfMethodCall(vn, uses)) {
				return vn;
			}
			if (uses.size() != 1 || uses.get(0).getOpcode() == PcodeOp.MULTIEQUAL ||
				uses.get(0).getOpcode() == PcodeOp.INDIRECT) {
				return null;
			}
			return vn;
		}

		/**
		 * True if {@code vn} is read only by "f = vn.name" and by the call "f(vn, ...)" through it,
		 * with f a temporary read once: in JS that is the single expression vn.name(...).
		 */
		private boolean isReceiverOfMethodCall(Varnode vn, List<PcodeOp> uses) {
			for (PcodeOp load : uses) {
				if (load.getOpcode() != PcodeOp.CALLOTHER || load.getNumInputs() < 2 || load.getInput(1) != vn ||
					!"LdaNamedProperty".equals(currentProgram.getLanguage().getUserDefinedOpName((int) load.getInput(0).getOffset()))) {
					continue;
				}
				Varnode callee = load.getOutput();
				if (callee == null || countUses(callee) != 1) {
					continue;
				}
				PcodeOp next = callee.getDescendants().next();
				if (next.getOpcode() == PcodeOp.CAST && next.getOutput() != null && countUses(next.getOutput()) == 1) {
					callee = next.getOutput();
					next = callee.getDescendants().next();
				}
				HighSymbol sym = callee.getHigh() != null ? callee.getHigh().getSymbol() : null;
				if (sym != null && sym.isNameLocked()) {
					continue;
				}
				for (PcodeOp call : uses) {
					if (call == next && call.getOpcode() == PcodeOp.CALLIND && call.getNumInputs() > 1 &&
						call.getInput(0) == callee && call.getInput(1) == vn) {
						return true;
					}
				}
			}
			return false;
		}

		private void flush(int count) {
			for (Pending p : new ArrayList<>(pending.subList(0, count))) {
				ClangBreak saved = lineBreak;
				for (Pending c : p.carried) {
					lineBreak = p.lineBreak;
					emit(c.statement);
				}
				lineBreak = p.lineBreak;
				emit(p.statement);
				lineBreak = saved;
			}
			pending.subList(0, count).clear();
		}

		private void emit(Tok t) {
			emit(List.of(t));
		}

		private void emit(List<Tok> tokens) {
			String text = join(tokens);
			if (text.isEmpty()) {
				return;
			}
			if (lineBreak != null) {
				out.append('\n').append(" ".repeat(lineBreak.getIndent()));
				lineBreak = null;
			}
			out.append(text);
		}

		// ---- expression rewriting ----

		private List<Tok> rewrite(List<Tok> in) {
			List<Tok> result = new ArrayList<>();
			for (int i = 0; i < in.size();) {
				Tok t = in.get(i);
				if (t.src instanceof ClangBreak) {
					result.add(new Tok(" ", true));
					i++;
					continue;
				}
				if (t.src instanceof ClangSyntaxToken && t.is("(") && matchClose(in, i) > i) {
					int close = matchClose(in, i);
					int first = nextSignificant(in, i + 1);
					if (first >= 0 && first < close && in.get(first).src instanceof ClangTypeToken) {
						i = close + 1; // a C cast
						continue;
					}
					if (first >= 0 && first < close && isCallInd(in.get(first))) {
						int argsOpen = nextSignificant(in, close + 1);
						if (argsOpen >= 0 && in.get(argsOpen).is("(")) {
							int argsClose = matchClose(in, argsOpen);
							Tok callee = single(rewrite(in.subList(first + 1, close)));
							result.add(indirectCall(in.get(first).src.getPcodeOp(), callee,
								args(in, argsOpen, argsClose)));
							i = argsClose + 1;
							continue;
						}
					}
					List<Tok> inner = rewrite(in.subList(i + 1, close));
					result.add(new Tok("(" + join(inner) + ")", true));
					i = close + 1;
					continue;
				}
				if (t.src instanceof ClangOpToken && t.src.getPcodeOp() != null &&
					t.src.getPcodeOp().getOpcode() == PcodeOp.CALLOTHER) {
					int open = nextSignificant(in, i + 1);
					if (open >= 0 && in.get(open).is("(")) {
						int close = matchClose(in, open);
						result.add(userop(t.text, args(in, open, close)));
						i = close + 1;
						continue;
					}
				}
				if (t.src instanceof ClangOpToken && t.is("*") && t.src.getPcodeOp() != null &&
					t.src.getPcodeOp().getOpcode() == PcodeOp.STORE) {
					i++; // a context slot store, "*slot = value" in C
					continue;
				}
				result.add(simple(t));
				i++;
			}
			return negatives(truthTests(result));
		}

		/** "x + -1" is "x - 1". */
		private List<Tok> negatives(List<Tok> in) {
			List<Tok> result = new ArrayList<>(in);
			for (int i = 0; i < result.size(); i++) {
				int num = nextSignificant(result, i + 1);
				if (result.get(i).src instanceof ClangOpToken && result.get(i).is("+") && num >= 0 &&
					result.get(num).text.matches("-\\d.*")) {
					result.set(i, new Tok(result.get(i).src, "-", true));
					result.set(num, new Tok(result.get(num).src, result.get(num).text.substring(1), true));
				}
			}
			return result;
		}

		/** "!!x === false" is "!x", "!!x === true" is "x" (and the negated forms). */
		private List<Tok> truthTests(List<Tok> in) {
			List<Tok> result = new ArrayList<>(in);
			for (int i = 0; i < result.size(); i++) {
				Tok x = result.get(i);
				int op = nextSignificant(result, i + 1);
				int lit = op >= 0 ? nextSignificant(result, op + 1) : -1;
				if (x.truthOf == null || lit < 0) {
					continue;
				}
				String o = result.get(op).text;
				String l = result.get(lit).text;
				if (!(o.equals("===") || o.equals("!==")) || !(l.equals("true") || l.equals("false"))) {
					continue;
				}
				boolean positive = o.equals("===") == l.equals("true");
				Tok test = positive ? x.truthOf : new Tok("!" + operand(x.truthOf), false);
				result.subList(i, lit + 1).clear();
				result.add(i, test);
			}
			return result;
		}

		/** Operators and constants that read differently in JS. */
		private Tok simple(Tok t) {
			if (t.src instanceof ClangVariableToken v && v.getVarnode() != null && v.getVarnode().isConstant() &&
				t.text.matches("-?0x[0-9a-fA-F]+")) {
				long value = Long.decode(t.text);
				if (!t.text.startsWith("-") && v.getVarnode().getSize() == 4 && value >= 0x80000000L) {
					value = (int) value;
				}
				return new Tok(t.src, Long.toString(value), value >= 0);
			}
			if (t.src instanceof ClangVariableToken && t.text.startsWith(".")) {
				return new Tok(t.src, jsName(t.text), true);
			}
			if (t.src instanceof ClangVariableToken v && ODDBALLS.containsKey(t.text)) {
				Varnode vn = v.getVarnode();
				Register reg = (vn != null && vn.isRegister())
						? currentProgram.getLanguage().getRegister(vn.getAddress(), vn.getSize())
						: null;
				if (reg != null && reg.getName().equals(t.text)) {
					return new Tok(t.src, ODDBALLS.get(t.text), true);
				}
			}
			if (t.src instanceof ClangOpToken && t.src.getPcodeOp() != null) {
				int opcode = t.src.getPcodeOp().getOpcode();
				if (t.is("==") && (opcode == PcodeOp.INT_EQUAL || opcode == PcodeOp.FLOAT_EQUAL)) {
					return new Tok(t.src, "===", true);
				}
				if (t.is("!=") && (opcode == PcodeOp.INT_NOTEQUAL || opcode == PcodeOp.FLOAT_NOTEQUAL)) {
					return new Tok(t.src, "!==", true);
				}
			}
			return t;
		}

		private boolean isCallInd(Tok t) {
			return t.src instanceof ClangOpToken && t.is("*") && t.src.getPcodeOp() != null &&
				t.src.getPcodeOp().getOpcode() == PcodeOp.CALLIND;
		}

		private Tok indirectCall(PcodeOp op, Tok callee, List<Tok> args) {
			Instruction ins = currentProgram.getListing().getInstructionAt(op.getSeqnum().getTarget());
			String mnemonic = (ins != null) ? ins.getMnemonicString().split("\\.")[0] : "";
			if (mnemonic.equals("Throw") || mnemonic.equals("ReThrow")) {
				return new Tok("throw " + (args.isEmpty() ? "" : args.get(0).text), false);
			}
			if (RUNTIME_CALLS.contains(mnemonic)) {
				return new Tok("%" + callee.text + "(" + joinArgs(args) + ")", true);
			}
			if (RECEIVER_CALLS.contains(mnemonic) && !args.isEmpty()) {
				Tok receiver = args.get(0);
				List<Tok> rest = args.subList(1, args.size());
				if (callee.memberOf != null && receiver.src instanceof ClangVariableToken v &&
					v.getHighVariable() == callee.memberOf) {
					return new Tok(callee.text + "(" + joinArgs(rest) + ")", true);
				}
				return new Tok(operand(callee) + ".call(" + joinArgs(args) + ")", true);
			}
			return new Tok(operand(callee) + "(" + joinArgs(args) + ")", true);
		}

		private Tok userop(String name, List<Tok> a) {
			switch (name) {
				case "LdaNamedProperty":
				case "LdaKeyedProperty":
					if (a.size() == 2) {
						return member(a.get(0), a.get(1), name.equals("LdaNamedProperty"));
					}
					break;
				case "StaNamedProperty":
				case "StaNamedOwnProperty":
				case "StaKeyedProperty":
					if (a.size() == 3) {
						return new Tok(member(a.get(0), a.get(1), !name.equals("StaKeyedProperty")).text +
							" = " + a.get(2).text, false);
					}
					break;
				case "GetGlobal":
				case "LdaGlobalInsideTypeof":
					if (a.size() == 1 && literal(a.get(0)) != null) {
						return new Tok(literal(a.get(0)), true);
					}
					break;
				case "SetGlobalValue":
					if (a.size() == 2 && literal(a.get(0)) != null) {
						return new Tok(literal(a.get(0)) + " = " + a.get(1).text, false);
					}
					break;
				case "CreateClosure":
					if (a.size() == 1) {
						return a.get(0);
					}
					break;
				case "Construct":
				case "ConstructWithSpread":
					if (!a.isEmpty()) {
						return new Tok("new " + operand(a.get(0)) + "(" + joinArgs(a.subList(1, a.size())) + ")", true);
					}
					break;
				case "CreateEmptyArrayLiteral":
					return new Tok("[]", true);
				case "CreateObjectLiteral":
				case "CreateArrayLiteral":
					// Theia's constant pool hands over the boilerplate as literal text
					if (a.size() == 1 && (a.get(0).text.startsWith("{") || a.get(0).text.startsWith("["))) {
						return new Tok(a.get(0).text, true);
					}
					break;
				case "CreateRegExpLiteral":
					if (a.size() == 2 && literal(a.get(0)) != null) {
						return new Tok("/" + unescapeC(literal(a.get(0))) + "/" + regExpFlags(a.get(1).text), true);
					}
					break;
				case "CreateEmptyObjectLiteral":
					return new Tok("{}", true);
				case "TypeOf":
					if (a.size() == 1) {
						return new Tok("typeof " + operand(a.get(0)), false);
					}
					break;
				case "ToBoolean":
					if (a.size() == 1) {
						Tok t = new Tok("!!" + operand(a.get(0)), false);
						t.truthOf = a.get(0);
						return t;
					}
					break;
				case "LogicalNot":
					if (a.size() == 1) {
						return new Tok("!" + operand(a.get(0)), false);
					}
					break;
				case "ToNumber":
				case "ToNumeric":
					if (a.size() == 1) {
						return new Tok("+" + operand(a.get(0)), false);
					}
					break;
				case "TestEqual":
					if (a.size() == 2) {
						return new Tok(operand(a.get(0)) + " == " + operand(a.get(1)), false);
					}
					break;
				case "InstanceOf":
					if (a.size() == 2) {
						return new Tok(operand(a.get(0)) + " instanceof " + operand(a.get(1)), false);
					}
					break;
				case "HasProperty":
					if (a.size() == 2) {
						return new Tok(operand(a.get(1)) + " in " + operand(a.get(0)), false);
					}
					break;
				default:
					break;
			}
			return new Tok(name + "(" + joinArgs(a) + ")", true);
		}

		/** obj.name for a string key that is an identifier, obj[key] otherwise. */
		private Tok member(Tok object, Tok key, boolean named) {
			String lit = named ? literal(key) : null;
			String text = (lit != null && IDENTIFIER.matcher(lit).matches())
					? operand(object) + "." + lit
					: operand(object) + "[" + key.text + "]";
			Tok t = new Tok(text, true);
			t.memberOf = (object.src instanceof ClangVariableToken v) ? v.getHighVariable() : object.standsFor;
			return t;
		}

		/** JSRegExp::Flags of V8 6.5 as the letters after a regular expression literal. */
		private String regExpFlags(String number) {
			long bits;
			try {
				bits = Long.decode(number);
			}
			catch (NumberFormatException e) {
				return "";
			}
			StringBuilder sb = new StringBuilder();
			String letters = "gimyus"; // global, ignoreCase, multiline, sticky, unicode, dotAll
			for (int i = 0; i < letters.length(); i++) {
				if ((bits & (1L << i)) != 0) {
					sb.append(letters.charAt(i));
				}
			}
			return sb.toString();
		}

		/** Undoes the decompiler's C escaping of string literal contents. */
		private String unescapeC(String s) {
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < s.length(); i++) {
				char c = s.charAt(i);
				if (c != '\\' || i + 1 >= s.length()) {
					sb.append(c);
					continue;
				}
				char n = s.charAt(++i);
				switch (n) {
					case 'n' -> sb.append('\n');
					case 't' -> sb.append('\t');
					case 'r' -> sb.append('\r');
					case '0' -> sb.append('\0');
					case 'x' -> {
						int end = Math.min(i + 3, s.length());
						sb.append((char) Integer.parseInt(s.substring(i + 1, end), 16));
						i = end - 1;
					}
					default -> sb.append(n);
				}
			}
			return sb.toString();
		}

		/** The contents of a string literal token, or null. */
		private String literal(Tok t) {
			if (t.text.length() >= 2 && t.text.startsWith("\"") && t.text.endsWith("\"")) {
				return t.text.substring(1, t.text.length() - 1);
			}
			return null;
		}

		private String operand(Tok t) {
			return t.atomic ? t.text : "(" + t.text + ")";
		}

		/** The comma-separated arguments between the parentheses at {@code open} and {@code close}. */
		private List<Tok> args(List<Tok> in, int open, int close) {
			List<Tok> result = new ArrayList<>();
			int start = open + 1;
			int depth = 0;
			for (int i = open + 1; i <= close; i++) {
				Tok t = in.get(i);
				if (i == close || (depth == 0 && t.is(","))) {
					List<Tok> arg = trim(rewrite(in.subList(start, i)));
					if (!arg.isEmpty()) {
						result.add(single(arg));
					}
					start = i + 1;
				}
				else if (t.is("(")) {
					depth++;
				}
				else if (t.is(")")) {
					depth--;
				}
			}
			return result;
		}

		private Tok single(List<Tok> tokens) {
			List<Tok> t = trim(tokens);
			if (t.size() == 1) {
				return t.get(0);
			}
			boolean atomic = true;
			for (Tok x : t) {
				if (x.src instanceof ClangOpToken || x.blank()) {
					atomic = false;
				}
			}
			return new Tok(join(t), atomic);
		}

		// ---- token helpers ----

		private ClangStatement statementOf(ClangToken tok) {
			for (ClangNode n = tok.Parent(); n != null; n = n.Parent()) {
				if (n instanceof ClangStatement s) {
					return s;
				}
			}
			return null;
		}

		private List<Tok> toks(List<ClangToken> tokens) {
			List<Tok> result = new ArrayList<>();
			for (ClangToken t : tokens) {
				if (t != null) {
					result.add(new Tok(t));
				}
			}
			return result;
		}

		private List<Tok> trim(List<Tok> tokens) {
			int s = 0;
			int e = tokens.size();
			while (s < e && tokens.get(s).blank()) {
				s++;
			}
			while (e > s && tokens.get(e - 1).blank()) {
				e--;
			}
			return tokens.subList(s, e);
		}

		private String join(List<Tok> tokens) {
			StringBuilder sb = new StringBuilder();
			for (Tok t : tokens) {
				sb.append(t.text);
			}
			return sb.toString();
		}

		private String joinArgs(List<Tok> args) {
			List<String> parts = new ArrayList<>();
			for (Tok t : args) {
				parts.add(t.text);
			}
			return String.join(", ", parts);
		}

		private int indexOf(List<Tok> tokens, String text) {
			for (int i = 0; i < tokens.size(); i++) {
				if (tokens.get(i).is(text)) {
					return i;
				}
			}
			return -1;
		}

		private int nextSignificant(List<?> tokens, int from) {
			for (int i = from; i < tokens.size(); i++) {
				Object o = tokens.get(i);
				String text = (o instanceof Tok t) ? t.text : (o instanceof ClangToken c) ? c.getText() : "";
				if (o != null && !text.isBlank()) {
					return i;
				}
			}
			return -1;
		}

		/** Index of the ')' closing the '(' at {@code open}, by the decompiler's paren ids. */
		private int matchClose(List<?> tokens, int open) {
			Object o = tokens.get(open);
			ClangToken src = (o instanceof Tok t) ? t.src : (ClangToken) o;
			int id = (src instanceof ClangSyntaxToken s) ? s.getOpen() : -1;
			int depth = 0;
			for (int i = open + 1; i < tokens.size(); i++) {
				Object x = tokens.get(i);
				ClangToken c = (x instanceof Tok t) ? t.src : (ClangToken) x;
				if (id >= 0 && c instanceof ClangSyntaxToken s && s.getClose() == id) {
					return i;
				}
				String text = (x instanceof Tok t) ? t.text : (c != null ? c.getText() : "");
				if (id < 0) {
					if (text.equals("(")) {
						depth++;
					}
					else if (text.equals(")")) {
						if (depth == 0) {
							return i;
						}
						depth--;
					}
				}
			}
			return tokens.size() - 1;
		}

		private int indexOfText(List<ClangToken> tokens, String text, int from) {
			for (int i = from; i < tokens.size(); i++) {
				if (tokens.get(i) != null && tokens.get(i).getText().equals(text)) {
					return i;
				}
			}
			return -1;
		}

		private int lastIndexOfText(List<ClangToken> tokens, String text) {
			for (int i = tokens.size() - 1; i >= 0; i--) {
				if (tokens.get(i) != null && tokens.get(i).getText().equals(text)) {
					return i;
				}
			}
			return -1;
		}
	}
}
