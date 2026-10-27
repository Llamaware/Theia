package v8_bytecode;

//import java.io.IOException;

//import ghidra.app.plugin.processors.sleigh.*;
import ghidra.app.plugin.processors.sleigh.PcodeEmit;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
//import ghidra.app.plugin.processors.sleigh.template.*;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.*;
//import ghidra.xml.*;
//import ghidra.program.model.util.PropertyMap;

public abstract class V8_InjectPayload implements InjectPayload {
	/** Receiver kinds passed by the slaspec (RECV_UNDEF / RECV_ARG). */
	protected static final int RECV_UNDEF = 0;
	protected static final int RECV_ARG = 1;
	/** Constant pool record types passed by the slaspec (CP_INTRINSICTYPE etc.). */
	protected static final int INTRINSICTYPE = 1;
	protected static final int RUNTIMETYPE = 2;
	protected static final int PROPERTYTYPE = 3;
	/** Runtime::kDefineDataPropertyInLiteral in node 9.7.1. */
	protected static final int DEFINE_DATA_PROPERTY_IN_LITERAL = 323;
	/** Prefix of the outgoing-argument registers read by the default prototype. */
	protected static final String OUT_ARG = "o";

	protected SleighLanguage language;
	protected long uniqueBase;
	private String sourceName;

	protected V8_InjectPayload(String sourceName, SleighLanguage language, long uniqueBase) {
		this.language = language;
		this.sourceName = sourceName;
		this.uniqueBase = uniqueBase;

	}

	/**
	 * Expands a register range operand, displayed as "rStart-rEnd" (or "{}" when empty),
	 * into its registers in V8 order. Consecutive registers of a V8 range have decreasing
	 * operand bytes, which is increasing r-register / decreasing a-register addresses, so
	 * stepping from the first to the last register's address covers both cases.
	 */
	protected static Register[] getRangeRegisters(Instruction instruction, int opIndex) {
		Register first = null;
		Register last = null;
		for (Object o : instruction.getOpObjects(opIndex)) {
			if (o instanceof Register) {
				if (first == null) {
					first = (Register) o;
				}
				last = (Register) o;
			}
		}
		if (first == null) {
			return new Register[0];
		}
		final Language lang = instruction.getPrototype().getLanguage();
		final long delta = last.getOffset() - first.getOffset();
		final int step = delta >= 0 ? 4 : -4;
		final Register[] result = new Register[(int) (Math.abs(delta) / 4) + 1];
		for (int i = 0; i < result.length; i++) {
			result[i] = lang.getRegister(first.getAddress().add((long) i * step), 4);
		}
		return result;
	}

	/**
	 * Copies call arguments, in source order, into the outgoing-argument registers o0..oN.
	 * The default prototype reads its inputs from there, so the caller's own a/r registers
	 * never need saving and the decompiler prints the arguments in source order.
	 */
	protected static void emitCallArgs(V8_PcodeOpEmitter pCode, String... args) {
		for (int i = 0; i < args.length; i++) {
			pCode.emitAssignVarnodeFromVarnode(OUT_ARG + i, args[i], 4);
		}
	}

	protected static void emitCallArgs(V8_PcodeOpEmitter pCode, Register[] args) {
		String[] names = new String[args.length];
		for (int i = 0; i < args.length; i++) {
			names[i] = args[i].getName();
		}
		emitCallArgs(pCode, names);
	}

	/**
	 * Fallback for flow the listing has not disassembled: the decompiler rejects an empty
	 * injection, so emit a COPY of acc onto itself.
	 */
	protected PcodeOp[] noOpPayload(InjectContext context) {
		final Register acc = language.getRegister("acc");
		final Varnode accVn = new Varnode(acc.getAddress(), acc.getMinimumByteSize());
		return new PcodeOp[] { new PcodeOp(context.baseAddr, 0, PcodeOp.COPY, new Varnode[] { accVn }, accVn) };
	}

	@Override
	public int getType() {
		return InjectPayload.CALLOTHERFIXUP_TYPE;
	}

	@Override
	public String getSource() {
		return sourceName;
	}

	@Override
	public int getParamShift() {
		return 0;
	}

	@Override
	public void inject(InjectContext context, PcodeEmit emit) {
		// Not used
	}

	@Override
	public boolean isFallThru() {
		return true;
	}

	@Override
	public InjectParameter[] getInput() {
		return null;
	}

	@Override
	public InjectParameter[] getOutput() {
		return null;
	}
	@Override
	public void encode(Encoder encoder) {
		//TODO: Implement
	}

	@Override
	public boolean isIncidentalCopy() {
		return false;
	}

	@Override
	public boolean isErrorPlaceholder() {
		return false;
	}
}
