package v8_bytecode;

import java.util.ArrayList;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.lang.InjectPayload;
import ghidra.xml.XmlPullParser;
import ghidra.xml.XmlElement;

public class V8_InjectJSCallN extends V8_InjectPayload {
	//protected SleighLanguage language;
	//protected long uniqueBase;

	public V8_InjectJSCallN(String sourceName, SleighLanguage language, long uniqueBase) {
		super(sourceName, language, uniqueBase);
		this.language = language;
		this.uniqueBase = uniqueBase;
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext context) {
		V8_PcodeOpEmitter pCode = new V8_PcodeOpEmitter(language, context.baseAddr, uniqueBase);
		Address opAddr = context.baseAddr;
		Instruction instruction = program.getListing().getInstructionAt(opAddr);
		if (instruction == null) {
			// The decompiler can follow flow the listing has not disassembled; emit nothing.
			return noOpPayload(context);
		}
		// get arguments from slaspec, definition in cspec
		int argcount = (int) context.inputlist.get(0).getOffset();
		int receiver = (int) context.inputlist.get(1).getOffset();
		// operand 0 is the callable; the receiver (if passed) and the arguments follow in source order
		String[] args = new String[argcount + (receiver == RECV_ARG ? 1 : 0)];
		for (int i = 0; i < args.length; i++) {
			args[i] = instruction.getRegister(i + 1).getName();
		}
		emitCallArgs(pCode, args);
		pCode.emitVarnodeCall(instruction.getRegister(0).getName(), 4);
		return pCode.getPcodeOps();
	}

	@Override
	public void restoreXml(XmlPullParser parser, SleighLanguage lang){
		XmlElement el = parser.start("V8_InjectCallJSRuntime");
		parser.end(el);
	}
	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return "InjectJSCallN";
	}
	
	@Override
	public boolean isIncidentalCopy() {
		return false;
	}
	
@Override	
	public boolean isEquivalent(InjectPayload obj) {
		if (this.getClass() != obj.getClass()) {
			return false;
		}
		V8_InjectJSCallN op2 = (V8_InjectJSCallN) obj;
		if (uniqueBase != op2.uniqueBase) {
			return false;
		}
		return true;
	}
}
