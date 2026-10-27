package v8_bytecode;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

public class V8_InjectCallJSRuntime extends V8_InjectPayload {
	//protected SleighLanguage language;
	//protected long uniqueBase;

	public V8_InjectCallJSRuntime(String sourceName, SleighLanguage language, long uniqueBase) {
		super(sourceName, language, uniqueBase);
		this.language = language;
		this.uniqueBase = uniqueBase;
	}

	@Override
	public String getName() {
		return "callJSRuntime";
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
		// the slaspec loads the runtime function into acc; the receiver is implicitly undefined
		emitCallArgs(pCode, getRangeRegisters(instruction, 2));
		pCode.emitVarnodeCall("acc", 4);
		return pCode.getPcodeOps();
	}
	@Override
	public void restoreXml(XmlPullParser parser, SleighLanguage lang){
		XmlElement el = parser.start("V8_InjectCallJSRuntime");
		parser.end(el);
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
		V8_InjectCallJSRuntime op2 = (V8_InjectCallJSRuntime) obj;
		if (uniqueBase != op2.uniqueBase) {
			return false;
		}
		return true;
	}
}
