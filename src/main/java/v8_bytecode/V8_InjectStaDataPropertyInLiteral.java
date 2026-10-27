package v8_bytecode;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;
public class V8_InjectStaDataPropertyInLiteral extends V8_InjectPayload {
	//protected SleighLanguage language;
	//protected long uniqueBase;

	public V8_InjectStaDataPropertyInLiteral(String sourceName, SleighLanguage language, long uniqueBase) {
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
		// Runtime::kDefineDataPropertyInLiteral(object, name, value, flags)
		pCode.emitAssignVarnodeFromPcodeOpCall("call_target", 4, "cpool", "0", "0x" + opAddr.toString(),
				Integer.toString(DEFINE_DATA_PROPERTY_IN_LITERAL), Integer.toString(RUNTIMETYPE));
		emitCallArgs(pCode, instruction.getRegister(0).getName(), instruction.getRegister(1).getName(), "acc");
		pCode.emitAssignConstantToRegister(OUT_ARG + 3, (int) instruction.getScalar(2).getValue());
		pCode.emitVarnodeCall("call_target", 4);
		return pCode.getPcodeOps();
	}


	@Override
	public boolean isIncidentalCopy() {
		return false;
	}
	
@Override
	public String getName() {
		// TODO Auto-generated method stub
		return "InjectStaDataPropertyInLiteral";
	}
	@Override
	public void restoreXml(XmlPullParser parser, SleighLanguage lang){
		XmlElement el = parser.start("V8_InjectStaDataPropertyInLiteral");
		parser.end(el);
	}
	@Override	
	public boolean isEquivalent(InjectPayload obj) {
		if (this.getClass() != obj.getClass()) {
			return false;
		}
		V8_InjectStaDataPropertyInLiteral op2 = (V8_InjectStaDataPropertyInLiteral) obj;
		if (uniqueBase != op2.uniqueBase) {
			return false;
		}
		return true;
	}
}
