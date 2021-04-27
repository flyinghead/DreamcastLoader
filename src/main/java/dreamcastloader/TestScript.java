package dreamcastloader;

import java.math.BigInteger;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class TestScript extends GhidraScript {

	public TestScript() {
		// TODO Auto-generated constructor stub
	}

	@Override
	protected void run() throws Exception {
		Function func = getCurrentProgram().getFunctionManager().getFunctionContaining(currentAddress);
		if (func == null)
			throw new Exception("Current address is not in a function");
		//setCurrentSelection(func.getBody());
		//getCurrentProgram().set
		Address funcEntry = func.getEntryPoint();

		Instruction instr = getCurrentProgram().getListing().getInstructionAt(funcEntry);
		if (instr == null) {
			throw new Exception("Cannot get first instruction");
		}

		currentAddress = funcEntry;
		Register sz = currentProgram.getRegister("FPCSR_SZ");
		if (instr.getValue(sz, false) != null) {
			throw new Exception("FPCSR.SZ already has a value");
		}

		instr.setValue(sz, BigInteger.valueOf(0));
		
//		instr = getCurrentProgram().getListing().getInstructionAt(func.getBody());
	}

}
