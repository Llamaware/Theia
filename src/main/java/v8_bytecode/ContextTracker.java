package v8_bytecode;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import v8_bytecode.storage.FuncsStorage;
import v8_bytecode.storage.ScopeInfoStore;
import v8_bytecode.storage.SharedFunctionStore;

/**
 * Works out which context (and so which ScopeInfo) every context-slot access refers to.
 *
 * <p>V8 enters a function with the context of the closure, i.e. the context that was current
 * where the creating CreateClosure ran (the code cache does not keep outer_scope_info).
 * Create*Context makes a child of the current context, PushContext rX saves the current
 * context in rX and switches to the new one, PopContext rX switches back. Functions are
 * walked along their control flow, callers before the closures they create, starting at the
 * top-level script function, which runs in the script context described by its own ScopeInfo.
 */
public final class ContextTracker {
	/** A runtime context: the scope it was created for and the context it was created in. */
	private static final class Ctx {
		final ScopeInfoStore scope;
		final Ctx parent;

		Ctx(ScopeInfoStore scope, Ctx parent) {
			this.scope = scope;
			this.parent = parent;
		}
	}

	/** Context state while walking a function: current context, acc (a new context) and registers. */
	private static final class State {
		Ctx current;
		Ctx acc;
		Map<String, Ctx> regs = new HashMap<>();

		State(Ctx current) {
			this.current = current;
		}

		State copy() {
			State s = new State(current);
			s.acc = acc;
			s.regs = new HashMap<>(regs);
			return s;
		}
	}

	private static final String CONTEXT = "_context";

	private final Program program;
	private final FuncsStorage funcsStorage;
	private final FlatProgramAPI fpa;
	private final Map<Address, Ctx> slotContexts = new HashMap<>();
	private final Map<Address, Ctx> initial = new HashMap<>();
	private final Deque<Function> work = new ArrayDeque<>();

	public ContextTracker(Program program, FuncsStorage funcsStorage, AddressSetView set, TaskMonitor monitor)
			throws CancelledException {
		this.program = program;
		this.funcsStorage = funcsStorage;
		this.fpa = new FlatProgramAPI(program);

		// Which functions some CreateClosure creates: the others are where the walk starts.
		final Set<Address> created = new HashSet<>();
		for (Instruction ins : program.getListing().getInstructions(set, true)) {
			if (trimMnemonic(ins.getMnemonicString()).equals("CreateClosure")) {
				final Function child = closureTarget(ins);
				if (child != null) {
					created.add(child.getEntryPoint());
				}
			}
		}
		// Function literal 0 is the top-level script code, which runs in the script context. Roots
		// no CreateClosure reaches (declarations made by DeclareGlobals) close over that context too.
		Ctx script = new Ctx(null, null);
		for (Function f : program.getFunctionManager().getFunctions(set, true)) {
			if (f.getName().equals("func_0000")) {
				script = new Ctx(funcsStorage.getScopeInfo(f.getEntryPoint(), CONTEXT), null);
			}
		}
		final Set<Function> done = new HashSet<>();
		for (Function f : program.getFunctionManager().getFunctions(set, true)) {
			if (created.contains(f.getEntryPoint())) {
				continue;
			}
			initial.put(f.getEntryPoint(), script);
			work.add(f);
			while (!work.isEmpty()) {
				monitor.checkCancelled();
				final Function next = work.poll();
				if (done.add(next)) {
					walk(next, initial.get(next.getEntryPoint()));
				}
			}
		}
		// Closures whose creator could not be followed.
		for (Function f : program.getFunctionManager().getFunctions(set, true)) {
			if (done.add(f)) {
				walk(f, initial.getOrDefault(f.getEntryPoint(), script));
			}
		}
	}

	private Function closureTarget(Instruction ins) {
		final Object item = funcsStorage.getConstItem(ins.getAddress(), scalar(ins, 0));
		if (item instanceof SharedFunctionStore) {
			return fpa.getFunctionAt(fpa.toAddr(((SharedFunctionStore) item).getAddress()));
		}
		return null;
	}

	private int walked;
	private int visitedTotal;

	/** @return counts for the analyzer log */
	public String summary() {
		return walked + " functions walked (" + visitedTotal + " instructions), " + slotContexts.size()
				+ " context-slot accesses";
	}

	/** @return the ScopeInfo of the context a context-slot access at {@code addr} reads or writes */
	public ScopeInfoStore getSlotScope(Address addr) {
		final Ctx ctx = slotContexts.get(addr);
		return ctx != null ? ctx.scope : null;
	}

	private void walk(Function func, Ctx entry) {
		walked++;
		final Set<Address> visited = new HashSet<>();
		final Deque<Object[]> pending = new ArrayDeque<>();
		pending.push(new Object[] { func.getEntryPoint(), new State(entry) });
		while (!pending.isEmpty()) {
			final Object[] item = pending.pop();
			Address addr = (Address) item[0];
			final State state = (State) item[1];
			while (addr != null && inFunction(program, func, addr) && visited.add(addr)) {
				final Instruction ins = program.getListing().getInstructionAt(addr);
				if (ins == null) {
					break;
				}
				visitedTotal++;
				step(func, ins, state);
				for (Address target : ins.getFlows()) {
					pending.push(new Object[] { target, state.copy() });
				}
				addr = ins.getFallThrough();
			}
		}
	}

	/**
	 * @return the function's instructions in address order, found by following its control flow:
	 * the analyzer first runs before Ghidra has grown the function bodies past their entry points
	 */
	public static List<Instruction> instructions(Program program, Function func) {
		final Set<Address> visited = new HashSet<>();
		final Deque<Address> pending = new ArrayDeque<>();
		final List<Instruction> result = new ArrayList<>();
		pending.push(func.getEntryPoint());
		while (!pending.isEmpty()) {
			Address addr = pending.pop();
			while (addr != null && inFunction(program, func, addr) && visited.add(addr)) {
				final Instruction ins = program.getListing().getInstructionAt(addr);
				if (ins == null) {
					break;
				}
				result.add(ins);
				for (Address target : ins.getFlows()) {
					pending.push(target);
				}
				addr = ins.getFallThrough();
			}
		}
		result.sort((a, b) -> a.getAddress().compareTo(b.getAddress()));
		return result;
	}

	/** Bytecode never flows into another function; stop where one starts (Throw falls through). */
	private static boolean inFunction(Program program, Function func, Address addr) {
		return addr.equals(func.getEntryPoint()) || program.getFunctionManager().getFunctionAt(addr) == null;
	}

	private void step(Function func, Instruction ins, State state) {
		final String mnemonic = trimMnemonic(ins.getMnemonicString());
		final Address addr = ins.getAddress();
		switch (mnemonic) {
		case "CreateFunctionContext":
		case "CreateEvalContext":
			state.acc = new Ctx(funcsStorage.getScopeInfo(addr, CONTEXT), state.current);
			break;
		case "CreateBlockContext":
			state.acc = new Ctx(scopeOperand(addr, ins, 0), state.current);
			break;
		case "CreateCatchContext":
			state.acc = new Ctx(scopeOperand(addr, ins, 2), state.current);
			break;
		case "CreateWithContext":
			state.acc = new Ctx(scopeOperand(addr, ins, 1), state.current);
			break;
		case "PushContext":
			state.regs.put(registerName(ins, 0), state.current);
			if (state.acc != null) {
				state.current = state.acc;
			}
			break;
		case "PopContext": {
			final Ctx saved = state.regs.get(registerName(ins, 0));
			if (saved != null) {
				state.current = saved;
			}
		} break;
		case "Mov": {
			final Ctx src = contextIn(state, registerName(ins, 0));
			if (src != null) {
				state.regs.put(registerName(ins, 1), src);
			}
		} break;
		case "CreateClosure": {
			final Function child = closureTarget(ins);
			if (child != null && !initial.containsKey(child.getEntryPoint())) {
				initial.put(child.getEntryPoint(), state.current);
				work.add(child);
			}
		} break;
		case "LdaCurrentContextSlot":
		case "LdaImmutableCurrentContextSlot":
		case "StaCurrentContextSlot":
			slotContexts.put(addr, state.current);
			break;
		case "LdaContextSlot":
		case "LdaImmutableContextSlot":
		case "StaContextSlot": {
			Ctx ctx = contextIn(state, registerName(ins, 0));
			for (int depth = scalar(ins, 2); ctx != null && depth > 0; --depth) {
				ctx = ctx.parent;
			}
			slotContexts.put(addr, ctx);
		} break;
		default:
			break;
		}
	}

	private Ctx contextIn(State state, String reg) {
		return CONTEXT.equals(reg) ? state.current : state.regs.get(reg);
	}

	private ScopeInfoStore scopeOperand(Address addr, Instruction ins, int opIndex) {
		final Object item = funcsStorage.getConstItem(addr, scalar(ins, opIndex));
		return item instanceof ScopeInfoStore ? (ScopeInfoStore) item : null;
	}

	private static String registerName(Instruction ins, int opIndex) {
		final Register reg = ins.getRegister(opIndex);
		return reg != null ? reg.getName() : "";
	}

	private static int scalar(Instruction ins, int opIndex) {
		final Scalar s = ins.getScalar(opIndex);
		return s != null ? (int) s.getUnsignedValue() : -1;
	}

	private static String trimMnemonic(String mnemonic) {
		final int dot = mnemonic.indexOf('.');
		return dot != -1 ? mnemonic.substring(0, dot) : mnemonic;
	}
}
