// Decompile every function whose name matches args[0] (regex) into args[1].
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;
public class Decomp extends GhidraScript {
  public void run() throws Exception {
    String[] a = getScriptArgs();
    DecompInterface d = new DecompInterface(); d.openProgram(currentProgram);
    try (PrintWriter w = new PrintWriter(new FileWriter(a[1]))) {
      for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
        String n = f.getName(true);
        if (!n.matches(a[0])) continue;
        DecompileResults r = d.decompileFunction(f, 120, monitor);
        w.println("// ==== " + n + " @ " + f.getEntryPoint());
        w.println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "// FAILED " + r.getErrorMessage());
      }
    }
  }
}
