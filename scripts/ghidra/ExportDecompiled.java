// Ghidra headless post-script: write decompiled C for functions of the current program.
// Run through scripts/native-decompile.sh, not directly.
//
// Script arguments: <output file> [function name or 0xADDRESS ...]
// With no function arguments every non-thunk function is exported.
import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class ExportDecompiled extends GhidraScript {
  @Override
  public void run() throws Exception {
    String[] args = getScriptArgs();
    if (args.length < 1) {
      throw new IllegalArgumentException("usage: ExportDecompiled.java <output file> [function ...]");
    }
    FunctionManager fm = currentProgram.getFunctionManager();
    List<Function> targets = new ArrayList<>();
    if (args.length == 1) {
      for (Function f : fm.getFunctions(true)) {
        if (!f.isThunk() && !f.isExternal()) {
          targets.add(f);
        }
      }
    } else {
      for (int i = 1; i < args.length; i++) {
        String want = args[i];
        if (want.startsWith("0x")) {
          // addresses are given as file virtual addresses; Ghidra may rebase the image
          long offset = Long.parseLong(want.substring(2), 16);
          Address a = currentProgram.getImageBase().add(offset);
          Function f = fm.getFunctionContaining(a);
          if (f == null) {
            f = createFunction(a, null);
          }
          if (f != null) {
            targets.add(f);
          } else {
            println("no function at " + want);
          }
        } else {
          for (Function f : fm.getFunctions(true)) {
            if (f.getName().equals(want)) {
              targets.add(f);
            }
          }
        }
      }
    }

    DecompInterface ifc = new DecompInterface();
    ifc.openProgram(currentProgram);
    long base = currentProgram.getImageBase().getOffset();
    int failed = 0;
    try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
      w.println("// Decompiled by Ghidra from " + currentProgram.getName()
          + ". A reconstruction: names and types are inferred.");
      w.println("// Image base " + currentProgram.getImageBase()
          + "; addresses below are file virtual addresses (base subtracted).");
      for (Function f : targets) {
        if (monitor.isCancelled()) {
          break;
        }
        DecompileResults r = ifc.decompileFunction(f, 120, monitor);
        w.println();
        w.println("// ---- " + f.getName() + " @ 0x"
            + Long.toHexString(f.getEntryPoint().getOffset() - base));
        if (r != null && r.decompileCompleted()) {
          w.println(r.getDecompiledFunction().getC());
        } else {
          failed++;
          w.println("// DECOMPILE FAILED: " + (r == null ? "no result" : r.getErrorMessage()));
        }
      }
    } finally {
      ifc.dispose();
    }
    println("exported " + targets.size() + " functions, " + failed + " failed, to " + args[0]);
  }
}
