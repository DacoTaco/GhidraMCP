package com.lauriewired.handlers.set;

import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.SwingUtilities;

import org.eclipse.jetty.http.HttpMethod;

import com.lauriewired.handlers.Handler;
import com.lauriewired.http.HttpRoute;
import com.lauriewired.endpoints.Param;
import com.lauriewired.mcp.McpTool;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Handler for writing bytes to a specific memory address in the current program.
 * Expects POST parameters: "address" (the target address) and "bytes" (hex string separated by spaces).
 */
public final class SetBytes extends Handler {

    /**
     * Constructor for the new SetBytes handler.
     *
     * @param tool the PluginTool instance to use for program access
     */
    public SetBytes(PluginTool tool) {
        super(tool);
    }

    /**
     * Writes the given bytes to the specified memory address in the current program.
     *
     * @param addressStr the string representation of the address
     * @param bytesStr   the string of bytes in hex (e.g., "90 90 90")
     * @return a message indicating the result of the operation
     */
    @HttpRoute(method=HttpMethod.POST, path="/set_bytes")
    @McpTool(name="set_bytes", description="Writes a sequence of bytes to the specified address in the program's memory.")
    public String writeBytesToAddress(@Param(name="address") String addressStr, @Param(name="bytes") String bytesStr, @Param(name="program", nullable=true) String programName) {
        Program program = getProgramByName(programName);
        if (program == null)
            return "No active program";

        AtomicReference<String> result = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int txId = program.startTransaction("Write Bytes");
                boolean success = false;
                try {
                    Address address = program.getAddressFactory().getAddress(addressStr);
                    Memory memory = program.getMemory();

                    String[] byteTokens = bytesStr.trim().split("\\s+");
                    byte[] newBytes = new byte[byteTokens.length];
                    for (int i = 0; i < byteTokens.length; i++) {
                        newBytes[i] = (byte) Integer.parseInt(byteTokens[i], 16);
                    }

                    Address endAddress = address.add(newBytes.length - 1);

                    if (!memory.contains(address) || !memory.contains(endAddress)) {
                        result.set("Memory range out of bounds or unmapped");
                        return;
                    }

                    byte[] existingBytes = new byte[newBytes.length];
                    int bytesRead = memory.getBytes(address, existingBytes);
                    if (bytesRead != newBytes.length) {
                        result.set("Mismatch: memory region size differs from replacement size");
                        return;
                    }

                    Listing listing = program.getListing();
                    listing.clearCodeUnits(address, endAddress, false);
                    memory.setBytes(address, newBytes);

                    Disassembler disassembler = Disassembler.getDisassembler(program, TaskMonitor.DUMMY, null);
                    disassembler.disassemble(address, null);

                    success = true;
                    result.set("Bytes written successfully");
                } catch (Exception e) {
                    Msg.error(this, "Write bytes error", e);
                    result.set("Error: " + e.getMessage());
                } finally {
                    program.endTransaction(txId, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to write bytes on Swing thread", e);
            return "Error: failed to execute on Swing thread: " + e.getMessage();
        }

        return result.get();
    }
}
