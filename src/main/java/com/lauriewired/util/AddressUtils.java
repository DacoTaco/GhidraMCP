package com.lauriewired.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * Helpers for parsing addresses given to the handlers.
 */
public final class AddressUtils {
	private AddressUtils() {
	}

	/**
	 * Parses an address string, with or without 0x prefix.
	 *
	 * @param program    the program whose address space is used
	 * @param addressStr the address string
	 * @return the address
	 * @throws IllegalArgumentException when the address is missing or invalid
	 */
	public static Address parseAddress(Program program, String addressStr) {
		if (addressStr == null || addressStr.isBlank())
			throw new IllegalArgumentException("Address is required");

		Address address = program.getAddressFactory().getAddress(addressStr.trim());
		if (address == null)
			throw new IllegalArgumentException("Invalid address '" + addressStr + "'");
		return address;
	}
}
