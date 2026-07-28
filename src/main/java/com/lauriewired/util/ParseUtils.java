package com.lauriewired.util;

import java.util.Collections;
import java.util.List;

import ghidra.program.model.address.Address;

/**
 * Utility methods for parsing HTTP requests and responses.
 * 
 * This class provides methods to parse query parameters, post body parameters,
 * paginate lists, parse integers with defaults, escape non-ASCII characters,
 * and send HTTP responses.
 */
public final class ParseUtils {

	/**
	 * Paginate a list of items based on offset and limit.
	 * 
	 * @param items  The list of items to paginate.
	 * @param offset The starting index for pagination.
	 * @param limit  The maximum number of items to return.
	 * @return A string containing the paginated items, each on a new line.
	 *         If the offset is beyond the list size, returns an empty string.
	 */
	public static <T> List<T> paginateList(List<T> items, int offset, int limit) {
		int start = Math.max(0, offset);
		int end = Math.min(items.size(), start + limit);

		if (start >= items.size()) {
			return Collections.emptyList();
		}

		return items.subList(start, end);
	}
	/**
	 * Escape non-ASCII characters in a string.
	 * 
	 * @param input The input string to escape.
	 * @return A string where non-ASCII characters are replaced with their
	 *         hexadecimal representation, e.g. "\xFF" for 255.
	 */
	public static String escapeNonAscii(String input) {
		if (input == null)
			return "";
		StringBuilder sb = new StringBuilder();
		for (char c : input.toCharArray()) {
			if (c >= 32 && c < 127) {
				sb.append(c);
			} else {
				sb.append("\\x");
				sb.append(Integer.toHexString(c & 0xFF));
			}
		}
		return sb.toString();
	}

	/**
	 * Escape special characters in a string for safe display
	 * 
	 * @param input the string to escape
	 * @return the escaped string
	 */
	public static String escapeString(String input) {
		if (input == null)
			return "";

		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < input.length(); i++) {
			char c = input.charAt(i);
			if (c >= 32 && c < 127) {
				sb.append(c);
			} else if (c == '\n') {
				sb.append("\\n");
			} else if (c == '\r') {
				sb.append("\\r");
			} else if (c == '\t') {
				sb.append("\\t");
			} else {
				sb.append(String.format("\\x%02x", (int) c & 0xFF));
			}
		}
		return sb.toString();
	}

	/**
	 * Generate a hexdump of a byte array starting from a given base address.
	 * 
	 * @param base The base address to start the hexdump from.
	 * @param buf  The byte array to generate the hexdump for.
	 * @param len  The number of bytes to include in the hexdump.
	 * @return A string representation of the hexdump.
	 */
	public static String hexdump(Address base, byte[] buf, int len) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < len; i += 16) {
			sb.append(String.format("%s  ", base.add(i)));
			for (int j = 0; j < 16 && (i + j) < len; j++) {
				sb.append(String.format("%02X ", buf[i + j]));
			}
			sb.append('\n');
		}
		return sb.toString();
	}

	/**
	 * Decode a hexadecimal string into a byte array.
	 * 
	 * @param hex The hexadecimal string to decode.
	 * @return A byte array representing the decoded hexadecimal string.
	 * @throws IllegalArgumentException If the input string is not a valid hex
	 *                                  string.
	 */
	public static byte[] decodeHex(String hex) {
		hex = hex.replaceAll("\\s+", "");
		if (hex.length() % 2 != 0)
			throw new IllegalArgumentException();
		byte[] out = new byte[hex.length() / 2];
		for (int i = 0; i < out.length; i++) {
			out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
		}
		return out;
	}
}
