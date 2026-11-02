package com.lauriewired.util;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;

/**
 * Utility class for handling structures and their members.
 * This class provides a representation of a structure member with its name,
 * type, comment, and offset.
 */
public final class StructUtils {
	/**
	 * Represents a member of a structure.
	 */
	public static class StructMember {
		/**
		 * The name of the member.
		 */
		public String name;

		/**
		 * The type of the member.
		 */
		public String type;

		/**
		 * The comment for the member.
		 */
		public String comment;

		/**
		 * The offset of the member in the structure.
		 * Initialized to -1 to indicate that it has not been set.
		 */
		public double offset = -1; // Use double to handle GSON parsing number as double
	}

	/**
	 * Places a member over undefined bytes, so pre-sized structures keep their size.
	 *
	 * @param struct   The structure to modify.
	 * @param member   The member to place.
	 * @param dataType The resolved data type of the member.
	 */
	public static void PlaceMember(Structure struct, StructMember member, DataType dataType) {
		int offset = (int) member.offset;
		if (member.offset == -1) {
			if (struct.isPackingEnabled()) {
				struct.add(dataType, member.name, member.comment);
				return;
			}
			offset = 0;
			DataTypeComponent[] defined = struct.getDefinedComponents();
			if (defined.length > 0) {
				DataTypeComponent last = defined[defined.length - 1];
				offset = last.getOffset() + last.getLength();
			}
		}

		// an empty structure reports a length of 1
		int length = struct.isZeroLength() ? 0 : struct.getLength();
		if (offset < length) {
			struct.replaceAtOffset(offset, dataType, -1, member.name, member.comment);
			return;
		}

		if (offset > length)
			struct.growStructure(offset - length);
		struct.add(dataType, member.name, member.comment);
	}
}
