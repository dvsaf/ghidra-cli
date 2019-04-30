/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.util.data;

import java.util.*;

import ghidra.app.plugin.core.datamgr.util.DataTypeUtils;
import ghidra.app.services.DataTypeManagerService;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.database.data.ProgramDataTypeManager;
import ghidra.program.model.data.*;

public class DataTypeParser {

	public enum AllowedDataTypes {
		/**
		 * All data-types are permitted
		 */
		ALL,
		/**
		 * All data-types, excluding factory data-types are permitted
		 */
		DYNAMIC,
		/**
		 * All fixed-length data-types and sizable Dynamic(i.e., canSpecifyLength) data-types
		 */
		SIZABLE_DYNAMIC,
		/**
		 * Only Fixed-length data-types
		 */
		FIXED_LENGTH
	}

	private DataTypeManager sourceDataTypeManager;			// may be null
	private DataTypeManager destinationDataTypeManager;		// may be null
	private DataTypeManagerService dataTypeManagerService;	// may be null
	private AllowedDataTypes allowedTypes;

	/**
	 * A constructor that does not use the source or destination data type managers.  In terms of
	 * the source data type manager, this means that all data type managers will be used when
	 * resolving data types.
	 * 
	 * @param dataTypeManagerService
	 * @param allowedTypes
	 */
	public DataTypeParser(DataTypeManagerService dataTypeManagerService,
			AllowedDataTypes allowedTypes) {
		this.dataTypeManagerService = dataTypeManagerService;
		this.allowedTypes = allowedTypes;
	}

	/**
	 * Constructor
	 * @param sourceDataTypeManager preferred source data-type manager, or null
	 * @param destinationDataTypeManager target data-type manager, or null
	 * @param dataTypeManagerService data-type manager tool service, or null
	 * @param allowedTypes constrains which data-types may be parsed
	 * 
	 * @see #DataTypeParser(DataTypeManagerService, AllowedDataTypes)
	 */
	public DataTypeParser(DataTypeManager sourceDataTypeManager,
			DataTypeManager destinationDataTypeManager,
			DataTypeManagerService dataTypeManagerService, AllowedDataTypes allowedTypes) {
		this.sourceDataTypeManager = sourceDataTypeManager;
		this.destinationDataTypeManager = destinationDataTypeManager;
		this.dataTypeManagerService = dataTypeManagerService;
		this.allowedTypes = allowedTypes;
	}

	/**
	 * Parse a data-type string specification
	 * @param dataTypeString a known data-type name followed by zero or more pointer/array decorations.
	 * @return parsed data-type or null if not found
	 * @throws InvalidDataTypeException if data-type string is invalid or length exceeds specified maxSize
	 */
	public DataType parse(String dataTypeString) throws InvalidDataTypeException {
		return parse(dataTypeString, (CategoryPath) null);
	}

	/**
	 * Parse a data-type string specification with category path.  If category is not null,
	 * the dataTypeManagerService will not be queried.
	 * @param dataTypeString a known data-type name followed by zero or more pointer/array decorations.
	 * @param category known path of data-type or null if unknown
	 * @return parsed data-type or null if not found
	 * @throws InvalidDataTypeException if data-type string is invalid or length exceeds specified maxSize
	 */
	public DataType parse(String dataTypeString, CategoryPath category)
			throws InvalidDataTypeException {
		dataTypeString = dataTypeString.replaceAll("\\s+", " ").trim();
		String dataTypeName = getBaseString(dataTypeString);
		DataType namedDt = getNamedDataType(dataTypeName, category);
		if (namedDt == null) {
			throw new InvalidDataTypeException("valid data-type not specified");
		}
		return parseDataTypeModifiers(namedDt, dataTypeString.substring(dataTypeName.length()));
	}

	/**
	 * Parse a data-type string specification using the specified baseDatatype.
	 * @param suggestedBaseDataType base data-type (may be null), this will be used as the base data-type if
	 * its name matches the base name in the specified dataTypeString.
	 * @param dataTypeString a base data-type followed by a sequence of zero or more pointer/array decorations to be applied.  
	 * The string may start with the baseDataType's name.
	 * @return parsed data-type or null if not found
	 * @throws InvalidDataTypeException if data-type string is invalid or length exceeds specified maxSize
	 */
	public DataType parse(String dataTypeString, DataType suggestedBaseDataType)
			throws InvalidDataTypeException {
		dataTypeString = dataTypeString.replaceAll("\\s+", " ").trim();
		String dataTypeName = getBaseString(dataTypeString);
		if (dataTypeName == null || dataTypeName.length() == 0) {
			throw new InvalidDataTypeException("missing base data-type name");
		}
		DataType namedDt;
		if (suggestedBaseDataType != null && dataTypeName.equals(suggestedBaseDataType.getName())) {
			namedDt = suggestedBaseDataType;
			if (namedDt.getDataTypeManager() != destinationDataTypeManager) {
				namedDt = namedDt.clone(destinationDataTypeManager);
			}
		}
		else {
			namedDt = getNamedDataType(dataTypeName, null);
			if (namedDt == null) {
				throw new InvalidDataTypeException("valid data-type not specified");
			}
		}

		return parseDataTypeModifiers(namedDt, dataTypeString.substring(dataTypeName.length()));
	}

	/**
	 * Validate the specified data-type dt against the specified allowedTypes.
	 * @param dt data-type
	 * @param allowedTypes
	 * @throws InvalidDataTypeException if dt violates the specified allowedTypes
	 */
	public static void checkAllowableType(DataType dt, AllowedDataTypes allowedTypes)
			throws InvalidDataTypeException {
		if (allowedTypes == AllowedDataTypes.DYNAMIC) {
			if (dt instanceof FactoryDataType) {
				throw new InvalidDataTypeException("factory data-type not allowed");
			}
		}
		else if (allowedTypes == AllowedDataTypes.SIZABLE_DYNAMIC) {
			if (dt instanceof FactoryDataType) {
				throw new InvalidDataTypeException("factory data-type not allowed");
			}
			if (dt instanceof Dynamic && !((Dynamic) dt).canSpecifyLength()) {
				throw new InvalidDataTypeException("non-sizable data-type not allowed");
			}
		}
		else if (allowedTypes == AllowedDataTypes.FIXED_LENGTH) {
			if (dt.getLength() < 0) {
				throw new InvalidDataTypeException("fixed-length data-type required");
			}
		}
	}

	private DataType parseDataTypeModifiers(DataType namedDataType, String dataTypeModifiers)
			throws InvalidDataTypeException {
		int arraySequenceStartIndex = -1;
		List<DtPiece> modifiers = new ArrayList<>();
		for (String piece : splitDataTypeModifiers(dataTypeModifiers)) {
			if (piece.startsWith("*")) {
				modifiers.add(new PointerSpecPiece(piece));
				arraySequenceStartIndex = -1;
			}
			else if (piece.startsWith("[")) {
				// group of array specifications are reversed for proper data-type creation order
				ArraySpecPiece arraySpec = new ArraySpecPiece(piece);
				if (arraySequenceStartIndex >= 0) {
					modifiers.add(arraySequenceStartIndex, arraySpec);
				}
				else {
					arraySequenceStartIndex = modifiers.size();
					modifiers.add(arraySpec);
				}
			}
			else if (piece.startsWith("{")) {
				// # indicates the size of an array element when the base data type is dynamic.
				modifiers.add(new ElementSizeSpecPiece(piece));
				arraySequenceStartIndex = -1;
			}
		}
		DataType dt = namedDataType;
		int elementLength = dt.getLength();
		try {
			for (DtPiece modifier : modifiers) {
				if (modifier instanceof PointerSpecPiece) {
					int pointerSize = ((PointerSpecPiece) modifier).getPointerSize();
					dt = new PointerDataType(dt, pointerSize, destinationDataTypeManager);
					elementLength = dt.getLength();
				}
				else if (modifier instanceof ElementSizeSpecPiece) {
					if (elementLength <= 0) {
						elementLength = ((ElementSizeSpecPiece) modifier).getElementSize();
					}
				}
				else {
					int elementCount = ((ArraySpecPiece) modifier).getElementCount();
					dt = createArrayDataType(dt, elementLength, elementCount);
					elementLength = dt.getLength();
				}
			}
		}
		catch (IllegalArgumentException e) {
			throw new InvalidDataTypeException(e.getMessage());
		}
		checkAllowableType(dt, allowedTypes);
		return dt;
	}

	private DataType getNamedDataType(String baseName, CategoryPath category)
			throws InvalidDataTypeException {

		List<DataType> results = new ArrayList<>();
		DataType dt = findDataType(sourceDataTypeManager, baseName, category, results);
		if (dt != null) {
			return dt; // found a direct match
		}

		//
		// We now either have no results or multiple results
		//
		if (results.isEmpty() && DataType.DEFAULT.getDisplayName().equals(baseName)) {
			dt = DataType.DEFAULT;
		}
		else if (category == null) {
			dt = findDataTypeInAllDataTypeManagers(baseName, results);
		}

		if (dt == null) {
			String msg = "Unrecognized data type of \"" + baseName + "\"";
			throw new InvalidDataTypeException(msg);
		}

		return dt.clone(destinationDataTypeManager);
	}

	private DataType findDataTypeInAllDataTypeManagers(String baseName, List<DataType> results) {
		if (results.isEmpty() && dataTypeManagerService != null) {
			results.addAll(
				DataTypeUtils.getExactMatchingDataTypes(baseName, dataTypeManagerService));
		}

		DataType dt = null;
		if (!results.isEmpty()) {
			// try to heuristically pick the right type
			dt = pickFromPossibleEquivalentDataTypes(results);
			if (dt == null && dataTypeManagerService != null) {
				// give up and ask the user
				dt = dataTypeManagerService.getDataType(baseName);
			}
		}
		return dt;
	}

	private DataType findDataType(DataTypeManager dtm, String baseName, CategoryPath category,
			List<DataType> list) {

		DataTypeManager builtInDTM = BuiltInDataTypeManager.getDataTypeManager();
		if (dtm == null) {
			// not DTM specified--try the built-ins
			return findDataType(builtInDTM, baseName, category, list);
		}

		if (category != null) {
			DataType dt = dtm.getDataType(category, baseName);
			if (dt != null) {
				list.add(dt);
				return dt;
			}
		}
		else {

			// handle C primitives (e.g.  long long, unsigned long int, etc.)
			DataType dataType = DataTypeUtilities.getCPrimitiveDataType(baseName);
			if (dataType != null) {
				return dataType;
			}

			dtm.findDataTypes(baseName, list);
			if (list.size() == 1) {
				return list.get(0);
			}
		}

		// nothing found--try the built-ins if we haven't yet
		if (list.isEmpty() && dtm != builtInDTM) {
			return findDataType(builtInDTM, baseName, category, list);
		}

		return null;
	}

	// ultimately, if one of the types is from the program or the builtin types, *and* the rest of
	// the data types are equivalent to that one, then this method returns that data type
	private static DataType pickFromPossibleEquivalentDataTypes(List<DataType> dtList) {

		DataType programDataType = null;

		// see if one of the data types belongs to the program or the built in types, where the
		// program is more important than the builtin
		for (Iterator<DataType> iter = dtList.iterator(); iter.hasNext();) {
			DataType dataType = iter.next();
			DataTypeManager manager = dataType.getDataTypeManager();
			if (manager instanceof BuiltInDataTypeManager) {
				programDataType = dataType;
			}
			else if (manager instanceof ProgramDataTypeManager) {
				programDataType = dataType;
				break;
			}
		}

		if (programDataType == null) {
			return null;
		}

		for (Iterator<DataType> iter = dtList.iterator(); iter.hasNext();) {
			DataType dataType = iter.next();
			// just one non-matching case means that we can't use the program's data type
			if (!programDataType.isEquivalent(dataType)) {
				return null;
			}
		}

		return programDataType;
	}

	private static String getBaseString(String dataTypeString) {
		int nextIndex = 0;
		while (nextIndex < dataTypeString.length()) {
			char c = dataTypeString.charAt(nextIndex);
			if (c == '*' || c == '[' || c == '{') {
				return dataTypeString.substring(0, nextIndex).trim();
			}
			++nextIndex;
		}
		return dataTypeString;
	}

	private static String[] splitDataTypeModifiers(String dataTypeModifiers) {
		dataTypeModifiers = dataTypeModifiers.replaceAll("[ \\t]", "");
		if (dataTypeModifiers.length() == 0) {
			return new String[0];
		}
		List<String> list = new ArrayList<>();
		int startIndex = 0;
		int nextIndex = 1;
		while (nextIndex < dataTypeModifiers.length()) {
			char c = dataTypeModifiers.charAt(nextIndex);
			if (c == '*' || c == '[' || c == '{') {
				list.add(dataTypeModifiers.substring(startIndex, nextIndex));
				startIndex = nextIndex;
			}
			++nextIndex;
		}
		list.add(dataTypeModifiers.substring(startIndex, nextIndex));
		String[] pieces = new String[list.size()];
		list.toArray(pieces);
		return pieces;
	}

	private DataType createArrayDataType(DataType baseDataType, int elementLength, int elementCount)
			throws InvalidDataTypeException {
		DataType dt = baseDataType;
		if (dt instanceof TypeDef) {
			dt = ((TypeDef) dt).getBaseDataType();
		}
		if (elementLength <= 0) {
			throw new InvalidDataTypeException(
				"only a positive datatype element size may be used for array: " +
					baseDataType.getName());
		}
		return new ArrayDataType(baseDataType, elementCount, elementLength,
			destinationDataTypeManager);
	}

	private static int parseArraySize(String numStr) {
		numStr = (numStr == null ? "" : numStr.trim());
		if (numStr.length() == 0) {
			throw new NumberFormatException();
		}
		if (numStr.startsWith("0x") || numStr.startsWith("0X")) {
			return Integer.parseInt(numStr.substring(2), 16);
		}
		return Integer.parseInt(numStr);
	}

	private static interface DtPiece {
		// dummy interface so we don't have to use Object in the list container
	}

	private static class ArraySpecPiece implements DtPiece {
		int elementCount;

		ArraySpecPiece(String piece) throws InvalidDataTypeException {
			if (piece.startsWith("[") && piece.endsWith("]")) {
				String elementCountStr = piece.substring(1, piece.length() - 1);
				try {
					elementCount = parseArraySize(elementCountStr);
					return;
				}
				catch (NumberFormatException e) {
					// handled below
				}
			}
			throw new InvalidDataTypeException("invalid array specification: " + piece);
		}

		int getElementCount() {
			return elementCount;
		}
	}

	private static class PointerSpecPiece implements DtPiece {
		int pointerSize = -1;

		PointerSpecPiece(String piece) throws InvalidDataTypeException {
			if (!piece.startsWith("*")) {
				throw new InvalidDataTypeException("invalid pointer specification: " + piece);
			}
			if (piece.length() == 1) {
				return;
			}
			try {
				pointerSize = Integer.parseInt(piece.substring(1));
			}
			catch (NumberFormatException e) {
				throw new InvalidDataTypeException("invalid pointer specification: " + piece);
			}
			int mod = pointerSize % 8;
			pointerSize = pointerSize / 8;
			if (mod != 0 || pointerSize <= 0 || pointerSize > 8) {
				throw new InvalidDataTypeException("invalid pointer size: " + piece);
			}
		}

		int getPointerSize() {
			return pointerSize;
		}
	}

	private static class ElementSizeSpecPiece implements DtPiece {
		int elementSize;

		ElementSizeSpecPiece(String piece) throws InvalidDataTypeException {
			if (piece.startsWith("{") && piece.endsWith("}")) {
				String elementSizeStr = piece.substring(1, piece.length() - 1);
				try {
					elementSize = parseArraySize(elementSizeStr);
					return;
				}
				catch (NumberFormatException e) {
					// handled below
				}
			}
			throw new InvalidDataTypeException(
				"invalid array element size specification: " + piece);
		}

		int getElementSize() {
			return elementSize;
		}
	}
}
