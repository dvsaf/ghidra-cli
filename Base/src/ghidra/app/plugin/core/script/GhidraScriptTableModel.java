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
package ghidra.app.plugin.core.script;

import java.awt.Color;
import java.awt.Component;
import java.util.*;

import javax.swing.*;

import docking.widgets.table.*;
import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.ScriptInfo;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.util.DateUtils;
import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.CaseInsensitiveDuplicateStringComparator;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;
import resources.Icons;

class GhidraScriptTableModel extends GDynamicColumnTableModel<ResourceFile, Object> {

	private static final String EMPTY_STRING = "";
	private static final ImageIcon ERROR_IMG = Icons.ERROR_ICON;

	final static String SCRIPT_ACTION_COLUMN_NAME = "In Tool";
	final static String SCRIPT_STATUS_COLUMN_NAME = "Status";

	private GhidraScriptComponentProvider provider;
	private List<ResourceFile> scriptList = new ArrayList<>();

	GhidraScriptTableModel(GhidraScriptComponentProvider provider) {
		super(provider.getTool());
		this.provider = provider;
	}

	@Override
	protected TableColumnDescriptor<ResourceFile> createTableColumnDescriptor() {
		TableColumnDescriptor<ResourceFile> descriptor = new TableColumnDescriptor<>();
		descriptor.addVisibleColumn(new ScriptActionColumn());
		descriptor.addVisibleColumn(new StatusColumn());
		descriptor.addVisibleColumn(new NameColumn(), 1, true);
		descriptor.addVisibleColumn(new DescriptionColumn());
		descriptor.addVisibleColumn(new KeyBindingColumn());
		descriptor.addHiddenColumn(new PathColumn());
		descriptor.addVisibleColumn(new CategoryColumn());
		descriptor.addHiddenColumn(new CreatedColumn());
		descriptor.addVisibleColumn(new ModifiedColumn());

		return descriptor;
	}

	@Override
	public String getName() {
		return "Scripts";
	}

	boolean contains(int row) {
		return row >= 0 && row < scriptList.size();
	}

	int getScriptIndex(ResourceFile script) {
		return scriptList.indexOf(script);
	}

	List<ResourceFile> getScripts() {
		return new ArrayList<>(scriptList);
	}

	ResourceFile getScriptAt(int row) {
		if (row < 0 || row > scriptList.size() - 1) {
			return null;
		}
		return scriptList.get(row);
	}

	void insertScript(ResourceFile script) {
		if (!scriptList.contains(script)) {
			int row = scriptList.size();
			scriptList.add(script);
			fireTableRowsInserted(row, row);
		}
	}

	void insertScripts(List<ResourceFile> scriptFiles) {
		for (ResourceFile script : scriptFiles) {
			if (!scriptList.contains(script)) {
				scriptList.add(script);
			}
		}
		fireTableDataChanged();
	}

	void removeScript(ResourceFile script) {
		int row = scriptList.indexOf(script);
		if (row >= 0) {
			scriptList.remove(row);

			fireTableRowsDeleted(row, row);
		}
	}

	void switchScript(ResourceFile oldScript, ResourceFile newScript) {
		int index = scriptList.indexOf(oldScript);
		if (index != -1) {
			scriptList.set(index, newScript);
			fireTableRowsUpdated(index, index);
		}
	}

	int getNameColumnIndex() {
		return getColumnIndex(NameColumn.class);
	}

	@Override
	public int getRowCount() {
		if (scriptList == null) {
			return 0;
		}
		return scriptList.size();
	}

	@Override
	public boolean isCellEditable(int row, int col) {

		DynamicTableColumn<ResourceFile, ?, ?> column = tableColumns.get(col);
		String columnName = column.getColumnName();
		if (SCRIPT_ACTION_COLUMN_NAME.equals(columnName)) {
			return true;
		}
		return false;
	}

	@Override
	public void setValueAt(Object value, int row, int col) {
		DynamicTableColumn<ResourceFile, ?, ?> column = tableColumns.get(col);
		String columnName = column.getColumnName();
		if (SCRIPT_ACTION_COLUMN_NAME.equals(columnName)) {
			ResourceFile script = getScriptAt(row);
			if ((Boolean) value) {
				provider.getActionManager().createAction(script);
			}
			else {
				provider.getActionManager().removeAction(script);
			}
		}
		fireTableCellUpdated(row, col);
	}

	private String getCategoryString(ScriptInfo info) {
		String[] category = info.getCategory();
		if (category.length == 0) {
			return EMPTY_STRING;
		}

		StringBuilder buffy = new StringBuilder();
		for (String string : category) {
			buffy.append(string).append('-').append('>');
		}

		buffy.delete(buffy.length() - 2, buffy.length()); // strip off last separator

		return buffy.toString();
	}

	@Override
	public List<ResourceFile> getModelData() {
		return scriptList;
	}

	@Override
	public Object getDataSource() {
		return null;
	}

	private class ScriptActionColumn
			extends AbstractDynamicTableColumn<ResourceFile, Boolean, Object> {

		@Override
		public String getColumnDescription() {
			return "When selected, the script has been added as an action to the tool";
		}

		@Override
		public String getColumnName() {
			return "In Tool";
		}

		@Override
		public Boolean getValue(ResourceFile rowObject, Settings settings, Object data,
				ServiceProvider sp) throws IllegalArgumentException {
			return provider.getActionManager().hasScriptAction(rowObject);
		}
	}

	private class StatusColumn extends AbstractDynamicTableColumn<ResourceFile, ImageIcon, Object> {
		private Comparator<ImageIcon> comparator = (i1, i2) -> {
			if (i1 == i2) {
				return 0;
			}
			if (i1 == ERROR_IMG && i2 != ERROR_IMG) {
				return -1;
			}
			if (i1 != ERROR_IMG && i2 == ERROR_IMG) {
				return 1;
			}
			if (i1 == null) {
				return 1; // empty after icon
			}
			if (i2 == null) {
				return -1; // empty after icon
			}
			String d1 = i1.getDescription();
			String d2 = i2.getDescription();
			return SystemUtilities.compareTo(d1, d2);
		};

		private GColumnRenderer<ImageIcon> renderer = new AbstractGColumnRenderer<ImageIcon>() {
			@Override
			public Component getTableCellRendererComponent(GTableCellRenderingData data) {
				JLabel label = (JLabel) super.getTableCellRendererComponent(data);

				ResourceFile file = (ResourceFile) data.getRowObject();
				ScriptInfo info = GhidraScriptUtil.getScriptInfo(file);

				label.setText(null);
				label.setToolTipText(null);
				if (info.hasErrors()) {
					label.setToolTipText("Status: " + info.getErrorMessage());
				}

				ImageIcon icon = (ImageIcon) data.getValue();
				label.setIcon(null);
				if (icon != null) {
					label.setToolTipText("Status: Script has toolbar icon");
					label.setIcon(icon);
				}
				else {
					label.setToolTipText("Status: No script toolbar icon has been set");
				}

				return label;
			}

			@Override
			public String getFilterString(ImageIcon t, Settings settings) {
				// we could use the tooltip text, but it doesn't seem worth it
				return "";
			}
		};

		@Override
		public GColumnRenderer<ImageIcon> getColumnRenderer() {
			return renderer;
		}

		@Override
		public String getColumnName() {
			return "Status";
		}

		@Override
		public ImageIcon getValue(ResourceFile rowObject, Settings settings, Object data,
				ServiceProvider sp) throws IllegalArgumentException {
			ScriptInfo info = GhidraScriptUtil.getScriptInfo(rowObject);
			if (info.isCompileErrors() || info.isDuplicate()) {
				return ERROR_IMG;
			}
			return info.getToolBarImage(true);
		}

		@Override
		public Comparator<ImageIcon> getComparator() {
			return comparator;
		}
	}

	private class NameColumn extends AbstractDynamicTableColumn<ResourceFile, String, Object> {

		private Comparator<String> comparator = new CaseInsensitiveDuplicateStringComparator();

		@Override
		public Comparator<String> getComparator() {
			return comparator;
		}

		@Override
		public String getColumnName() {
			return "Name";
		}

		@Override
		public String getValue(ResourceFile rowObject, Settings settings, Object data,
				ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getName();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 250;
		}
	}

	private class DescriptionColumn
			extends AbstractDynamicTableColumn<ResourceFile, String, Object> {

		@Override
		public String getColumnName() {
			return "Description";
		}

		@Override
		public String getValue(ResourceFile rowObject, Settings settings, Object data,
				ServiceProvider sp) throws IllegalArgumentException {
			ScriptInfo info = GhidraScriptUtil.getScriptInfo(rowObject);
			return info.getDescription();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 250;
		}
	}

	private class KeyBindingColumn
			extends AbstractDynamicTableColumn<ResourceFile, KeyBindingsInfo, Object> {

		private GColumnRenderer<KeyBindingsInfo> renderer =
			new AbstractGColumnRenderer<KeyBindingsInfo>() {

				@Override
				public Component getTableCellRendererComponent(GTableCellRenderingData data) {
					JComponent component = (JComponent) super.getTableCellRendererComponent(data);

					Object value = data.getValue();
					boolean isSelected = data.isSelected();

					KeyBindingsInfo info = (KeyBindingsInfo) value;

					if (info.errorMessage != null) {
						component.setForeground(Color.RED);
						component.setToolTipText(info.errorMessage);
					}
					else {
						String keybindingText = "";
						if (!info.keystroke.isEmpty()) {
							keybindingText = ": " + info.toString();
						}

						if (info.hasAction) {
							component.setForeground(Color.BLACK);
							component.setToolTipText(
								"Keybinding for action in tool" + keybindingText);
						}
						else {
							component.setForeground(Color.LIGHT_GRAY);
							component.setToolTipText("Keybinding for script" + keybindingText);
						}
					}

					if (isSelected) {
						Color selectedForegroundColor =
							(info.errorMessage != null) ? Color.PINK : Color.WHITE;
						component.setForeground(selectedForegroundColor);
					}
					return component;

				}

				@Override
				public String getFilterString(KeyBindingsInfo t, Settings settings) {
					return t.toString();
				}
			};

		@Override
		public GColumnRenderer<KeyBindingsInfo> getColumnRenderer() {
			return renderer;
		}

		@Override
		public String getColumnName() {
			return "Key";
		}

		@Override
		public KeyBindingsInfo getValue(ResourceFile rowObject, Settings settings, Object data,
				ServiceProvider sp) throws IllegalArgumentException {
			ScriptInfo info = GhidraScriptUtil.getScriptInfo(rowObject);
			KeyStroke actionKeyStroke = provider.getActionManager().getKeyBinding(rowObject);
			boolean isActionBinding = false;
			KeyStroke keyBinding = info.getKeyBinding();
			if (actionKeyStroke != null) {
				keyBinding = actionKeyStroke;
				isActionBinding = true;
			}

			String errorMessage = info.getKeyBindingErrorMessage();
			if (errorMessage != null) {
				return new KeyBindingsInfo(isActionBinding, keyBinding, errorMessage);
			}
			return new KeyBindingsInfo(isActionBinding, keyBinding);
		}

		@Override
		public int getColumnPreferredWidth() {
			return 80;
		}
	}

	private class PathColumn extends AbstractDynamicTableColumn<ResourceFile, String, Object> {

		@Override
		public String getColumnName() {
			return "Path";
		}

		@Override
		public String getValue(ResourceFile rowObject, Settings settings, Object data,
				ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getAbsolutePath();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 250;
		}
	}

	private class CategoryColumn extends AbstractDynamicTableColumn<ResourceFile, String, Object> {

		private Comparator<String> comparator = new CaseInsensitiveDuplicateStringComparator();

		@Override
		public Comparator<String> getComparator() {
			return comparator;
		}

		@Override
		public String getColumnName() {
			return "Category";
		}

		@Override
		public String getValue(ResourceFile rowObject, Settings settings, Object data,
				ServiceProvider sp) throws IllegalArgumentException {
			ScriptInfo info = GhidraScriptUtil.getScriptInfo(rowObject);
			return getCategoryString(info);
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}
	}

	private class CreatedColumn extends AbstractDynamicTableColumn<ResourceFile, Date, Object> {

		private DateRenderer renderer = new DateRenderer();

		@Override
		public GColumnRenderer<Date> getColumnRenderer() {
			return renderer;
		}

		@Override
		public String getColumnName() {
			return "Created";
		}

		@Override
		public Date getValue(ResourceFile rowObject, Settings settings, Object data,
				ServiceProvider sp) throws IllegalArgumentException {
			return new Date(rowObject.lastModified());
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}
	}

	private class ModifiedColumn extends AbstractDynamicTableColumn<ResourceFile, Date, Object> {

		private DateRenderer renderer = new DateRenderer();

		@Override
		public GColumnRenderer<Date> getColumnRenderer() {
			return renderer;
		}

		@Override
		public String getColumnName() {
			return "Modified";
		}

		@Override
		public Date getValue(ResourceFile rowObject, Settings settings, Object data,
				ServiceProvider sp) throws IllegalArgumentException {
			return new Date(rowObject.lastModified());
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}
	}

	private class DateRenderer extends AbstractGColumnRenderer<Date> {
		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			Date date = (Date) data.getValue();
			String formatted = DateUtils.formatDate(date);
			JLabel renderer = (JLabel) super.getTableCellRendererComponent(data);
			renderer.setText(formatted);
			return renderer;
		}

		@Override
		public ColumnConstraintFilterMode getColumnConstraintFilterMode() {
			// not sure about this: it could be USE_COLUMN_CONSTRAINTS_ONLY, but then the text
			// filter would not match the formatted date.  This allows for both.
			return ColumnConstraintFilterMode.USE_BOTH_COLUMN_RENDERER_FITLER_STRING_AND_CONSTRAINTS;
		}

		@Override
		public String getFilterString(Date t, Settings settings) {
			String formatted = DateUtils.formatDate(t);
			return formatted;
		}
	}

}
