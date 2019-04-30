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
package ghidra.util.table;

import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.table.TableModel;

import docking.ActionContext;
import docking.action.MenuData;
import docking.action.ToolBarData;
import docking.widgets.table.GTable;
import docking.widgets.table.RowObjectTableModel;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.app.actions.AbstractSharedKeybindingAction;
import ghidra.app.util.HelpTopics;
import ghidra.framework.options.DummyKeyBindingsOptionsAction;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.timer.GTimer;
import resources.ResourceManager;

/**
 * An action to delete data from a table.   If your model is a {@link ThreadedTableModel}, then
 * this class is self-contained.  If you have some other kind of model, then you must 
 * override {@link #removeSelectedItems()} in order to remove items from your model when the 
 * action is executed.
 * <p>
 * Note: deleting a row object is simply removing it from the given table/model.  This code is
 * not altering the database.
 * <p>
 * Tip: if you are a plugin that uses transient providers, then use 
 * {@link #registerDummy(PluginTool)} at creation time to install a dummy representative of
 * this action in the Tool's options so that user's can update keybindings, regardless of whether
 * they have ever shown one of your transient providers.  
 */
public class DeleteTableRowAction extends AbstractSharedKeybindingAction {

	private static final KeyStroke DEFAULT_KEYSTROKE =
		KeyStroke.getKeyStroke(KeyEvent.VK_DELETE, 0);
	private static final ImageIcon ICON = ResourceManager.loadImage("images/table_delete.png");
	private static final String NAME = "Remove Items";

	private GTable table;

	/**
	 * A special method that triggers the registration of this action's shared/dummy keybinding.
	 * This is needed for plugins that produce transient component providers that do not exist
	 * at the time the plugin is loaded.
	 * 
	 * @param tool the tool whose options will updated with a dummy keybinding
	 */
	public static void registerDummy(PluginTool tool) {
		new DummyDeleteAction(tool);
	}

	/**
	 * Constructor for stubs only.
	 * 
	 * @param tool the tool needed to access options
	 */
	private DeleteTableRowAction(PluginTool tool) {
		super(tool, NAME, DummyKeyBindingsOptionsAction.DEFAULT_OWNER, DEFAULT_KEYSTROKE);
	}

	public DeleteTableRowAction(PluginTool tool, GTable table, String owner) {
		this(tool, NAME, owner, DEFAULT_KEYSTROKE);
		this.table = table;
	}

	private DeleteTableRowAction(PluginTool tool, String name, String owner,
			KeyStroke defaultkeyStroke) {
		super(tool, name, owner, defaultkeyStroke);
		
		setDescription("Remove the selected rows from the table");
		setHelpLocation(new HelpLocation(HelpTopics.SEARCH, "Remove_Items"));
		setToolBarData(new ToolBarData(ICON, null));
		setPopupMenuData(new MenuData(new String[] { "Remove Items" }, ICON, null));
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return table.getSelectedRowCount() > 0;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		removeSelectedItems();
	}

	protected void removeSelectedItems() {
		TableModel model = table.getModel();
		if (!(model instanceof RowObjectTableModel)) {
			throw new AssertException("This action cannot delete rows for the given table model." +
				"You can override this method to peform the delete action yourself.");
		}

		if (checkForBusy(model)) {
			Msg.showInfo(this, table, "Table is Busy",
				"Cannot remove items from the table while it is working");
			return;
		}

		@SuppressWarnings("unchecked")
		RowObjectTableModel<Object> rowObjectModel = (RowObjectTableModel<Object>) model;
		int[] rows = table.getSelectedRows();
		List<Object> itemsToRemove = new ArrayList<Object>();
		for (int row : rows) {
			itemsToRemove.add(rowObjectModel.getRowObject(row));
		}

		removeRowObjects(model, itemsToRemove);

		// put some selection back
		int restoreRow = rows[0];
		selectRow(model, restoreRow);
	}

	@SuppressWarnings("unchecked")
	protected void removeRowObjects(TableModel model, List<Object> itemsToRemove) {

		if (!(model instanceof ThreadedTableModel)) {
			throw new AssertException("This action cannot delete rows for the given table model." +
				"You can override this method to peform the delete action yourself.");
		}

		ThreadedTableModel<Object, Object> threadedModel =
			(ThreadedTableModel<Object, Object>) model;
		for (Object o : itemsToRemove) {
			threadedModel.removeObject(o);
		}
	}

	public boolean checkForBusy(TableModel model) {

		if (!(model instanceof ThreadedTableModel)) {
			return false;
		}

		ThreadedTableModel<?, ?> threadedModel = (ThreadedTableModel<?, ?>) model;
		if (threadedModel.isBusy()) {
			return true;
		}
		return false;
	}

	private void selectRow(TableModel model, final int row) {
		SwingUtilities.invokeLater(() -> {

			if (checkForBusy(model)) {
				// Selecting rows whilst the model is processing deletes will cause the
				// selection to be lost.  So, wait until the model settles down.
				GTimer.scheduleRunnable(500, () -> selectRow(model, row));
				return;
			}

			int rowCount = model.getRowCount();
			if (rowCount == 0) {
				return;
			}

			if (row < 0) {
				return; // this can happen during disposal
			}

			int selectRow = row;
			if (row >= rowCount) {
				selectRow = rowCount - 1;
			}

			table.setRowSelectionInterval(selectRow, selectRow);
		});
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private static class DummyDeleteAction extends DeleteTableRowAction {
		DummyDeleteAction(PluginTool tool) {
			super(tool);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			// stub
		}
	}
}
