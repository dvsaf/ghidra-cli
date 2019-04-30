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
package ghidra.app.plugin.core.symtable;

import java.awt.event.MouseEvent;
import java.util.List;

import javax.swing.ImageIcon;
import javax.swing.JComponent;

import docking.ActionContext;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.context.ProgramSymbolActionContext;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.util.SymbolInspector;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.table.GhidraTable;

class SymbolProvider extends ComponentProviderAdapter {
	private SymbolTablePlugin plugin;
	private SymbolRenderer renderer;
	private SymbolTableModel symbolKeyModel;
	private SymbolPanel symbolPanel;

	SymbolProvider(SymbolTablePlugin plugin) {
		super(plugin.getTool(), "Symbol Table", plugin.getName(), ProgramActionContext.class);
		this.plugin = plugin;
		setHelpLocation(new HelpLocation(plugin.getName(), "Symbol_Table"));
		setWindowGroup("symbolTable");
		renderer = new SymbolRenderer();

		symbolKeyModel = new SymbolTableModel(this, plugin.getTool());
		symbolPanel = new SymbolPanel(this, symbolKeyModel, renderer, plugin.getTool(),
			plugin.getGoToService());
	}

	void updateTitle() {
		setSubTitle(generateSubTitle());
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		Program program = plugin.getProgram();
		if (program == null) {
			return null;
		}
		List<SymbolRowObject> rowObjects = symbolPanel.getSelectedSymbolKeys();
		long[] symbolIDs = new long[rowObjects.size()];
		int index = 0;
		for (SymbolRowObject obj : rowObjects) {
			symbolIDs[index++] = obj.getKey();
		}
		return new ProgramSymbolActionContext(this, program, symbolIDs);
	}

	void deleteSymbols() {
		List<SymbolRowObject> rowObjects = symbolPanel.getSelectedSymbolKeys();
		symbolKeyModel.delete(rowObjects);
	}

	void makeSelection() {
		ProgramSelection selection = symbolPanel.getProgramSelection();
		PluginEvent event =
			new ProgramSelectionPluginEvent(plugin.getName(), selection, plugin.getProgram());
		plugin.firePluginEvent(event);
	}

	void setFilter() {
		symbolPanel.setFilter();
	}

	Symbol getCurrentSymbol() {
		List<SymbolRowObject> rowObjects = symbolPanel.getSelectedSymbolKeys();
		if (rowObjects != null && rowObjects.size() >= 1) {
			return symbolKeyModel.getSymbol(rowObjects.get(0).getKey());
		}
		return null;
	}

	void setCurrentSymbol(Symbol symbol) {
		plugin.getReferenceProvider().setCurrentSymbol(symbol);
	}

	Symbol getSymbol(long id) {
		return symbolKeyModel.getSymbol(id);
	}

	void dispose() {
		symbolKeyModel.dispose();
		symbolPanel.dispose();
		plugin = null;
	}

	void reload() {
		if (isVisible()) {
			symbolKeyModel.reload();
		}
	}

	void symbolAdded(Symbol s) {
		if (isVisible()) {
			symbolKeyModel.symbolAdded(s);
		}
	}

	void symbolRemoved(long symbolID) {
		if (isVisible()) {
			symbolKeyModel.symbolRemoved(symbolID);
		}
	}

	void symbolChanged(Symbol s) {
		if (isVisible()) {
			symbolKeyModel.symbolChanged(s);
		}
	}

	void setProgram(Program program, SymbolInspector inspector) {
		renderer.setSymbolInspector(inspector);
		if (isVisible()) {
			symbolKeyModel.reload(program);
		}
	}

	GhidraTable getTable() {
		return symbolPanel.getTable();
	}

	NewSymbolFilter getFilter() {
		return symbolPanel.getFilter();
	}

	private String generateSubTitle() {
		SymbolFilter filter = symbolKeyModel.getFilter();
		int rowCount = symbolKeyModel.getRowCount();
		int unfilteredCount = symbolKeyModel.getUnfilteredCount();

		if (rowCount != unfilteredCount) {
			return " (Text filter matched " + rowCount + " of " + unfilteredCount + " symbols)";
		}
		if (filter.acceptsAll()) {
			return "(" + symbolPanel.getActualSymbolCount() + " Symbols)";
		}
		return "(Filter settings matched " + symbolPanel.getActualSymbolCount() + " Symbols)";

	}

	@Override
	public ImageIcon getIcon() {
		return SymbolTablePlugin.SYM_GIF;
	}

	void open() {
		if (!isVisible()) {
			setVisible(true);
		}
	}

	@Override
	public void componentHidden() {
		symbolKeyModel.reload(null);
		if (plugin != null) {
			plugin.closeReferenceProvider();
		}
	}

	@Override
	public void componentShown() {
		symbolKeyModel.reload(plugin.getProgram());
	}

	@Override
	public JComponent getComponent() {
		return symbolPanel;
	}

	void readConfigState(SaveState saveState) {
		symbolPanel.readConfigState(saveState);
	}

	void writeConfigState(SaveState saveState) {
		symbolPanel.writeConfigState(saveState);
	}

}
