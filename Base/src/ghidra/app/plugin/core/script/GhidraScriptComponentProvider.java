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

import java.awt.BorderLayout;
import java.awt.Rectangle;
import java.awt.event.*;
import java.io.*;
import java.util.*;

import javax.swing.*;
import javax.swing.table.*;
import javax.swing.text.html.HTMLEditorKit;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;

import docking.ActionContext;
import docking.action.KeyBindingData;
import docking.event.mouse.GMouseListenerAdapter;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.pathmanager.PathManager;
import docking.widgets.pathmanager.PathManagerListener;
import docking.widgets.table.*;
import docking.widgets.tree.*;
import docking.widgets.tree.support.BreadthFirstIterator;
import generic.jar.ResourceFile;
import generic.util.Path;
import ghidra.app.script.*;
import ghidra.app.services.ConsoleService;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.listing.Program;
import ghidra.util.*;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.task.*;
import resources.ResourceManager;
import utilities.util.FileUtilities;

public class GhidraScriptComponentProvider extends ComponentProviderAdapter {

	private static final double TOP_PREFERRED_RESIZE_WEIGHT = .80;
	private static final String DESCRIPTION_DIVIDER_LOCATION = "DESCRIPTION_DIVIDER_LOCATION";
	private static final String FILTER_TEXT = "FILTER_TEXT";

	static final String WINDOW_GROUP = "Script Group";

	private Map<ResourceFile, GhidraScriptEditorComponentProvider> editorMap = new HashMap<>();
	private GhidraScriptMgrPlugin plugin;
	private JPanel component;
	private RootNode scriptRoot;
	private GTree scriptCategoryTree;
	private DraggableScriptTable scriptTable;
	private GhidraScriptTableModel tableModel;
	private PathManager pathManager;
	private TaskListener taskListener = new ScriptTaskListener();
	private GhidraScriptActionManager actionManager;
	private GhidraTableFilterPanel<ResourceFile> tableFilterPanel;
	private JTextPane descriptionTextPane;
	private JSplitPane dataDescriptionSplit;
	private boolean hasBeenRefreshed = false;

	private TreePath previousPath;
	private String[] previousCategory;

	private ResourceFile lastRunScript;
	private WeakSet<RunScriptTask> runningScriptTaskSet =
		WeakDataStructureFactory.createCopyOnReadWeakSet();
	private TaskListener cleanupTaskSetListener = new TaskListener() {
		@Override
		public void taskCompleted(Task task) {
			runningScriptTaskSet.remove((RunScriptTask) task);
		}

		@Override
		public void taskCancelled(Task task) {
			runningScriptTaskSet.remove((RunScriptTask) task);
		}
	};

	GhidraScriptComponentProvider(GhidraScriptMgrPlugin plugin) {
		super(plugin.getTool(), "Script Manager", plugin.getName());
		this.plugin = plugin;

		setHelpLocation(new HelpLocation(plugin.getName(), plugin.getName()));
		setIcon(ResourceManager.loadImage("images/play.png"));
		setWindowGroup(WINDOW_GROUP);

		build();
		plugin.getTool().addComponentProvider(this, false);
		actionManager = new GhidraScriptActionManager(this, plugin);
		updateTitle();
	}

	void dispose() {

		editorMap.clear();
		scriptCategoryTree.dispose();
		scriptTable.dispose();
		tableFilterPanel.dispose();
		actionManager.dispose();
		pathManager.dispose();
	}

	GhidraScriptActionManager getActionManager() {
		return actionManager;
	}

	Map<ResourceFile, GhidraScriptEditorComponentProvider> getEditorMap() {
		return editorMap;
	}

	void pickPaths() {
		PickPathsDialog pd = new PickPathsDialog(getComponent(), pathManager);
		pd.setHelpLocation(actionManager.getPathHelpLocation());
		pd.show();
		if (pd.hasChanged()) {
			plugin.getTool().setConfigChanged(true);

			// Note: do this here, instead of performRefresh() below, as we don't want
			// initialization refreshes to trigger excessive updating.  Presumably, the
			// system is in a good state after default initialization.  However, when the *user*
			// changes the paths, that is a signal to refresh after we have already initialized.
			GhidraScriptUtil.refreshRequested();

			performRefresh();
		}
	}

	private void performRefresh() {

		GhidraScriptUtil.setScriptDirectories(pathManager.getPaths());
		GhidraScriptUtil.clean();
		refresh();
	}

	void assignKeyBinding() {
		ResourceFile script = getSelectedScript();
		ScriptAction action = actionManager.createAction(script);

		KeyBindingInputDialog dialog = new KeyBindingInputDialog(getComponent(), script.getName(),
			action.getKeyBinding(), plugin, actionManager.getKeyBindingHelpLocation());
		if (dialog.isCancelled()) {
			plugin.getTool().setStatusInfo("User cancelled keybinding.");
			return;
		}
		action.setKeyBindingData(new KeyBindingData(dialog.getKeyStroke()));
		scriptTable.repaint();
	}

	void renameScript() {
		ResourceFile script = getSelectedScript();
		ResourceFile directory = script.getParentFile();
		Path path = GhidraScriptUtil.getScriptPath(directory);
		if (path == null || path.isReadOnly()) {
			Msg.showWarn(getClass(), getComponent(), getName(),
				"Unable to rename scripts in '" + directory + "'.");
			return;
		}
		if (isEditorOpen(script)) {
			Msg.showWarn(getClass(), getComponent(), "Unable to rename script",
				"The script is open for editing.\nPlease close the script and try again.");
			return;
		}

		GhidraScriptProvider provider = GhidraScriptUtil.getProvider(script);
		SaveDialog dialog = new SaveDialog(getComponent(), "Rename Script", this, script,
			actionManager.getRenameHelpLocation());
		if (dialog.isCancelled()) {
			plugin.getTool().setStatusInfo("User cancelled rename.");
			return;
		}

		ResourceFile renameFile = dialog.getFile();
		if (renameFile == null) {
			return;
		}

		if (renameFile.exists()) {
			Msg.showWarn(getClass(), getComponent(), "Unable to rename script",
				"Destination file already exists.");
			return;
		}

		checkNewScriptDirectoryEnablement(renameFile);

		renameScriptByCopying(script, provider, renameFile);
	}

	private void renameScriptByCopying(ResourceFile script, GhidraScriptProvider provider,
			ResourceFile renameFile) {
		String oldClassName = GhidraScriptUtil.getBaseName(script);
		String newClassName = GhidraScriptUtil.getBaseName(renameFile);

		ResourceFile temp = null;
		PrintWriter writer = null;
		BufferedReader reader = null;
		try {

			ResourceFile parentFile = script.getParentFile();
			temp = new ResourceFile(parentFile, "ghidraScript.tmp");
			writer = new PrintWriter(temp.getOutputStream());
			reader = new BufferedReader(new InputStreamReader(script.getInputStream()));
			while (true) {
				String line = reader.readLine();
				if (line == null) {
					break;
				}
				writer.println(line.replaceAll(oldClassName, newClassName));
			}
			reader.close();
			writer.close();

			FileUtilities.copyFile(temp, renameFile, TaskMonitorAdapter.DUMMY_MONITOR);

			if (!renameFile.exists()) {
				Msg.showWarn(getClass(), getComponent(), "Unable to rename script",
					"The rename operation failed.\nPlease check file permissions.");
				return;
			}

			if (!provider.deleteScript(script)) {
				Msg.showWarn(getClass(), getComponent(), "Unable to rename script",
					"Unable to remove original file.\nPlease check file permissions.");
				renameFile.delete();
				return;
			}
			if (actionManager.hasScriptAction(script)) {
				KeyStroke ks = actionManager.getKeyBinding(script);
				actionManager.removeAction(script);
				ScriptAction action = actionManager.createAction(renameFile);
				action.setKeyBindingData(new KeyBindingData(ks));
			}

			tableModel.switchScript(script, renameFile);
			setSelectedScript(renameFile);
		}
		catch (IOException e) {
			Msg.showError(getClass(), getComponent(), "Unable to rename script", e.getMessage());
			return;
		}
		finally {
			if (reader != null) {
				try {
					reader.close();
				}
				catch (IOException e) {
					// we tried
				}
			}

			if (writer != null) {
				writer.close();
			}

			if (temp != null) {
				temp.delete();
			}
		}
	}

	TableModel getTableModel() {
		return tableModel;
	}

	JTable getTable() {
		return scriptTable;
	}

	int getScriptIndex(ResourceFile scriptFile) {
		return tableFilterPanel.getViewRow(tableModel.getScriptIndex(scriptFile));
	}

	ResourceFile getScriptAt(int rowIndex) {
		return tableModel.getScriptAt(tableFilterPanel.getModelRow(rowIndex));
	}

	boolean isEditorOpen(ResourceFile script) {
		GhidraScriptEditorComponentProvider editor = editorMap.get(script);
		return editor != null && plugin.getTool().isVisible(editor);
	}

	void deleteScript() {
		ResourceFile script = getSelectedScript();
		if (script == null) {
			return;
		}
		ResourceFile directory = script.getParentFile();

		Path path = GhidraScriptUtil.getScriptPath(directory);
		if (path == null || path.isReadOnly()) {
			Msg.showWarn(getClass(), getComponent(), getName(),
				"Unable to delete scripts in '" + directory + "'.");
			return;
		}

		int result = OptionDialog.showYesNoDialog(getComponent(), getName(),
			"Are you sure you want to delete script '" + script.getName() + "'?");
		if (result == OptionDialog.OPTION_ONE) {
			if (removeScript(script)) {
				GhidraScriptProvider provider = GhidraScriptUtil.getProvider(script);
				if (provider.deleteScript(script)) {
					restoreSelection(script);
				}
				else {
					Msg.showInfo(getClass(), getComponent(), getName(),
						"Unable to delete script '" + script.getName() + "'" + "\n" +
							"Please verify the file permissions.");
				}
			}
		}
	}

	private void restoreSelection(ResourceFile script) {
		int selectedRow = scriptTable.getSelectedRow();
		if (selectedRow < 0) {
			return;
		}

		int selectedModelRow = getModelRowForViewRow(selectedRow);
		if (tableModel.contains(selectedModelRow)) {
			scriptTable.setRowSelectionInterval(selectedRow, selectedRow);
			return;
		}

		if (tableModel.contains(selectedModelRow - 1)) {
			int viewRow = getViewRowForModelRow(selectedModelRow - 1);
			scriptTable.setRowSelectionInterval(viewRow, viewRow);
		}
	}

	public List<Path> getScriptDirectories() {
		return pathManager.getPaths();
	}

	public void checkNewScriptDirectoryEnablement(ResourceFile scriptFile) {
		if (pathManager.addPath(scriptFile.getParentFile(), true)) {
			Msg.showInfo(this, getComponent(), "Script Path Added/Enabled",
				"The directory containing the new script has been automatically enabled for use:\n" +
					scriptFile.getParentFile().getAbsolutePath());
		}
	}

	void newScript() {
		try {
			PickProviderDialog providerDialog =
				new PickProviderDialog(getComponent(), actionManager.getNewHelpLocation());
			GhidraScriptProvider provider = providerDialog.getSelectedProvider();
			if (provider == null) {
				plugin.getTool().setStatusInfo("User cancelled creating a new script.");
				return;
			}

			ResourceFile newFile = GhidraScriptUtil.createNewScript(provider,
				new ResourceFile(GhidraScriptUtil.USER_SCRIPTS_DIR), getScriptDirectories());
			SaveDialog dialog = new SaveNewScriptDialog(getComponent(), "New Script", this, newFile,
				actionManager.getNewHelpLocation());
			if (dialog.isCancelled()) {
				plugin.getTool().setStatusInfo("User cancelled creating a new script.");
				return;
			}
			newFile = dialog.getFile();

			checkNewScriptDirectoryEnablement(newFile);

			String category = StringUtilities.convertStringArray(getSelectedCategoryPath(),
				ScriptInfo.DELIMITTER);
			provider.createNewScript(newFile, category);

			GhidraScriptEditorComponentProvider editor =
				new GhidraScriptEditorComponentProvider(plugin, this, newFile);
			editorMap.put(newFile, editor);

			tableModel.insertScript(newFile);
			int index = getScriptIndex(newFile);

			if (index >= 0) {
				scriptTable.setRowSelectionInterval(index, index);
				Rectangle rect = scriptTable.getCellRect(index, 0, true);
				scriptTable.scrollRectToVisible(rect);
			}
		}
		catch (IOException e) {
			Msg.showError(this, getComponent(), getName(), e.getMessage(), e);
		}
	}

	void runScript(String scriptName, TaskListener listener) {
		List<Path> dirPaths = pathManager.getPaths();
		for (Path dir : dirPaths) {
			ResourceFile scriptSource = new ResourceFile(dir.getPath(), scriptName);
			if (scriptSource.exists()) {
				runScript(scriptSource, listener);
				return;
			}
		}
		throw new IllegalArgumentException("Script does not exist: " + scriptName);
	}

	void runScript(ResourceFile scriptFile) {
		runScript(scriptFile, taskListener);
	}

	void runScript(ResourceFile scriptFile, TaskListener listener) {
		lastRunScript = scriptFile;

		ConsoleService console = plugin.getConsoleService();
		GhidraScript script = getScriptInstance(scriptFile, console);
		if (script == null) {
			return;
		}

		RunScriptTask task =
			new RunScriptTask(scriptFile, script, plugin.getCurrentState(), console);
		runningScriptTaskSet.add(task);
		task.addTaskListener(listener);
		task.addTaskListener(cleanupTaskSetListener);
		new TaskLauncher(task, plugin.getTool().getToolFrame());
		tool.contextChanged(this); // some actions change after we run a script
		actionManager.notifyScriptWasRun();
	}

	private GhidraScript getScriptInstance(ResourceFile scriptFile, ConsoleService console) {
		String scriptName = scriptFile.getName();
		GhidraScriptProvider provider = GhidraScriptUtil.getProvider(scriptFile);
		try {
			return provider.getScriptInstance(scriptFile, console.getStdErr());
		}
		catch (IllegalAccessException e) {
			console.addErrorMessage("", "Unable to access script: " + scriptName);
		}
		catch (InstantiationException e) {
			console.addErrorMessage("", "Unable to instantiate script: " + scriptName);
		}
		catch (ClassNotFoundException e) {
			console.addErrorMessage("", "Unable to locate script class: " + e.getMessage());
		}

		// show the error icon
		scriptTable.repaint();
		return null;
	}

	void runScript() {
		ResourceFile script = getSelectedScript();
		if (script != null) {
			runScript(script);
		}
	}

	void runLastScript() {
		if (lastRunScript != null) {
			runScript(lastRunScript);
		}
	}

	ResourceFile getLastRunScript() {
		return lastRunScript;
	}

	void sortScripts() {
		tableModel.fireTableDataChanged();
	}

	/**
	 * is more than just root node selected?
	 */
	boolean isSelectedCategory() {
		TreePath path = scriptCategoryTree.getSelectionPath();
		return path != null && path.getPathCount() > 1;
	}

	String[] getSelectedCategoryPath() {
		TreePath currentPath = scriptCategoryTree.getSelectionPath();

		String[] currentCategory = null;

		if (currentPath != null) {
			if (currentPath.equals(previousPath)) {
				return previousCategory;
			}
			if (currentPath.getPathCount() > 1) {
				GTreeNode node = (GTreeNode) currentPath.getLastPathComponent();
				currentCategory = getCategoryPath(node);
			}
		}

		previousPath = currentPath;
		previousCategory = currentCategory;

		return currentCategory;
	}

	private String[] getCategoryPath(GTreeNode node) {
		TreePath treePath = node.getTreePath();
		Object[] path = treePath.getPath();
		String[] categoryPath = new String[path.length - 1];
		for (int i = 0; i < categoryPath.length; i++) {
			categoryPath[i] = ((GTreeNode) path[i + 1]).getName();
		}
		return categoryPath;
	}

	void refresh() {

		hasBeenRefreshed = true;

		TreePath preRefreshSelectionPath = scriptCategoryTree.getSelectionPath();

		updateAvailableScriptFilesForAllPaths();

		tableModel.fireTableDataChanged();

		updateTreeNodesToReflectAvailableScripts();

		scriptRoot.fireNodeStructureChanged(scriptRoot);
		if (preRefreshSelectionPath != null) {
			scriptCategoryTree.setSelectionPath(preRefreshSelectionPath);
		}
	}

	private void updateAvailableScriptFilesForAllPaths() {
		List<ResourceFile> scriptsToRemove = tableModel.getScripts();
		List<ResourceFile> scriptAccumulator = new ArrayList<>();
		List<Path> dirPaths = pathManager.getPaths();
		for (Path dirPath : dirPaths) {
			updateAvailableScriptFilesForDirectory(scriptsToRemove, scriptAccumulator,
				dirPath.getPath());
		}

		// note: do this after the loop to prevent a flurry of table model update events
		tableModel.insertScripts(scriptAccumulator);

		for (ResourceFile file : scriptsToRemove) {
			removeScript(file);
		}

		GhidraScriptUtil.refreshDuplicates();
		refreshActions();
	}

	private void updateAvailableScriptFilesForDirectory(List<ResourceFile> scriptsToRemove,
			List<ResourceFile> scriptAccumulator, ResourceFile directory) {
		ResourceFile[] files = directory.listFiles();
		if (files == null) {
			return;
		}

		for (ResourceFile scriptFile : files) {
			if (scriptFile.isFile() && GhidraScriptUtil.hasScriptProvider(scriptFile)) {
				if (getScriptIndex(scriptFile) == -1) {
					// note: we don't do this here, so we can prevent a flurry of table events
					// model.insertScript(element);
					scriptAccumulator.add(scriptFile);
				}
				scriptRoot.insert(scriptFile);
			}
			scriptsToRemove.remove(scriptFile);
		}

	}

	private void refreshActions() {
		List<ResourceFile> scripts = tableModel.getScripts();

		for (ResourceFile script : scripts) {
			// First get the ScriptInfo object and refresh, which will ensure any
			// info data (ie: script icons) will be reloaded.
			ScriptInfo info = GhidraScriptUtil.getScriptInfo(script);
			info.refresh();

			ScriptAction scriptAction = actionManager.get(script);
			if (scriptAction != null) {
				scriptAction.refresh();
			}
		}
	}

	private void updateTreeNodesToReflectAvailableScripts() {
		ArrayList<GTreeNode> nodesToRemove = new ArrayList<>();
		Iterator<GTreeNode> it = new BreadthFirstIterator(scriptCategoryTree, scriptRoot);
		while (it.hasNext()) {
			GTreeNode node = it.next();
			String[] category = getCategoryPath(node);
			Iterator<ScriptInfo> iter = GhidraScriptUtil.getScriptInfoIterator();
			boolean found = false;
			while (iter.hasNext()) {
				if (iter.next().isCategory(category)) {
					found = true;
					break;
				}
			}
			if (!found) {
				nodesToRemove.add(node);
			}
		}

		for (GTreeNode node : nodesToRemove) {
			GTreeNode parent = node.getParent();
			if (parent != null) {
				parent.removeNode(node);
			}
		}
	}

	GhidraScriptEditorComponentProvider getEditor() {
		ResourceFile script = getSelectedScript();
		return editorMap.get(script);
	}

	void editScriptBuiltin() {
		ResourceFile script = getSelectedScript();
		if (script == null) {
			plugin.getTool().setStatusInfo("Script is null.");
			return;
		}
		if (!script.exists()) {
			plugin.getTool().setStatusInfo(script.getName() + " does not exist.");
			return;
		}

		editScriptInGhidra(script);
	}

	void editScriptEclipse() {
		ResourceFile script = getSelectedScript();
		if (script == null) {
			plugin.getTool().setStatusInfo("Script is null.");
			return;
		}
		if (!script.exists()) {
			plugin.getTool().setStatusInfo(script.getName() + " does not exist.");
			return;
		}

		plugin.tryToEditFileInEclipse(script);
	}

	GhidraScriptEditorComponentProvider editScriptInGhidra(ResourceFile script) {
		GhidraScriptEditorComponentProvider editor = editorMap.get(script);
		if (editor == null) {
			try {
				editor = new GhidraScriptEditorComponentProvider(plugin, this, script);
				editorMap.put(script, editor);
				return editor;
			}
			catch (IOException e) {
				Msg.showError(this, getComponent(), "Error loading script", e.getMessage(), e);
				return null;
			}
		}
		plugin.getTool().showComponentProvider(editor, true);
		return editor;
	}

	void switchEditor(ResourceFile oldScript, ResourceFile newScript) {
		GhidraScriptEditorComponentProvider editor = editorMap.get(oldScript);
		editorMap.put(newScript, editor);
		editorMap.remove(oldScript);
		tableModel.insertScript(newScript);
	}

	boolean removeScript(ResourceFile script) {
		// Always remove the script from the table, as it is no longer on disk.  If the user
		// has it open in the editor, then they may choose to leave the editor open, but they
		// will have to save that file if they want to keep the changes.
		tableModel.removeScript(script);

		if (!removeScriptEditor(script, true)) {
			return false; // user cancelled the closing of a dirty editor
		}

		actionManager.removeAction(script);
		GhidraScriptUtil.unloadScript(script);
		return true;
	}

	boolean removeScriptEditor(ResourceFile script, boolean checkForSave) {
		GhidraScriptEditorComponentProvider editor = editorMap.get(script);
		if (editor == null) {
			return true;
		}

		if (checkForSave && editor.hasChanges()) {
			JComponent parentComponent = getComponent();
			if (plugin.getTool().isVisible(editor)) {
				parentComponent = editor.getComponent();
			}
			int result = OptionDialog.showYesNoDialog(parentComponent, getName(),
				"'" + script.getName() + "' has been modified. Discard changes?");
			if (result != OptionDialog.OPTION_ONE) {
				return false;
			}
		}

		plugin.getTool().removeComponentProvider(editor);
		editorMap.remove(script);
		return true;
	}

	private void build() {
		pathManager = new PathManager(GhidraScriptUtil.getDefaultScriptDirectories(), true, false);
		pathManager.setFileChooserProperties("Select Script Directory", "LastGhidraScriptDirectory",
			GhidraFileChooserMode.DIRECTORIES_ONLY, false, null);

		pathManager.addListener(new PathManagerListener() {
			@Override
			public void pathsChanged() {
				if (isVisible()) { // we will be refreshed when first shown
					performRefresh();
				}
			}

			@Override
			public void pathMessage(String message) {
				// don't care
			}
		});

		scriptRoot = new RootNode();

		scriptCategoryTree = new GTree(scriptRoot);
		scriptCategoryTree.setName("CATEGORY_TREE");
		scriptCategoryTree.addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				maybeSelect(e);
			}

			@Override
			public void mouseReleased(MouseEvent e) {
				maybeSelect(e);
			}

			private void maybeSelect(MouseEvent e) {
				if (e.isPopupTrigger()) {
					TreePath path = scriptCategoryTree.getPathForLocation(e.getX(), e.getY());
					scriptCategoryTree.setSelectionPath(path);
				}
			}
		});
		scriptCategoryTree.addGTreeSelectionListener(e -> {
			tableModel.fireTableDataChanged(); // trigger a refilter
			TreePath path = e.getPath();
			if (path != null) {
				scriptCategoryTree.expandPath(path);
			}
		});

		scriptCategoryTree.getSelectionModel().setSelectionMode(
			TreeSelectionModel.SINGLE_TREE_SELECTION);

		tableModel = new GhidraScriptTableModel(this);

		scriptTable = new DraggableScriptTable(this);
		scriptTable.setName("SCRIPT_TABLE");
		scriptTable.setAutoLookupColumn(tableModel.getNameColumnIndex());
		scriptTable.setRowSelectionAllowed(true);
		scriptTable.setAutoCreateColumnsFromModel(false);
		scriptTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		scriptTable.getSelectionModel().addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}
			tool.contextChanged(GhidraScriptComponentProvider.this);
			updateDescriptionPanel();
		});
		tableModel.addTableModelListener(e -> updateTitle());

		scriptTable.addMouseListener(new GMouseListenerAdapter() {
			@Override
			public void popupTriggered(MouseEvent e) {
				int displayRow = scriptTable.rowAtPoint(e.getPoint());
				if (displayRow >= 0) {
					scriptTable.setRowSelectionInterval(displayRow, displayRow);
				}
			}

			@Override
			public void doubleClickTriggered(MouseEvent e) {
				runScript();
			}
		});

		TableColumnModel columnModel = scriptTable.getColumnModel();
		// Set default column sizes
		for (int i = 0; i < columnModel.getColumnCount(); i++) {
			TableColumn column = columnModel.getColumn(i);
			String name = (String) column.getHeaderValue();
			switch (name) {
				case GhidraScriptTableModel.SCRIPT_ACTION_COLUMN_NAME:
					initializeUnresizableColumn(column, 50);
					break;
				case GhidraScriptTableModel.SCRIPT_STATUS_COLUMN_NAME:
					initializeUnresizableColumn(column, 50);
					break;
			}
		}

		JScrollPane scriptTableScroll = new JScrollPane(scriptTable);
		buildFilter();

		JPanel tablePanel = new JPanel(new BorderLayout());
		tablePanel.add(scriptTableScroll, BorderLayout.CENTER);
		tablePanel.add(tableFilterPanel, BorderLayout.SOUTH);

		JSplitPane treeTableSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
		treeTableSplit.setLeftComponent(scriptCategoryTree);
		treeTableSplit.setRightComponent(tablePanel);
		treeTableSplit.setDividerLocation(150);

		JComponent descriptionPanel = buildDescriptionComponent();

		dataDescriptionSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
		dataDescriptionSplit.setResizeWeight(TOP_PREFERRED_RESIZE_WEIGHT);
		dataDescriptionSplit.setName("dataDescriptionSplit");
		dataDescriptionSplit.setTopComponent(treeTableSplit);
		dataDescriptionSplit.setBottomComponent(descriptionPanel);

		component = new JPanel(new BorderLayout());
		component.add(dataDescriptionSplit, BorderLayout.CENTER);
	}

	private void initializeUnresizableColumn(TableColumn column, int width) {
		column.setPreferredWidth(width);
		column.setMinWidth(width);
		column.setMaxWidth(width);
		column.setResizable(false);
	}

	private void updateTitle() {
		StringBuilder buffy = new StringBuilder();
		int currentRowCount = tableFilterPanel.getRowCount();
		buffy.append(currentRowCount).append(" scripts ");
		if (tableFilterPanel.isFiltered()) {
			int unfilteredRowCount = tableFilterPanel.getUnfilteredRowCount();
			buffy.append(" (of ").append(unfilteredRowCount).append(')');
		}

		setSubTitle(buffy.toString());
	}

	void scriptUpdated(ResourceFile script) {
		ResourceFile selectedScript = getSelectedScript();
		if (selectedScript == null) {
			return; // no script selected, nothing to do
		}

		if (!selectedScript.equals(script)) {
			return; // the updated script is not the selected script, nothing to do
		}

		// the selected script has been changed, update the description panel
		updateDescriptionPanel();
		updateCategoryTree(script);
	}

	private void updateCategoryTree(ResourceFile script) {
		scriptRoot.insert(script);
		updateTreeNodesToReflectAvailableScripts();
	}

	private void buildFilter() {
		tableFilterPanel = new GhidraTableFilterPanel<>(scriptTable, tableModel);
		tableFilterPanel.setSecondaryFilter(new ScriptTableSecondaryFilter());
		tableFilterPanel.setFilterRowTransformer(new RowFilterTransformer<ResourceFile>() {
			List<String> list = new ArrayList<>();

			@Override
			public List<String> transform(ResourceFile script) {
				ScriptInfo info = GhidraScriptUtil.getScriptInfo(script);
				list.clear();
				list.add(info.getName());
				list.add(info.getDescription());
				return list;
			}
		});
		tableFilterPanel.setToolTipText("<HTML>Include scripts with <b>Names</b> or " +
			"<b>Descriptions</b> containing this text.");
		tableFilterPanel.setFocusComponent(scriptCategoryTree);
	}

	private JComponent buildDescriptionComponent() {
		JPanel descriptionPanel = new JPanel(new BorderLayout());
		descriptionTextPane = new JTextPane();
		descriptionTextPane.setEditable(false);
		descriptionTextPane.setEditorKit(new HTMLEditorKit());
		descriptionPanel.add(descriptionTextPane);
		JScrollPane scrollPane = new JScrollPane(descriptionPanel);

		// since we use HTML, the default scroll amount is not correct (the line size in HTML is
		// larger than the default text line size)
		int newScrollIncrement = 5;
		JScrollBar verticalScrollBar = scrollPane.getVerticalScrollBar();
		verticalScrollBar.setUnitIncrement(newScrollIncrement);
		JScrollBar horizontalScrollBar = scrollPane.getHorizontalScrollBar();
		horizontalScrollBar.setUnitIncrement(newScrollIncrement);
		return scrollPane;
	}

	private void updateDescriptionPanel() {
		descriptionTextPane.setText("");
		ResourceFile script = getSelectedScript();
		if (script == null) {
			return;
		}

		ScriptInfo info = GhidraScriptUtil.getScriptInfo(script);
		if (info != null) {
			descriptionTextPane.setText(info.getToolTipText());

			// have to do an invokeLater here, since the DefaultCaret class runs in an invokeLater,
			// which will overwrite our location setting
			SwingUtilities.invokeLater(() -> descriptionTextPane.setCaretPosition(0));
		}
	}

	private int getModelRowForViewRow(int viewRow) {
		int rowCount = tableModel.getRowCount();
		if (rowCount == 0) {
			// this method can be called after a delete, with an index that is no longer valid
			return -1;
		}
		return tableFilterPanel.getModelRow(viewRow);
	}

	private int getViewRowForModelRow(int modelRow) {
		return tableFilterPanel.getViewRow(modelRow);
	}

	ResourceFile getSelectedScript() {
		int row = scriptTable.getSelectedRow();
		if (row < 0) {
			return null;
		}
		int modelRow = tableFilterPanel.getModelRow(row);
		return tableModel.getScriptAt(modelRow);
	}

	void setSelectedScript(ResourceFile script) {
		if (script == null) {
			return;
		}

		int scriptIndex = tableModel.getScriptIndex(script);

		int viewRow = tableFilterPanel.getViewRow(scriptIndex);

		if (viewRow == -1) {
			return;
		}

		scriptTable.setRowSelectionInterval(viewRow, viewRow);

		// make sure the script row is in the view (but don't scroll the x coordinate)
		Rectangle visibleRect = scriptTable.getVisibleRect();
		Rectangle cellRect = scriptTable.getCellRect(viewRow, 0, true);
		cellRect.width = 0;
		cellRect.x = visibleRect.x;
		if (visibleRect.contains(cellRect)) {
			return; // already in view
		}

		scriptTable.scrollRectToVisible(cellRect);
	}

	TaskListener getTaskListener() {
		return taskListener;
	}

	private class ScriptTaskListener implements TaskListener {
		@Override
		public void taskCancelled(Task task) {
			taskCompleted(task);
		}

		@Override
		public void taskCompleted(Task task) {
			Rectangle visibleRect = scriptTable.getVisibleRect();
			scriptTable.repaint(visibleRect);
		}
	}

	public void readConfigState(SaveState saveState) {
		pathManager.restoreState(saveState);

		// pull in the just-loaded paths
		List<Path> paths = pathManager.getPaths();
		GhidraScriptUtil.setScriptDirectories(paths);
		actionManager.restoreUserDefinedKeybindings(saveState);
		actionManager.restoreScriptsThatAreInTool(saveState);

		final int descriptionDividerLocation = saveState.getInt(DESCRIPTION_DIVIDER_LOCATION, 0);
		if (descriptionDividerLocation > 0) {

			ComponentListener listener = new ComponentAdapter() {
				@Override
				public void componentResized(ComponentEvent e) {
					dataDescriptionSplit.setResizeWeight(TOP_PREFERRED_RESIZE_WEIGHT); // give the top pane the most space
				}
			};
			component.addComponentListener(listener);

			dataDescriptionSplit.setDividerLocation(descriptionDividerLocation);
		}

		String filterText = saveState.getString(FILTER_TEXT, "");
		tableFilterPanel.setFilterText(filterText);
	}

	public void writeConfigState(SaveState saveState) {
		pathManager.saveState(saveState);
		actionManager.saveUserDefinedKeybindings(saveState);
		actionManager.saveScriptsThatAreInTool(saveState);

		int dividerLocation = dataDescriptionSplit.getDividerLocation();
		if (dividerLocation > 0) {
			saveState.putInt(DESCRIPTION_DIVIDER_LOCATION, dividerLocation);
		}

		String filterText = tableFilterPanel.getFilterText();
		saveState.putString(FILTER_TEXT, filterText);
	}

	/********************************************************************/

	@Override
	public void componentShown() {
		if (!hasBeenRefreshed) {
			performRefresh();
		}
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		Object source = scriptTable;
		if (event != null) {
			source = event.getSource();
			if (source instanceof JViewport) {
				JViewport viewport = (JViewport) source;
				source = viewport.getView();
			}
			if (!(source instanceof GTable)) {
				return null; // clicked somewhere not in the table
			}
		}

		int[] selectedRows = scriptTable.getSelectedRows();
		if (selectedRows.length != 1) {
			return new ActionContext(this, scriptTable); // can only work on one selection at a time
		}

		ResourceFile script = tableModel.getRowObject(selectedRows[0]);
		return new ActionContext(this, script, scriptTable);
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	void programClosed(Program program) {
		for (RunScriptTask scriptTask : runningScriptTaskSet) {
			if (program == scriptTask.getProgram()) {
				scriptTask.cancel();
			}
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	/** Table filter that uses the state of the tree to further filter */
	private class ScriptTableSecondaryFilter implements TableFilter<ResourceFile> {

		@Override
		public boolean acceptsRow(ResourceFile script) {
			ScriptInfo info = GhidraScriptUtil.getScriptInfo(script);
			String[] category = getSelectedCategoryPath();

			if (category == null) { // root node
				return matchesRootNode(info);
			}

			// matches the category?
			boolean isMatch = info.isCategory(category);
			return isMatch;
		}

		private boolean matchesRootNode(ScriptInfo info) {
			if (!scriptCategoryTree.isFiltered()) {
				return true; // without a filter, everything matches the root node
			}

			// with a filter, only things in the available children match the root node (this is
			// so filtering in the tree will show all matching results when the
			// root is selected, instead of all results).
			GTreeRootNode rootNode = scriptCategoryTree.getRootNode();
			List<GTreeNode> children = rootNode.getChildren();
			for (GTreeNode node : children) {
				String[] path = getCategoryPath(node);
				if (info.isCategory(path)) {
					return true;
				}
			}
			return false;
		}

		@Override
		public boolean isSubFilterOf(TableFilter<?> tableFilter) {
			// For now the user does not have a way to change this filter, which means it will
			// never be a sub-filter of anything.
			return false;
		}
	}

}
