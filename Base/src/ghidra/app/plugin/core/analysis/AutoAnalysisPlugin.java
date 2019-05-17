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
package ghidra.app.plugin.core.analysis;

import java.util.*;

import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.DockingWindowManager;
import docking.action.*;
import docking.widgets.dialogs.MultiLineMessageDialog;
import ghidra.GhidraOptions;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.app.events.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.Analyzer;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.TaskLauncher;

/**
 * AutoAnalysisPlugin
 * 
 * Provides support for auto analysis tasks. Manages a pipeline or priority of
 * tasks to run given some event has occurred.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Manages auto-analysis",
	description = "Provides coordination and a service for All Auto Analysis tasks.",
	eventsConsumed = { ProgramOpenedPluginEvent.class, ProgramClosedPluginEvent.class, ProgramActivatedPluginEvent.class }
)
//@formatter:on
public class AutoAnalysisPlugin extends Plugin implements AutoAnalysisManagerListener {

	private static final String SHOW_ANALYSIS_OPTIONS = "Show Analysis Options";

	private static final String ANALYZE_GROUP_NAME = "Analyze";

	private DockingAction autoAnalyzeAction;
	private DockingAction analyzeAllAction;

	private HelpLocation helpLocation;

	private List<Analyzer> analyzers = new ArrayList<>();
	private List<OneShotAnalyzerAction> oneShotActions = new ArrayList<>();

	/**
	 * Creates a new instance of the plugin giving it the tool that it will work
	 * in.
	 */
	public AutoAnalysisPlugin(PluginTool tool) {
		super(tool);

		findAnalyzers();
		createActions();

		// get the option so that an owner is associated with it, otherwise
		// it will not show up in the Options dialog for the tool.
		Options options = tool.getOptions(GhidraOptions.CATEGORY_AUTO_ANALYSIS);
		String description =
			"This option forces the analysis options"
				+ " dialog to appear whenever auto-analysis action is invoked.";

		helpLocation = new HelpLocation("AutoAnalysisPlugin", "AnalysisOptions");

		options.registerOption(SHOW_ANALYSIS_OPTIONS, true, helpLocation, description);
	}

	private void findAnalyzers() {
		analyzers.addAll(ClassSearcher.getInstances(Analyzer.class));

		// sort so that the menu items are always in the same order
		Collections.sort(analyzers, (o1, o2) -> o1.getName().compareTo(o2.getName()));
	}

	/**
	 * Creates actions for the plugin.
	 */
	private void createActions() {

		// use this index to make sure that the following actions are ordered in the way that 
		// they are inserted
		int subGroupIndex = 0;

		autoAnalyzeAction = new ListingContextAction("Auto Analyze", getName()) {
			@Override
			protected void actionPerformed(ListingActionContext programContext) {
				analyzeCallback(programContext.getProgram(), programContext.getSelection());
			}

			@Override
			public boolean isEnabledForContext(ListingActionContext context) {
				Program program = context.getProgram();
				getMenuBarData().setMenuItemName(
					"&Auto Analyze '" + program.getDomainFile().getName() + "'...");
				return true;
			}
		};
		String[] menuPath = { "&Analysis", "&Auto Analyze..." };
		MenuData menuData = new MenuData(menuPath, null, ANALYZE_GROUP_NAME);
		menuData.setMenuSubGroup("" + subGroupIndex++);
		autoAnalyzeAction.setMenuBarData(menuData);

		autoAnalyzeAction.setKeyBindingData(new KeyBindingData('A', 0));

		tool.addAction(autoAnalyzeAction);

		analyzeAllAction = new DockingAction("Analyze All Open", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				analyzeAllCallback();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return context.getContextObject() instanceof ListingActionContext;
			}
		};
		analyzeAllAction.setEnabled(false);
		menuData =
			new MenuData(new String[] { "&Analysis", "Analyze All &Open..." }, ANALYZE_GROUP_NAME);
		menuData.setMenuSubGroup("" + subGroupIndex++);
		analyzeAllAction.setMenuBarData(menuData);

		tool.addAction(analyzeAllAction);

		tool.setMenuGroup(new String[] { "Analysis", "One Shot" }, ANALYZE_GROUP_NAME);

	}

	private void addOneShotActions(Program program) {
		removeOneShotActions();
		for (Analyzer analyzer : analyzers) {
			if (analyzer.supportsOneTimeAnalysis()) {
				if (!analyzer.canAnalyze(program)) {
					continue;
				}
				OneShotAnalyzerAction action = new OneShotAnalyzerAction(analyzer);
				oneShotActions.add(action);
				tool.addAction(action);
			}
		}
	}

	private void removeOneShotActions() {
		for (OneShotAnalyzerAction action : oneShotActions) {
			tool.removeAction(action);
		}
		oneShotActions.clear();
	}

	private void analyzeAllCallback() {
		AnalyzeAllOpenProgramsTask task = new AnalyzeAllOpenProgramsTask(this);
		new TaskLauncher(task, tool.getToolFrame());
	}

	private void analyzeCallback(Program program, ProgramSelection selection) {
		AutoAnalysisManager analysisMgr = AutoAnalysisManager.getAnalysisManager(program);

		analysisMgr.initializeOptions(); // get initial options

		if (!showOptionsDialog(program)) {
			return;
		}

		analysisMgr.initializeOptions(); // options may have changed

		// start analysis to set the flag, but it probably won't do more.  A bit goofy but better
		// than the way it was
		//TODO simplify all this after creating a taskManager per program instead of per tool.
		tool.executeBackgroundCommand(new AnalysisBackgroundCommand(analysisMgr, true), program);

		// if has a selection use it
		// if no selection, use all of memory
		analysisMgr.reAnalyzeAll(selection);
	}

	/**
	 * Get the description of this plugin.
	 */
	public static String getDescription() {
		return "Provides coordination and a service for All Auto Analysis tasks";
	}

	/**
	 * Get the descriptive name.
	 */
	public static String getDescriptiveName() {
		return "AutoAnalysisManager";
	}

	/**
	 * Get the category.
	 */
	public static String getCategory() {
		return "Analysis";
	}

	/***************************************************************************
	 * Implementation of AutoAnalysis Service
	 */

	protected void programClosed(Program program) {

		if (AutoAnalysisManager.hasAutoAnalysisManager(program)) {
			AutoAnalysisManager analysisMgr = AutoAnalysisManager.getAnalysisManager(program);
			analysisMgr.removeTool(tool);
			analysisMgr.removeListener(this);
		}
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramClosedPluginEvent) {
			ProgramClosedPluginEvent ev = (ProgramClosedPluginEvent) event;
			programClosed(ev.getProgram());
		}
		else if (event instanceof ProgramOpenedPluginEvent) {
			ProgramOpenedPluginEvent ev = (ProgramOpenedPluginEvent) event;
			programOpened(ev.getProgram());
		}
		else if (event instanceof ProgramActivatedPluginEvent) {
			ProgramActivatedPluginEvent ev = (ProgramActivatedPluginEvent) event;
			Program program = ev.getActiveProgram();
			if (program == null) {
				removeOneShotActions();
			}
			else {
				programActivated(program);
				addOneShotActions(program);
			}
		}
	}

	protected void programOpened(final Program program) {
		final AutoAnalysisManager analysisMgr = AutoAnalysisManager.getAnalysisManager(program);
		analysisMgr.addTool(tool);
		analysisMgr.addListener(this);

		Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
		options.registerOptionsEditor(new AnalysisOptionsEditor(program));
		options.setOptionsHelpLocation(new HelpLocation("AutoAnalysisPlugin",
			"Auto_Analysis_Option"));
	}

	private void programActivated(final Program program) {

		// invokeLater() to ensure that all other plugins have been notified of the program
		// activated.  This makes sure plugins like the Listing have opened and painted the 
		// program.
		//
		// If the user decided to instantly close the code browser before we get to run anything,
		// an exception could be thrown! Therefore, we must check to see if the program is closed
		// at this point before we run anything.
		//
		SwingUtilities.invokeLater(() -> {
			if (program.isClosed()) {
				return;
			}
			final AutoAnalysisManager analysisMgr = AutoAnalysisManager.getAnalysisManager(program);
			if (analysisMgr.askToAnalyze(tool)) {
				analyzeCallback(program, null);
			}
		});
	}

	/**
	 * Show the options panel for the auto analysis options. 
	 */
	private boolean showOptionsDialog(Program program) {
		tool.clearStatusInfo();
		Options options = tool.getOptions(GhidraOptions.CATEGORY_AUTO_ANALYSIS);
		boolean showDialog = options.getBoolean(SHOW_ANALYSIS_OPTIONS, true);
		if (!showDialog) {
			return true;
		}
		int id = program.startTransaction("Analysis Options");
		try {
			AnalysisOptionsDialog dialog = new AnalysisOptionsDialog(program);
			tool.showDialog(dialog);
			return dialog.wasAnalyzeButtonSelected();
		}
		finally {
			program.endTransaction(id, true);
		}
	}

	@Override
	public void analysisEnded(AutoAnalysisManager manager) {
		MessageLog log = manager.getMessageLog();
		if (log.getMsgCount() > 0) {
			MultiLineMessageDialog dialog =
				new MultiLineMessageDialog("Auto Analysis Summary",
					"There were warnings/errors issued during analysis.", log.toString(),
				MultiLineMessageDialog.WARNING_MESSAGE, false);//modal?
			DockingWindowManager.showDialog(null, dialog);
		}
	}

	class OneShotAnalyzerAction extends ListingContextAction {
		private Analyzer analyzer;
		private Program canAnalyzeProgram;
		private boolean canAnalyze;

		public OneShotAnalyzerAction(Analyzer analyzer) {
			super(analyzer.getName(), AutoAnalysisPlugin.this.getName());
			this.analyzer = analyzer;
			setMenuBarData(new MenuData(
				new String[] { "Analysis", "One Shot", analyzer.getName() }, null,
				ANALYZE_GROUP_NAME));
			setHelpLocation(new HelpLocation("AutoAnalysisPlugin", "Auto_Analyzers"));

			setEnabled(false);
		}

		@Override
		public void actionPerformed(ListingActionContext programContext) {
			AddressSetView set;
			if (programContext.hasSelection()) {
				set = programContext.getSelection();
			}
			else {
				set = programContext.getProgram().getMemory();
			}

			AutoAnalysisManager analysisMgr =
				AutoAnalysisManager.getAnalysisManager(programContext.getProgram());

			Program program = programContext.getProgram();
			Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
			options = options.getOptions(analyzer.getName());
			analyzer.optionsChanged(options, program);

			analysisMgr.schedule(
				new OneShotAnalysisCommand(analyzer, set, analysisMgr.getMessageLog()),
				analyzer.getPriority().priority());

			tool.setStatusInfo("Analysis scheduled: " + analyzer.getName());
		}

		@Override
		protected boolean isEnabledForContext(ListingActionContext programContext) {
			Program p = programContext.getProgram();
			if (p != canAnalyzeProgram) {
				canAnalyzeProgram = p;
				canAnalyze = analyzer.canAnalyze(p);
			}
			return canAnalyze;
		}
	}
}
