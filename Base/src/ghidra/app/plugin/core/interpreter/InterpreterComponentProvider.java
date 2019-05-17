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
package ghidra.app.plugin.core.interpreter;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.widgets.OptionDialog;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.generic.function.Callback;
import ghidra.util.HelpLocation;
import resources.Icons;
import resources.ResourceManager;

public class InterpreterComponentProvider extends ComponentProviderAdapter
		implements InterpreterConsole {
	private static final String CONSOLE_GIF = "images/monitor.png";
	private static final String CLEAR_GIF = "images/erase16.png";

	private InterpreterPanel panel;
	private InterpreterConnection interpreter;
	private ImageIcon icon;
	private List<Callback> firstActivationCallbacks;

	public InterpreterComponentProvider(InterpreterPanelPlugin plugin,
			InterpreterConnection interpreter, boolean visible) {
		super(plugin.getTool(), interpreter.getTitle(), plugin.getName());

		this.panel = new InterpreterPanel(plugin.getTool(), interpreter);
		this.interpreter = interpreter;
		this.firstActivationCallbacks = new ArrayList<>();

		setHelpLocation(new HelpLocation(getName(), "interpreter"));

		addToTool();
		createActions();

		icon = interpreter.getIcon();
		if (icon == null) {
			ResourceManager.loadImage(CONSOLE_GIF);
		}
		setIcon(icon);

		setVisible(visible);
	}

	private void createActions() {

		DockingAction clearAction = new DockingAction("Clear Interpreter", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				clear();
			}
		};
		clearAction.setDescription("Clear Interpreter");
		clearAction.setToolBarData(new ToolBarData(ResourceManager.loadImage(CLEAR_GIF), null));
		clearAction.setEnabled(true);

		addLocalAction(clearAction);
	}

	@Override
	public void addAction(DockingAction action) {
		addLocalAction(action);
	}

	/**
	 * Overridden so that we can add our custom actions for transient tools.
	 */
	@Override
	public void setTransient() {
		DockingAction disposeAction = new DockingAction("Remove Interpreter", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				int choice = OptionDialog.showYesNoDialog(panel, "Remove Interpreter?",
					"Are you sure you want to permanently close the interpreter?");
				if (choice == OptionDialog.NO_OPTION) {
					return;
				}

				InterpreterComponentProvider.this.dispose();
			}
		};
		disposeAction.setDescription("Remove interpreter from tool");
		disposeAction.setToolBarData(new ToolBarData(Icons.STOP_ICON, null));
		disposeAction.setEnabled(true);

		addLocalAction(disposeAction);
	}

	@Override
	public Icon getIcon() {
		return icon;
	}

	@Override
	public String getWindowSubMenuName() {
		return interpreter.getTitle();
	}

	@Override
	public String getTitle() {
		return interpreter.getTitle();
	}

	@Override
	public String getSubTitle() {
		return "Interpreter";
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	@Override
	public void clear() {
		panel.clear();
	}

	@Override
	public InputStream getStdin() {
		return panel.getStdin();
	}

	@Override
	public OutputStream getStdOut() {
		return panel.getStdOut();
	}

	@Override
	public OutputStream getStdErr() {
		return panel.getStdErr();
	}

	@Override
	public PrintWriter getOutWriter() {
		return panel.getOutWriter();
	}

	@Override
	public PrintWriter getErrWriter() {
		return panel.getErrWriter();
	}

	@Override
	public void setPrompt(String prompt) {
		panel.setPrompt(prompt);
	}

	@Override
	public void dispose() {
		removeFromTool();
		panel.dispose();
	}

	@Override
	public void componentActivated() {
		// Call the callbacks
		firstActivationCallbacks.forEach(l -> l.call());

		// Since we only care about the first activation, clear the list
		// of callbacks so future activations don't trigger anything.
		firstActivationCallbacks.clear();
	}

	@Override
	public void addFirstActivationCallback(Callback activationCallback) {
		firstActivationCallbacks.add(activationCallback);
	}
}
