package dreamcastloader;

import java.awt.Component;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;

import javax.swing.JComboBox;

import ghidra.app.util.Option;
import ghidra.app.util.opinion.Loader;

public class SystemFlavorOption extends Option {
	private String selected;
	private String[] items = new String[] {
			"Dreamcast",
			"Atomiswave",
			"Naomi"
	};
	
	private JComboBox<String> editor = new JComboBox<>(items);

	public SystemFlavorOption(String name, Object value) {
		super(name, SystemFlavorOption.class, value, Loader.COMMAND_LINE_ARG_PREFIX + "-flavor", null);

		selected = value == null ? items[0] : value.toString();
		editor.setSelectedItem(selected);
		
		editor.addItemListener(new ItemListener() {

			@Override
			public void itemStateChanged(ItemEvent e) {
				if (e.getStateChange() == ItemEvent.SELECTED) {
						selected = (String)e.getItem();
						SystemFlavorOption.super.setValue(selected);
			       }
			}
			
		});

		editor.setEditable(false);
	}

	@Override
	public Component getCustomEditorComponent() {
		return editor;
	}

	@Override
	public Option copy() {
		return new SystemFlavorOption(getName(), getValue());
	}

	@Override
	public Object getValue() {
		return selected;
	}

	@Override
	public void setValue(Object object) {
		selected = object == null ? items[0] : object.toString();
	}

	@Override
	public Class<?> getValueClass() {
		return String.class;
	}
}
