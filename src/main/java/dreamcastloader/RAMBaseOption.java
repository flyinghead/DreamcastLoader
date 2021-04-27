package dreamcastloader;

import java.awt.Component;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;

import javax.swing.JComboBox;

import ghidra.app.util.Option;
import ghidra.app.util.opinion.Loader;

public class RAMBaseOption extends Option {
	private String selected;
	private String[] items = new String[] {
			"0x8C000000",
			"0x0C000000",
	};
	
	private JComboBox<String> editor = new JComboBox<>(items);

	public RAMBaseOption(String name, Object value) {
		super(name, RAMBaseOption.class, value, Loader.COMMAND_LINE_ARG_PREFIX + "-ramStart", null);
		
		selected = value == null ? items[0] : value.toString();
		editor.setSelectedItem(selected);
		
		editor.addItemListener(new ItemListener() {

			@Override
			public void itemStateChanged(ItemEvent e) {
				if (e.getStateChange() == ItemEvent.SELECTED) {
						selected = (String)e.getItem();
						RAMBaseOption.super.setValue(selected);
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
		return new RAMBaseOption(getName(), getValue());
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
