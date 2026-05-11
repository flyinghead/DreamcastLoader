package dreamcastloader;

import java.awt.Component;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;

import javax.swing.JComboBox;

import ghidra.app.util.AddressFactoryService;
import ghidra.app.util.importer.options.StringOption;
import ghidra.app.util.opinion.Loader;

public class RAMBaseOption extends StringOption {
	private String selected;
	private String[] items = new String[] {
			"0x8C000000",
			"0x0C000000",
	};
	
	private JComboBox<String> editor = new JComboBox<>(items);

	public RAMBaseOption(String name, long value) {
		this(name, value == 0x0c000000 ? "0x0C000000" : "0x" + Long.toHexString(value));
	}

	public RAMBaseOption(String name, String value) {
		super(name, value, Loader.COMMAND_LINE_ARG_PREFIX + "-ramStart", null, 
				"ramBase", false, "The base address of RAM used by this program");
		
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
	public Component getCustomEditorComponent(AddressFactoryService addressFactoryService) {
		return editor;
	}

	@Override
	public void setValue(Object object) {
		selected = object == null ? items[0] : object.toString();
	}
}
