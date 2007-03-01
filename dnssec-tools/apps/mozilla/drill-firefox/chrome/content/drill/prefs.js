var fields;


function chooseExecFile() {

	prefService = Components.classes["@mozilla.org/preferences-service;1"].
		getService(Components.interfaces.nsIPrefService);
	
	prefs = prefService.getBranch("extensions.drill.");

	pref_executable = prefs.getCharPref("drill_executable");

	var exec = Components.classes["@mozilla.org/file/local;1"].
		   createInstance(Components.interfaces.nsILocalFile);
	exec.initWithPath(pref_executable);

	var fp = Components.classes["@mozilla.org/filepicker;1"].
		getService(Components.interfaces.nsIFilePicker);

	if (exec.exists()) {
		fp.displayDirectory = exec.parent;
	}

	// use whatever nsIFilePicker options are suitable
	fp.init(window, "File to Read", fp.modeOpen);

	if ( fp.show() != fp.returnCancel ) {
		executable_field = document.getElementById("drill_prefs_executable");
		executable_field.value = fp.file.persistentDescriptor;
	}
}


function chooseKeydir() {

	prefService = Components.classes["@mozilla.org/preferences-service;1"].
		getService(Components.interfaces.nsIPrefService);
	
	prefs = prefService.getBranch("extensions.drill.");

	pref_executable = prefs.getCharPref("keydir");

	var current_dir = Components.classes["@mozilla.org/file/local;1"].
		   createInstance(Components.interfaces.nsILocalFile);
	current_dir.initWithPath(pref_executable);

	var fp = Components.classes["@mozilla.org/filepicker;1"].
		getService(Components.interfaces.nsIFilePicker);

	if (current_dir.exists()) {
		fp.displayDirectory = current_dir;
	}

	// use whatever nsIFilePicker options are suitable
	fp.init(window, "Choose directory", fp.modeGetFolder);

	if ( fp.show() != fp.returnCancel ) {
		keydir_field = document.getElementById("drill_prefs_keydir");
		keydir_field.value = fp.file.persistentDescriptor;
	}
}

function disable_drill(yes_no) {
	pref = document.getElementById("drill_prefs_executable_label");
	pref.disabled = yes_no;
	pref = document.getElementById("drill_prefs_executable");
	pref.disabled = yes_no;
	pref = document.getElementById("drill_prefs_executable_button");
	pref.disabled = yes_no;
	pref = document.getElementById("drill_prefs_keydir_label");
	pref.disabled = yes_no;
	pref = document.getElementById("drill_prefs_keydir");
	pref.disabled = yes_no;
	pref = document.getElementById("drill_prefs_keydir_button");
	pref.disabled = yes_no;
	pref = document.getElementById("drill_prefs_usenameserver");
	pref.disabled = yes_no;
	pref = document.getElementById("drill_prefs_nameserver");
	pref.disabled = yes_no;
	pref = document.getElementById("drill_prefs_debug");
	pref.disabled = yes_no;
}

function disable_libval(yes_no) {
	pref = document.getElementById("libval_prefs_executable_label");
	pref.disabled = yes_no;
	pref = document.getElementById("libval_prefs_executable");
	pref.disabled = yes_no;
}


function toggle_use() {
    prefService = Components.classes["@mozilla.org/preferences-service;1"].
        getService(Components.interfaces.nsIPrefService);
    prefs = prefService.getBranch("extensions.drill.");

    use_box = document.getElementById("validator_prefs_use");

    try {
    pref_use = use_box.selectedIndex;
    if (pref_use == 0) {
        disable_drill(false);
        prefs.setBoolPref("use_drill", true);
        disable_libval(true);
        prefs.setBoolPref("use_libval", false);
    } else if (pref_use == 1) {
        disable_drill(true);
        prefs.setBoolPref("use_drill", false);
        disable_libval(false);
        prefs.setBoolPref("use_libval", true);
    } else {
        disable_drill(true);
        prefs.setBoolPref("use_drill", false);
        disable_libval(true);
        prefs.setBoolPref("use_libval", false);
    }
    } catch(e) {
        alert(e);
    }
}

function toggle_nameserver() {
	prefService = Components.classes["@mozilla.org/preferences-service;1"].
		getService(Components.interfaces.nsIPrefService);
	
	prefs = prefService.getBranch("extensions.drill.");

	pref_usenameserver = prefs.getBoolPref("usenameserver");
	usenameserver_box = document.getElementById("drill_prefs_usenameserver");

	nameserver_field = document.getElementById("drill_prefs_nameserver");
	nameserver_field.disabled = usenameserver_box.checked;
}

function onLoad() {

	prefService = Components.classes["@mozilla.org/preferences-service;1"].
		getService(Components.interfaces.nsIPrefService);
	
	prefs = prefService.getBranch("extensions.drill.");

	/* read all preferences */
	pref_use = prefs.getBoolPref("use_drill");
	pref_executable = prefs.getCharPref("drill_executable");
	pref_usenameserver = prefs.getBoolPref("usenameserver");
	pref_nameserver = prefs.getCharPref("nameserver");
	pref_keydir = prefs.getCharPref("keydir");

	pref_chase = prefs.getBoolPref("chase");
	pref_debug = prefs.getBoolPref("debug");

	/* set them in the window */
	use_field = document.getElementById("drill_prefs_use");
	use_field.checked = pref_use;

	executable_field = document.getElementById("drill_prefs_executable");
	executable_field.value = pref_executable;

	usenameserver_box = document.getElementById("drill_prefs_usenameserver");
	usenameserver_box.checked = pref_usenameserver;

	nameserver_field = document.getElementById("drill_prefs_nameserver");
	nameserver_field.value = pref_nameserver;
	nameserver_field.disabled = !pref_usenameserver;

	keydir_field = document.getElementById("drill_prefs_keydir");
	keydir_field.value = pref_keydir;

	/*chase_box = document.getElementById("drill_prefs_chase");
	chase_box.checked = pref_chase;*/

	debug_box = document.getElementById("drill_prefs_debug");
	debug_box.checked = pref_debug;

	pref_use = prefs.getBoolPref("use_libval");
	use_field = document.getElementById("libval_prefs_use");
	use_field.checked = pref_use;
	pref_executable = prefs.getCharPref("libval_executable");
	executable_field = document.getElementById("libval_prefs_executable");
	executable_field.value = pref_executable;

    toggle_use();
}

function onClose() {

	prefService = Components.classes["@mozilla.org/preferences-service;1"].
		getService(Components.interfaces.nsIPrefService);
	
	prefs = prefService.getBranch("extensions.drill.");

	prefs.setCharPref("drill_executable", document.getElementById("drill_prefs_executable").value);
	prefs.setBoolPref("usenameserver", document.getElementById("drill_prefs_usenameserver").checked);
	prefs.setCharPref("nameserver", document.getElementById("drill_prefs_nameserver").value);
	prefs.setCharPref("keydir", document.getElementById("drill_prefs_keydir").value);
	/*prefs.setBoolPref("chase", document.getElementById("drill_prefs_chase").checked);*/
	prefs.setBoolPref("debug", document.getElementById("drill_prefs_debug").checked);

	prefs.setCharPref("libval_executable", document.getElementById("libval_prefs_executable").value);
	/* TODO: perform exists checks? */
}

