/* Special subroutines go here */

function doDrill() {

	var host = window._content.document.location.host;
	var image = document.getElementById("drill-status-image");
	
	if (host) {
		/* read the preferences */
		prefService = Components.classes["@mozilla.org/preferences-service;1"].
			getService(Components.interfaces.nsIPrefService);
		
		prefs = prefService.getBranch("extensions.drill.");

		var pref_use = prefs.getBoolPref("use_drill");
		if (pref_use) {
			var executable_name = prefs.getCharPref("drill_executable");
			var usenameserver = prefs.getBoolPref("usenameserver");
			var nameserver = prefs.getCharPref("nameserver");
			var keydir = prefs.getCharPref("keydir");
			/*var chase = prefs.getBoolPref("chase");*/
			var debug = prefs.getBoolPref("debug");

			if (debug) {
				/* turn on dump() for a while, keep pref to turn back at and of function */
				var dump_pref_orig = prefService.getBoolPref("browser.dom.window.dump.enabled");
				prefService.setBoolPref("browser.dom.window.dump.enabled", true);
			}

			/* read the keys */
			var keys = new Array();

			var dir = Components.classes["@mozilla.org/file/local;1"].
				  createInstance(Components.interfaces.nsILocalFile);
			dir.initWithPath(keydir);
			if (!dir.exists()) {
				alert("[drill] The specified key directory does not exist, please enter the correct directory in the preferences dialog.");
				return;
			}
			if (!dir.isDirectory()) {
				alert("[drill] The specified key directory is not a directory, please enter the correct directory in the preferences dialog.");
				return;
			}

			var keyfiles = dir.directoryEntries;
			while (keyfiles.hasMoreElements()) {
				var entry = keyfiles.getNext();
				entry.QueryInterface(Components.interfaces.nsIFile);
				/* do we have some endsWith() function? */
				if (entry.path.length > 4 &&
				    entry.path.charAt(entry.path.length - 4) == "." &&
				    entry.path.charAt(entry.path.length - 3) == "k" &&
				    entry.path.charAt(entry.path.length - 2) == "e" &&
				    entry.path.charAt(entry.path.length - 1) == "y"
				) {
					keys.push(entry.path);
				}
			}

			if (keys.length == 0) {
				image.src = "chrome://drill/skin/drill_icon_status.png";
				image.tooltipText = "no keys found in " + keydir;
			}

			/* run the command and update the icon */
			try {
				var exec = Components.classes["@mozilla.org/file/local;1"].
					   createInstance(Components.interfaces.nsILocalFile);
				var pr = Components.classes["@mozilla.org/process/util;1"].
					 createInstance(Components.interfaces.nsIProcess);

				exec.initWithPath(executable_name);
				var str = executable_name;

				var args = new Array();
				
				args.push("-S");

				if (!debug) {
					args.push("-Q");
				}

				for (i=0; i<keys.length; i++) {
					args.push("-k");
					args.push(keys[i]);
				}

				if (usenameserver) {
					args.push("@" + nameserver);
				}

				args.push(host);

				if (debug) {
					dump("\nCommand: "+str);
					dump("\nArguments:\n"+args);
					dump("\nOutput:\n");
				}

				if (!exec.exists()) {
					alert(exec.leafName + " not found, disabling extension for now");
					prefs.setBoolPref("use_drill", false);
				} else {
					pr.init(exec);
					pr.run(true, args, args.length);

					if (!image) {
						alert("error image");
					}

					if (pr.exitValue == 0) {
						image.src = "chrome://drill/skin/drill_verified.png";
						image.tooltipText = host + " is verified.";
					} else {
						image.src = "chrome://drill/skin/drill_notverified.png";
						image.tooltipText = host + " could not be verified.";
					}
				}

				if (debug) {
					prefService.setBoolPref("browser.dom.window.dump.enabled", dump_pref_orig);
				}
			} catch (e) {
				alert(e);
			}
		} else {
			image.src = "chrome://drill/skin/drill_icon_status.png";
			image.tooltipText = "Drill not enabled, click here";
		}
	} else {
		image.src = "chrome://drill/skin/drill_icon_status.png";
		image.tooltipText = "no hostname";
	}
}

function doLibvalValidate() {

	var host = window._content.document.location.host;
	var image = document.getElementById("drill-status-image");
	
	if (host) {
		/* read the preferences */
		prefService = Components.classes["@mozilla.org/preferences-service;1"].
			getService(Components.interfaces.nsIPrefService);
		
		prefs = prefService.getBranch("extensions.drill.");

		var pref_use = prefs.getBoolPref("use_libval");
		if (pref_use) {
			var executable_name = prefs.getCharPref("libval_executable");

			/* run the command and update the icon */
			try {
				var exec = Components.classes["@mozilla.org/file/local;1"].
					   createInstance(Components.interfaces.nsILocalFile);
				var pr = Components.classes["@mozilla.org/process/util;1"].
					 createInstance(Components.interfaces.nsIProcess);

				exec.initWithPath(executable_name);
				var str = executable_name;

				var args = new Array();
				
				args.push(host);

				if (!exec.exists()) {
					alert(exec.leafName + " not found, disabling extension for now");
					prefs.setBoolPref("use_libval", false);
				} else {
					pr.init(exec);
					pr.run(true, args, args.length);

					if (!image) {
						alert("error image");
					}
                    if ((pr.exitValue == 2)) {
                        image.src = "chrome://drill/skin/drill_verified.png";
                        image.tooltipText = host + " was VALIDATED";
                    } else if (pr.exitValue == 1) {
                        image.src = "chrome://drill/skin/drill_icon_status.png";
                        image.tooltipText = host + " was TRUSTED but NOT VALIDATED";
                    } else {
                        image.src = "chrome://drill/skin/drill_notverified.png";
                        image.tooltipText = host + " was NOT TRUSTED, and NOT VALIDATED";
                    }
				}
			} catch (e) {
				alert(e);
			}
		} else {
			image.src = "chrome://drill/skin/drill_icon_status.png";
			image.tooltipText = "libval not enabled, click here";
		}
	} else {
		image.src = "chrome://drill/skin/drill_icon_status.png";
		image.tooltipText = "no hostname";
	}
}

/* This part is run once, when the extension is loaded */

/* These function is called every time a page is loaded */

function drill_init() { 
	/* read the preferences */
	var image = document.getElementById("drill-status-image");
	prefService = Components.classes["@mozilla.org/preferences-service;1"].
			getService(Components.interfaces.nsIPrefService);
	prefs = prefService.getBranch("extensions.drill.");
    if (prefs.getBoolPref("use_libval")) {
        doLibvalValidate();
    } else if (prefs.getBoolPref("use_drill")) {
	    doDrill(); 
	} else {
		image.src = "chrome://drill/skin/drill_icon_status.png";
		image.tooltipText = "Drill not enabled, click here";
    }
}

/* These functions are called by the contextmenu, toolsmenu, or statusbar icon */

function drill_contextmenu_action() {
	alert("nothing here yet");
}

function drill_toolsmenu_action() {
	alert("nothing here yet");
}

function drill_statusbar_action() {
	window.openDialog("chrome://drill/content/prefs.xul");
}

