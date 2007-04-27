/* Special subroutines go here */

const ifs = Components.interfaces;

function doDnssecstatus() {

}

function doLibvalValidate() {

}

/* This part is run once, when the extension is loaded */

/* These function is called every time a page is loaded */

var counter = 0;

var valcount = 0;
var trustcount = 0;
var errcount = 0;

var counters = new Object();

function reset_all() {
    valcount = 0;
    trustcount = 0;
    errcount = 0;
    counters.vallist = {};
    counters.trustlist = {};
    counters.errlist = {};
}

function add_to_list(thelist, host) {
    if(thelist[host]) {
      thelist[host] = thelist[host] + 1;
    } else {
      thelist[host] = 1;
    }
}

function get_unique_string(thelist) {
    var tempstr = "";
    for (var i in thelist) {
          tempstr = tempstr + i + "(" + thelist[i] + ") ";
    }
    return tempstr;
}

function dnssecstatus_got_dnssec(topic, host) { 
    if (topic == "dnssec-status-both" || topic == "dnssec-status-validated") {
        valcount++;
        add_to_list(counters.vallist, host);
    }
    if (topic == "dnssec-status-trusted") {
        trustcount++;
        add_to_list(counters.trustlist, host);
    }
    if (topic == "dnssec-status-neither") {
        errcount++;
        add_to_list(counters.errlist, host);
    }
    // window._content.dnscount = window._content.dnscount + 1;
}

function set_status(name, label, value, thelist) {
    if (value == 0) {
        document.getElementById("dnssecstatus-" + name + "text").value = "";
        document.getElementById("dnssecstatus-" + name + "num").value = "";
    } else {
        var uniquestring = get_unique_string(thelist);
        document.getElementById("dnssecstatus-" + name + "text").value = 
            label;
        document.getElementById("dnssecstatus-" + name + "text").tooltipText = 
            uniquestring;
        document.getElementById("dnssecstatus-" + name + "num").value = value;
        document.getElementById("dnssecstatus-" + name + "num").tooltipText = 
            uniquestring;
    }
}    

function dnssecstatus_show() { 

/*
        var thewindow = window.opener;
        var docshell = thewindow.QueryInterface(Ci.nsIInterfaceRequestor)
            .getInterface(Ci.nsIWebNavigation)
            .QueryInterface(Ci.nsIDocShell);

	var docshell = document.getElementById("content");
*/
	var docshell = document.getElementById("content").webNavigation;

        var shells = 
            docshell.getDocShellEnumerator(ifs.nsIDocShellTreeItem.typeAll,
                                           ifs.nsIDocShell.ENUMERATE_FORWARDS);

        var docnum = 0;
        var doccounter = window._content.dnscount;
        while (shells.hasMoreElements())
            { 	         
                var shell = shells.getNext().QueryInterface(ifs.nsIDocShell);
                docnum++;
            }

        set_status("val", "Secure:", valcount, counters.vallist);
        set_status("trust", "Insecure:", trustcount, counters.trustlist);
        set_status("err", "Errors:", errcount, counters.errlist);
}

/* These functions are called by the contextmenu, toolsmenu, or statusbar icon */

function dnssecstatus_contextmenu_action() {
	alert("nothing here yet");
}

function dnssecstatus_toolsmenu_action() {
	alert("nothing here yet");
}

function dnssecstatus_statusbar_action() {
	window.openDialog("chrome://dnssecstatus/content/prefs.xul");
}

//
// Register new loading events
//
function dpageload() {
    window._content.addEventListener('load', dnssecstatus_show, true);
    loadit();
}
window.addEventListener('load', dpageload, true);

//
// Register for window changing events
//
const STATE_START =
    Components.interfaces.nsIWebProgressListener.STATE_START;
const STATE_STOP =
    Components.interfaces.nsIWebProgressListener.STATE_STOP;

const dnssecListener =
{
    onStateChange: function(aProgress, aRequest, aFlag, aStatus)
    {
        if(aFlag & STATE_START)
            {
                // This fires when the load event is initiated
                reset_all();
                dnssecstatus_show();
            }
        if(aFlag & STATE_STOP)
            {
                // This fires when the load finishes
                dnssecstatus_show();
            }
        return 0;
    },

    onLocationChange: function(aProgress, aRequest, aURI)
    {
        // This fires when the location bar changes i.e load event is confirmed
        // or when the user switches tabs
        // alert("change");
        reset_all();
        dnssecstatus_show();
        return 0;
    },

    // For definitions of the remaining functions see XulPlanet.com
    onProgressChange: function() {return 0;},
    onStatusChange: function() {return 0;},
    onSecurityChange: function() {return 0;},
    onLinkIconAvailable: function() {return 0;}
}

function loadit() {

    //alert("registering");
    getBrowser().addProgressListener(dnssecListener);
}	


//
// register for listening to DNSSEC status observations
//

var dnsRequestObserver =
{	
    observe:	function(subject, topic, data) 
    {	   
        dnssecstatus_got_dnssec(topic, data);
    } 
};	

var observerService = Components.classes["@mozilla.org/observer-service;1"]
    .getService(Components.interfaces.nsIObserverService);

observerService.addObserver(dnsRequestObserver,
                            "dnssec-status-both", false);
observerService.addObserver(dnsRequestObserver,
                            "dnssec-status-validated", false);
observerService.addObserver(dnsRequestObserver,
                            "dnssec-status-trusted", false);
observerService.addObserver(dnsRequestObserver,
                            "dnssec-status-neither", false);

//
// **********************************************************************
/*
  function dpageunload() {
  window._content.addEventListener('unload', dnssecstatus_show, true);
  alert("unload");
  // reset_all();
  }
  function dpageshow() {
  window._content.addEventListener('show', dnssecstatus_show, true);
  alert("show");
  }
  window.addEventListener('load', dpageunload, true);
  window.addEventListener('load', dpageshow, true);
*/


