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

var storage = {};

var loginfo = "";

var current_spot = "";

function get_err_summary() {
    maybe_init_spot(current_spot);
    return "val: " + storage[current_spot]["valcount"] + "/tr: " +
        storage[current_spot]["trustcount"] + "/err: " +
        storage[current_spot]["errcount"];
}

function logit(str) {
    loginfo = loginfo + str + "- spot = " + current_spot + "\n";
}

function showlog(lastbit) {
    if (loginfo != "") {
        if (lastbit)
            loginfo = loginfo + lastbit;
        //alert(loginfo);
        loginfo = "";
    }
}

function reset_all(spot) {
    if (!storage[spot]) {
        storage[spot] = {};
    }
    storage[spot]["vallist"] = {};
    storage[spot]["trustlist"] = {};
    storage[spot]["errlist"] = {};
    storage[spot]["valcount"] = 0;
    storage[spot]["trustcount"] = 0;
    storage[spot]["errcount"] = 0;
    logit("- reseting: " + spot);
}

function maybe_init_spot(spot) {
    if (!storage[spot]) {
        logit("- creating: " + spot);
        reset_all(spot);
    }
}

function merge_spot(tospot, spotin) {
    if (storage[spotin]) {
        maybe_init_spot(tospot);
        for (var i in { trust: 1, err: 1, val: 1 }) {
            storage[tospot][i + "count"] += storage[spotin][i + "count"];
            for (var j in storage[spotin][i + "list"]) {
                add_to_list(storage[tospot][i + "list"], j);
                storage[tospot][i + "list"] = storage[spotin][i + "list"]-1;
            }
        }
        reset_all(spotin);
    }
}

function add_to_list(thelist, host) {
    if(thelist[host]) {
      thelist[host] = thelist[host] + 1;
    } else {
      thelist[host] = 1;
    }
    //logit("-  adding:" + host);
}

function get_unique_string(thelist) {
    var tempstr = "";
    for (var i in thelist) {
          tempstr = tempstr + i + "(" + thelist[i] + ") ";
    }
    return tempstr;
}

function add_to_storage(spot, name, host) {
    if (!storage[spot]) {
        storage[spot] = {};
        reset_all(spot);
    }
    storage[spot][name + "count"]++;
    add_to_list(storage[spot][name + "list"], host);
}

function dnssecstatus_got_dnssec(topic, host) { 
    logit("- dnssec: " + topic + " => " + host);
    if (topic == "dnssec-status-both" || topic == "dnssec-status-validated") {
        add_to_storage(current_spot, "val", host);
    }
    if (topic == "dnssec-status-trusted") {
        add_to_storage(current_spot, "trust", host);
    }
    if (topic == "dnssec-status-neither") {
        add_to_storage(current_spot, "err", host);
    }
    // window._content.document.dnscount = window._content.document.dnscount + 1;
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
/*
   var docshell = document.getElementById("content").webNavigation;

        var shells = 
            docshell.getDocShellEnumerator(ifs.nsIDocShellTreeItem.typeAll,
                                           ifs.nsIDocShell.ENUMERATE_FORWARDS);

        var docnum = 0;
        var doccounter = window._content.document.dnscount;
        while (shells.hasMoreElements())
            {           
                var shell = shells.getNext().QueryInterface(ifs.nsIDocShell);
                docnum++;
            }

        //var spot = window._content.document.documentURI.spec;

*/
        var spot = current_spot;
        maybe_init_spot(spot);
        set_status("val", "DNS: Verified:", storage[spot]["valcount"],
                   storage[spot]["vallist"]);
        set_status("trust", "Unverified:", storage[spot]["trustcount"],
                   storage[spot]["trustlist"]);
        set_status("err", "Errors:", storage[spot]["errcount"], 
                   storage[spot]["errlist"]);
        
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
                current_spot = "";
                reset_all(current_spot);
                logit("start: " + current_spot + " / " + get_err_summary());
            }
        if(aFlag & STATE_STOP)
            {
                // This fires when the load finishes
                // dnssecstatus_show();
/*
                window._content.document.dnserrcount = errcount;
                window._content.document.dnsvalcount = valcount;
                window._content.document.dnstrustcount = trustcount;
*/
//                logit("stop: " + // window._content.document.location.host +
//                      " " +  get_err_summary());
                dnssecstatus_show(current_spot);
                showlog("stop: " + current_spot);
            }
        return 0;
    },

    onLocationChange: function(aProgress, aRequest, aURI)
    {
        // This fires when the location bar changes i.e load event is confirmed
        // or when the user switches tabs
        // logit("change");
/*
        reset_all();
        errcount = window._content.document.dnserrcount;
        valcount = window._content.document.dnsvalcount;
        trustcount = window._content.document.dnstrustcount;
*/
        // dnssecstatus_show();
        if (current_spot == "") {
            // till now we haven't seen the parent
            reset_all(aURI.spec);
            merge_spot(aURI.spec, "");
        }
        current_spot = aURI.spec;
        logit("change: " + aURI.spec + " " + get_err_summary());
        dnssecstatus_show(current_spot);
        return 0;
    },

    // For definitions of the remaining functions see XulPlanet.com
    onProgressChange: function() {return 0;},
    onStatusChange: function() {return 0;},
    onSecurityChange: function() {return 0;},
    onLinkIconAvailable: function() {return 0;}
}

/*
function do_load() {
    logit("loading: ");
}
*/

function do_unload() {
    current_spot = "";
    reset_all(current_spot);
    logit("unload: ");
//    showlog();
}

/*
function loadit() {
    //logit("registering");
    var browser = getBrowser();
    browser.addProgressListener(dnssecListener);
    window._content.addEventListener("load", do_load, true);
    window._content.addEventListener("unload", do_unload, true);
} 
*/

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
  window._content.document.addEventListener('unload', dnssecstatus_show, true);
  logit("unload");
  // reset_all();
  }
  function dpageshow() {
  window._content.document.addEventListener('show', dnssecstatus_show, true);
  logit("show");
  }
  window.addEventListener('unload', dpageunload, true);
  window.addEventListener('show', dpageshow, true);
*/

//
// Register new loading events
//

function dpageload() {
    //logit("registering");

    window._content.addEventListener('load', dnssecstatus_show, true);
    window._content.addEventListener('unload', do_unload, true);

    try {
        var browser = getBrowser();
        browser.addProgressListener(dnssecListener);
    } catch (ex) {
        // exception thrown for Thunderbird
        //XXX is there a progress listener for thunderbird?
    }
}
window.addEventListener('load', dpageload, true);

