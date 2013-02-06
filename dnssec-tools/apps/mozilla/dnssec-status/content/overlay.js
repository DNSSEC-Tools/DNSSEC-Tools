///////////////////////////////////////////////////////////////////////////
// Globals

var dsu;
var dso;
var dsp;

///////////////////////////////////////////////////////////////////////////
// Structure for updating DNSSEC Status


// Constructor
function dnssecstatusUpdater() {
    this.registered = false;
    this.register();
};

dnssecstatusUpdater.prototype = {
    register: function() {
        if (this.registered == false) { 
            this.tabcnt = 0;
            this.browsertabs = [];
            this.statuscts = {};
            this.linkinfo = {};
            this.container = gBrowser.tabContainer;
            this.container.addEventListener("TabClose", this.onTabClose, false);
            this.strings = document.getElementById("dnssecstatus-strings");
            this.dnssec_enabled = true;
            this.registered = true;
        }
    },
    unregister: function() {
        if (this.registered == true) {
            this.container.removeEventListener("TabClose", this.onTabClose, false);
            this.registered = false;
        }
    },
    enable_dnssec: function(value) {
        if (value == 0 || value == 2) {
            this.dnssec_enabled = true;
        } else {
            this.dnssec_enabled = false;
        }
    },
    reset_counts: function(index) {
        this.statuscts[index] = {};
        this.statuscts[index][0] = 0;
        this.statuscts[index][1] = 0;
        this.statuscts[index][2] = 0;
        this.linkinfo[index] = {};
        this.linkinfo[index][0] = {};
        this.linkinfo[index][1] = {};
        this.linkinfo[index][2] = {};
    },
    find_tab_index: function(browser) {
        var i;
        var index = -1;
        for (i=0; i<this.tabcnt; i++) {
            if (this.browsertabs[i] == null) {
                // try and re-use an existing slot
                index = i;
            } else if (this.browsertabs[i] == browser) {
                return i;
            }
        }

        if (index == -1) {
            // we didn't find an empty slot
            index = this.tabcnt;
            this.tabcnt++;
        }
        this.reset_counts(index);
        //alert ("Setting browsertab at index: " + index + "to:" + browser);
        this.browsertabs[index] = browser;
        return index;
    },
    notifybox: function(u_cnt) {
        var nb = gBrowser.getNotificationBox();
        nb.appendNotification(  
          this.strings.getString("dnssecnotificationTitle"), 
          "dnssecstatus-notification",  
          "chrome://dnssecstatus/content/dnssecstatus.png",  
          nb.PRIORITY_WARNING_MEDIUM);
    },
    set_statusbar_info: function(index) {
        if ((index == -1) || (this.dnssec_enabled == false)) {
            //document.getElementById("dnssecstatus-label").style.color = "#e49917";
            //document.getElementById("dnssecstatus-unum").style.color = "#e49917";
            //document.getElementById("dnssecstatus-unum").value = "???";
            document.getElementById("dnssecstatus-label").style.display = "none";
            document.getElementById("dnssecstatus-unum").style.display = "none";
            document.getElementById("dnssec-enabled-icon").style.display = "none";
            return;
        } 

        var t_cnt = this.statuscts[index][0];
        var u_cnt = this.statuscts[index][1];
        var e_cnt = this.statuscts[index][2];

        // don't set status if all counts are 0
        // we could reach this condition if we've just hit an error page 
        // where counts are reset, followed by the onpageload event that
        // causes us to refresh the status bar information
        if ((t_cnt == 0) && (u_cnt == 0) && (e_cnt == 0)) {
            return;
        }

        // Display the address bar icon that says that we are DNSSEC-capable
        document.getElementById("dnssecstatus-label").style.display = "inline";
        document.getElementById("dnssecstatus-unum").style.display = "inline";
        document.getElementById("dnssec-enabled-icon").style.display = "inline";

        if (u_cnt > 0) {
            // color the indicator red
            document.getElementById("dnssecstatus-label").style.color = "#aa0000";
            document.getElementById("dnssecstatus-unum").style.color = "#aa0000";
            this.notifybox();
        } else {
            // color the indicator green
            document.getElementById("dnssecstatus-label").style.color = "#00aa00";
            document.getElementById("dnssecstatus-unum").style.color = "#00aa00"; 
        }
        document.getElementById("dnssecstatus-unum").value = u_cnt;
    },
    save_host_data: function(host, b_off, d_off) {

        this.statuscts[b_off][d_off]++; 
        if (this.linkinfo[b_off][d_off][host] > 0) {
            this.linkinfo[b_off][d_off][host]++;
        } else {
            this.linkinfo[b_off][d_off][host] = 1;
        }
    },
    get_hash_elements: function(hash) { 
        var i;
        var str = "";
        for (i in hash) {
           str += i + "\n"; 
        }
        return str;
    },
    logit: function(browser, host, topic) {
        if (!browser) {
            return;
        }
        var i = this.find_tab_index(browser);
        //alert ("logit:" + i + ":" + uri + ":" + topic);

        if (topic == "dnssec-status-trusted") {
            this.save_host_data(host, i, 0);
        } else if (topic == "dnssec-status-untrusted") {
            this.save_host_data(host, i, 1);
        } else if (topic == "dnssec-status-error") {
            this.save_host_data(host, i, 2);
        }
        // Set the untrusted count in the satus bar
        if (browser == gBrowser.selectedBrowser) {
            this.set_statusbar_info(i);
        }
    },
    getStatusSummary: function() {
        var opstr = "";
        var i;
        var cur_browser = gBrowser.selectedBrowser;
        for (i=0; i<this.tabcnt; i++) {
            if (this.browsertabs[i] == cur_browser) {
                opstr += "Untrusted links:" + "(" + this.statuscts[i][1] + "):\n" 
                         + this.get_hash_elements(this.linkinfo[i][1]);
                opstr += "\n\nError links:" + "(" + this.statuscts[i][2] + "):\n" 
                         + this.get_hash_elements(this.linkinfo[i][2]);
                opstr += "\n\nTrusted links:" + "(" + this.statuscts[i][0] + "):\n" 
                         + this.get_hash_elements(this.linkinfo[i][0]);
                return opstr;
            } 
        }
        return "No DNSSEC information registered.";
    },
    init_statusbar_info: function() {
        var index = this.find_tab_index(gBrowser.selectedBrowser);
        this.reset_counts(index);
        this.set_statusbar_info(-1);
    },
    refresh_statusbar_info: function() {
        var index = this.find_tab_index(gBrowser.selectedBrowser);
        this.set_statusbar_info(index);
    },
    onTabClose: function(ev) {
        var browser = ev.target.linkedBrowser;
        for (var i = 0; i < dsu.tabcnt; i++) {
            if (dsu.browsertabs[i] == browser) {
                //alert("onTabClose completed, set browsertab status to 0 for " + i);
                dsu.browsertabs[i] = null;
                return;    
            }
        }
    },
};

///////////////////////////////////////////////////////////////////////////
// Structure for observing notification events 

// Constructor
function dnssecstatusObserver() {
    this.registered = false;
    this.register();
};

dnssecstatusObserver.prototype = {

  getBrowserFromChannel: function (aChannel) {
      try {
          var notificationCallbacks = 
                aChannel.notificationCallbacks ? 
                    aChannel.notificationCallbacks : aChannel.loadGroup.notificationCallbacks;
          if (!notificationCallbacks)
              return null;
          var domWin = notificationCallbacks.getInterface(Components.interfaces.nsIDOMWindow);
          return gBrowser.getBrowserForDocument(domWin.top.document);
      } catch (e) {
          dump(e + "\n");
          return null;
      }
  },
  register: function() {
     if (this.registered == false) { 
       var observerService = Components.classes["@mozilla.org/observer-service;1"]
                                       .getService(Components.interfaces.nsIObserverService);
       observerService.addObserver(this, "dnssec-status-trusted", false);
       observerService.addObserver(this, "dnssec-status-untrusted", false);
       observerService.addObserver(this, "dnssec-status-error", false);

       var prefService = Components.classes["@mozilla.org/preferences-service;1"]  
                                       .getService(Components.interfaces.nsIPrefService);
       dsu.enable_dnssec(prefService.getIntPref("security.dnssec.dnssecBehavior"));
       this._branch = prefService.getBranch("security.dnssec.dnssecBehavior");
       this._branch.QueryInterface(Components.interfaces.nsIPrefBranch2);
       this._branch.addObserver("", this, false);

       this.registered = true;
     }
  },
   //Unregisters from the observer services
  unregister: function() {
     if (this.registered == true) {
       var observerService = Components.classes["@mozilla.org/observer-service;1"]
                                       .getService(Components.interfaces.nsIObserverService);
       observerService.removeObserver(this, "dnssec-status-trusted");
       observerService.removeObserver(this, "dnssec-status-untrusted");
       observerService.removeObserver(this, "dnssec-status-error");
       this._branch.removeObserver("", this);
       this.registered = false;
     }
  },
  observe: function(subject, topic, data) {
     if (topic == "nsPref:changed") {
        // update current DNSSEC status
        var prefService = Components.classes["@mozilla.org/preferences-service;1"]  
                                       .getService(Components.interfaces.nsIPrefService);
        dsu.enable_dnssec(prefService.getIntPref("security.dnssec.dnssecBehavior")); 
        return;
     }
     var httpChannel = subject.QueryInterface(Components.interfaces.nsIHttpChannel);
     var browser = this.getBrowserFromChannel(subject);
     var channel = subject.QueryInterface(Components.interfaces.nsIChannel);
     //var url = channel.URI.spec;
     //url = url.toString();
     //dsu.logit(browser, url, topic);
     var host = channel.URI.host;
     host = host.toString();

     dsu.logit(browser, host, topic);
  },
};

///////////////////////////////////////////////////////////////////////////
// Structure for observing web progress events 

const nsIIRequestor = Components.interfaces.nsIInterfaceRequestor;
const nsIWebProgress = Components.interfaces.nsIWebProgress;
const nsIWebProgressListener = Components.interfaces.nsIWebProgressListener;

// Constructor
function dnssecprogresslistener() {
    //var req = gBrowser.webNavigation.QueryInterface(nsIIRequestor);
    //var prog = req.getInterface(nsIWebProgress);
    //prog.addProgressListener(this, nsIWebProgress.NOTIFY_ALL);

    //var webProgress = Components.classes["@mozilla.org/docloaderservice;1"].getService(nsIWebProgress);
    //if (webProgress) {
    //    webProgress.addProgressListener(this, nsIWebProgress.NOTIFY_STATE_ALL);
    //}

    //getBrowser().addProgressListener(this ,nsIWebProgress.NOTIFY_ALL);
    //gBrowser.webProgress.addProgressListener(this, nsIWebProgress.NOTIFY_ALL);
    //window.getBrowser().docShell.addProgresslistener(this, nsIWebProgress.NOTIFY_STATE_ALL);
    //gBrowser.addProgressListener(this, nsIWebProgress.NOTIFY_STATE_ALL);
    //top.getBrowser().addProgressListener(this, nsIWebProgress.NOTIFY_STATE_ALL);
    this.registered = false;
    this.register();
};

dnssecprogresslistener.prototype = {

    register: function() {
        if (this.registered == false) {
            gBrowser.addProgressListener(this, nsIWebProgress.NOTIFY_ALL);
            this.registered = true;
        }
    },
    unregister: function() {
        if (this.registered == true) {
            gBrowser.removeProgressListener(this);
            this.registered = false;
        }
    },

    // nsIWebProgressListener methods 
    onStateChange: function(aProgress, aRequest, aFlag, aStatus)
    {
        //if(aFlag & (nsIWebProgressListener.STATE_STOP|nsIWebProgressListener.STATE_IS_REQUEST)) {
        //  aRequest.QueryInterface(Components.interfaces.nsIHttpChannel);
        //  alert( aRequest.URI.spec + ":\n" + aFlag + ":\n" + aStatus);        
        //}
        //return 0;
        //alert ("onStateChange: " + aFlag);
        //if(aFlag & (nsIWebProgressListener.STATE_START|
        //          nsIWebProgressListener.STATE_IS_DOCUMENT)) {
        //    dsu.init_statusbar_info();
        //}
        // Reset status bar information if we had an error loading the page 
        if (aStatus && (aFlag & nsIWebProgressListener.STATE_STOP)) {
            dsu.init_statusbar_info();
        }
    },
    onLocationChange:function(aProgress, aRequest, aURI) {
        //var domWindow = aProgress.DOMWindow;
        //alert (domWindow.location.href + ":" + domWindow.top.location.href + ":" + aURI.spec);
        if (gBrowser.selectedBrowser.webProgress.isLoadingDocument) { 
            // we are loading a document
            dsu.init_statusbar_info();
        } else {
            // we have just changed tabs
            dsu.refresh_statusbar_info();
        }
    },
    onProgressChange:function(a,b,c,d,e,f){},
    onSecurityChange:function(a,b,c){},
    onStatusChange:function(aProgress, aRequest, aStatus, aMessage){},
    onRefreshAttempted:function(a,b,c,d){},
    onLinkIconAvailable: function(a) {},
    QueryInterface : function(aIID) { 
        if (aIID.equals(Components.interfaces.nsIWebProgressListener) ||  
            aIID.equals(Components.interfaces.nsISupportsWeakReference) ||  
            aIID.equals(Components.interfaces.nsISupports))  
                return this;  
        throw Components.results.NS_NOINTERFACE;
    },
};

///////////////////////////////////////////////////////////////////////////
// Main body 

var dnssecstatus = {
  onLoad: function() {
    // initialization code
    dsu = new dnssecstatusUpdater();
    dso = new dnssecstatusObserver();
    dsp = new dnssecprogresslistener();
    this.initialized = true;
  },
  onUnload: function() {
    // cleanup code
    dsu.unregister();
    dso.unregister();
    dsp.unregister();
    this.initialized = false;
  },
  statusbar_action: function() {
    //var observerService = Components.classes["@mozilla.org/observer-service;1"]
    //                      .getService(Components.interfaces.nsIObserverService);
    //observerService.notifyObservers(null, "dnssec-status-error", "some data");
    alert(dsu.getStatusSummary());
  },
  urlbar_action: function() {
    alert(dsu.getStatusSummary());
  },
};


////////////////////////////////////////////////////////////////////////////////

window.addEventListener("load", function(e) { dnssecstatus.onLoad();}, false);
window.addEventListener("unload", function(e) { dnssecstatus.onUnload();}, false);
