/*
 *
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 */

var gSpfHeader = {name:"received-spf", outputFunction:OutputReceivedSPF};
var gSpfExpandedView  = false;
var gSpfInited     = false;
var gSpfFields = [ {name:"receiver",      elemid:"spfReceiverBox"},
                   {name:"client-ip",     elemid:"spfClientIpBox"},
                   {name:"helo",          elemid:"spfHeloBox"},
                   {name:"envelope-from", elemid:"spfEnvelopeFromBox"},
                   {name:"problem",       elemid:"spfProblemBox"},
                   {name:"x-dnssec",      elemid:"spfXDnssecBox"}];
var pref;

var spfMessageListener = {
    mSpfSaveViewAllHeaders : false,
    mSpfSaveHdr : 1,
    mReloaded   : 0,

    onStartHeaders: function()
    {
        if (!this.mReloaded) {

  	    this.mSpfSaveHdr = pref.getIntPref("mail.show_headers");
	    mSpfSaveViewAllHeaders = gViewAllHeaders;

            if (pref)
	        pref.setIntPref("mail.show_headers", 2);

            this.mReloaded = 1;
  	    ReloadMessage();
        }
	else {
            if (pref)
	        pref.setIntPref("mail.show_headers", this.mSpfSaveHdr);

	    if (mSpfSaveViewAllHeaders) {
		gViewAllHeaders = true;
	    }
	    else {
		gExpandedHeaderView = {};
		initializeHeaderViewTables();
	        gViewAllHeaders = false;
	    }
            this.mReloaded = 0;
	}
	
    },

    onEndHeaders: function()
    {
    }
}

function initSpfDnssecHeader()
{
    if (!gSpfInited) {
        var prefsService = Components.classes["@mozilla.org/preferences-service;1"];
        if (prefsService)
            prefsService = prefsService.getService();
        if (prefsService)
            pref = prefsService.QueryInterface(Components.interfaces.nsIPrefBranch);

        gExpandedHeaderList.push(gSpfHeader);
	gMessageListeners.push(spfMessageListener);
	gSpfInited = true;
    }
}

function ToggleSpfHeaderView()
{
    if (gSpfExpandedView) {
        gSpfExpandedView = false;
        showSpfCollapsedView();
    }
    else {
        gSpfExpandedView = true;
        showSpfExpandedView();
    }
}

function showSpfExpandedView()
{
    var expandedNode = document.getElementById("spfExpandedHeaderView");
    var collapsedNode = document.getElementById("spfCollapsedHeaderView");
    expandedNode.collapsed = false;
    collapsedNode.collapsed = true;
}

function showSpfCollapsedView()
{
    var expandedNode = document.getElementById("spfExpandedHeaderView");
    var collapsedNode = document.getElementById("spfCollapsedHeaderView");
    expandedNode.collapsed = true;
    collapsedNode.collapsed = false;
}

function hideAllSpfViews()
{
    var expandedNode = document.getElementById("spfExpandedHeaderView");
    var collapsedNode = document.getElementById("spfCollapsedHeaderView");
    expandedNode.collapsed = false;
    collapsedNode.collapsed = false;
}

function OutputReceivedSPF(headerEntry, headerValue)
{
    var collapsedIcon       = document.getElementById("collapsedSpfHeaderIcon");
    var collapsedResultNode = document.getElementById("collapsedSpfResultBox");
    var expandedResultNode  = document.getElementById("expandedSpfResultBox");
    var index;

    if (!headerValue) {
        return;
    }

    for (index = 0; index < gSpfFields.length; index++) {

        var searchExp = new RegExp (gSpfFields[index].name + '\s*=', 'gi') ;
        var spfFieldNode = document.getElementById(gSpfFields[index].elemid);

        if (headerValue.search(searchExp) != -1) {
            var replExp = new RegExp('.*' + gSpfFields[index].name + '\s*=([^;]+);.*', 'gi');
            spfFieldNode.headerValue = headerValue.replace(replExp, '$1');
            spfFieldNode.collapsed   = false;
        }
        else {
            spfFieldNode.collapsed   = true;
        }
    }

    var dnssec = headerValue.replace(/.*x-dnssec=([^;]+).*/g, '$1');
    var dnssecNode = document.getElementById("spfXDnssecBox");
    var bgcolor = "background-color: ";

    if (dnssec.search(/pass/gi) != -1) {
        bgcolor += "green";
    }
    else {
        if (dnssec.search(/none/gi) != -1) {
            bgcolor += "yellow";
	}
	else {
            bgcolor += "red";
        }
    }

    dnssecNode.setAttribute         ("style", bgcolor);
    collapsedResultNode.setAttribute("style", bgcolor);
    collapsedIcon.setAttribute      ("style", bgcolor);

    var problemNode = document.getElementById("spfProblemBox");
    if (problemNode.collapsed == false) {
	problemNode.setAttribute    ("style", "background-color: red");
    }

    var result = headerValue.replace(/^([^=]+) [^= ]+=.*/g, '$1');

    if (result) {
        expandedResultNode.headerValue = result;
        collapsedResultNode.headerValue = result;

        if (gSpfExpandedView) {
            showSpfExpandedView();
        }
        else {
            showSpfCollapsedView();
        }
    }
    else {
        hideAllSpfViews();
    }
}

initSpfDnssecHeader();
