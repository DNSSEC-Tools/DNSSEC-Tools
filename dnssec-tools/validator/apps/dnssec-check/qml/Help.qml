import QtQuick 2.0

InfoBox {
    id: helpWindow
    state: "hidden"

    anchors.fill: parent
    width: dnssecCheckTop.width
    height: dnssecCheckTop.height

    widthPercent: .9

    text: "<style>a { color: #8888ff; } a:visited { color: red; }</style><h2>DNSSEC-Check Help</h2>
    The DNSSEC-Check application, developed as part of the <a href=\"http://www.dnssec-tools.org/\">DNSSEC-Tools</a> project,
    is designed to test various aspects of DNS resolvers for their support of DNSSEC.  For the
    complete description of the tool, please visit the
    <a href=\"https://www.dnssec-tools.org/wiki/index.php/DNSSEC-Check\">DNSSEC-Check Wiki Page</a>.

    <h2>Overview</h2>

    <p>Upon starting, the DNSSEC-Check window shows you a list of the configured DNS resolvers for your system.  You can add new
    resolvers to the list by clicking and typing into the box labeled \"<i>Click to add a new resolver address</i>\" and then hitting
    return or pressing the \"<i>Add</i>\" button.  You can clear the list of resolvers and start with an empty list by clicking on
    the \"<i>Clear Resolvers</i>\" button.

    <p>The \"<i>Run Tessts</i>\" button will then execute each of the available tests for each of the resolvers and graphically
    show you the results by coloring in the result circles.  The full list of tests and an explination of them can be found at the bottom
    of this page.  The result circles have the following colors:

    <ul>
    <li>Green: the test passed
    <li>Warning: the test partially succeeded
    <li>Red: the test failed
    </ul>

    Hovering the mouse over a circle will show you a description of the test and its status.

    To clear the test results, hit the reset button.  You can also individually click on a given circle to (re)run that test.

    Finally, clicking on a resolver address will bring up a menu that will let you:
    <ul>
    <li>Run the tests for that resolver</li>
    <li>Reset the tests for that resolver</li>
    <li>Remove that resolver from the list</li>
    </ul>

    <h2>Submitting Your Results</h2>

    One of the goals of the <a href=\"http://www.dnssec-deployment.org/\">DNSSEC-Deployment</a> project, which the
    <a href=\"http://www.dnssec-tools.org/\">DNSSEC-Tools</a> project is a sub-project of, is to collect information about
    the current deployment level of DNSSEC.  In order to do this, we're asking that willing participants submit the results of running
    DNSSEC-Check to the collection server running on the DNSSEC-Tools web server.  The following pieces of information are collected and
    processed by the collection server:
    <ul>
    <li>A hashed version of the IP address for each resolver</li>
    <li>A hashed version of the IP address the submission is coming from</li>
    <li>The success/fail/warning status result of each test that was run.</li>
    </ul>

    It should be noted that in the above data all the IP addresses are hashed to provide anonymity of the data.

    <h2>Tests Performed</h2>

    <p>The following is a description of the tests performed.  Each test produces a color coded circle showing the results of
    the test:</p>
    <ul>
    <li>DNS: Can we at least resolve a simple A record?  If this is impossible, it's likely the resolver or the connection to it is not operational at all.</li>
    <li>TCP: Can we perform a simple query over TCP, which is needed for larger DNSSEC queries <i>(such as querying for large DNSKEYs)</i>?</li>
    <li>DO: Does the resolver properly support the DO bit?  This test only checks that it is set in the response as well.  <i>(Note that many resolvers copy the unknown bits into the response and don't actually support it.  The next test will catch the failures of those resolvers.)</i></li>
    <li>RRSIG: Are RRSIGs actually returned for a zone that is known to be signed when the DO bit is set?</li>
    <li>EDNS0: Do we get a reasonable EDNS0 size from the resolver? <i>(the actual value returned is in the help text)</i></li>
    <li>NSEC: Does the resolver properly return an NSEC record for a non-existent name in a zone that is known to be signed with NSEC support?</li>
    <li>NSEC: Does the resolver properly return an NSEC3 record for a non-existent name in a zone that is known to be signed with NSEC3 support?</li>
    <li>DNSKEY: Can we query the resolver for DNSKEYs and a response with DNSKEYs in it?</li>
    <li>DS: Can we query the resolver for DS records and get a response with DS records in it?</li>
    <li>AD: Does the resolver perform DNSSEC validation itself?</li>
    </ul>
    "

}
