import QtQuick 1.0

InfoBox {
    id: helpWindow
    state: "hidden"

    anchors.fill: parent
    width: dnssecCheckTop.width
    height: dnssecCheckTop.height

    widthPercent: .75

    text: "<style>a { color: #8888ff; } a:visited { color: red; }</style>
    The DNSSEC-Check application, developed as part of the <a href=\"http://www.dnssec-tools.org/\">DNSSEC-Tools</a> project
    is designed to test various aspects of DNS resolvers for their support of DNSSEC.  For the
    complete description of the tool, please visit the
    <a href=\"https://www.dnssec-tools.org/wiki/index.php/DNSSEC-Check\">DNSSEC-Check Wiki Page</a>."

    // the following doesn't fit on the screen and we need a scroll bar to get it to work
    /*
    <p>The following is a description of the tests performed.  Each test produces a color coded circle showing the results of
    the test:</p>
    <ul>
    <li>DNS: Can we at least resolve a simple A record?  If this is impossible, it's likely the resolver or the connection to it is not operational at all.</li>
    <li>TCP: Can we perform a simple query over TCP, which is needed for larger DNSSEC queries ''(such as querying for large DNSKEYs)''?</li>
    <li>DO: Does the resolver properly support the DO bit?  This test only checks that it is set in the response as well.  ''(Note that many resolvers copy the unknown bits into the response and don't actually support it.  The next test will catch the failures of those resolvers.)</li>
    <li>RRSIG: Are RRSIGs actually returned for a zone that is known to be signed when the DO bit is set?</li>
    <li>EDNS0: Do we get a reasonable EDNS0 size from the resolver? ''(the actual value returned is in the help text)''</li>
    <li>NSEC: Does the resolver properly return an NSEC record for a non-existent name in a zone that is known to be signed with NSEC support?</li>
    <li>NSEC: Does the resolver properly return an NSEC3 record for a non-existent name in a zone that is known to be signed with NSEC3 support?</li>
    <li>DNSKEY: Can we query the resolver for DNSKEYs and a response with DNSKEYs in it?</li>
    <li>DS: Can we query the resolver for DS records and get a response with DS records in it?</li>
    <li>AD: Does the resolver perform DNSSEC validation itself?</li>
    </ul>
    "
    */
}
