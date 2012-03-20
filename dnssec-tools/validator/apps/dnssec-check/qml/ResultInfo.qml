import QtQuick 1.0

InfoBox {
    id: resultInfo
    state: "hidden"

    anchors.fill: parent
    width: dnssecCheckTop.width
    height: dnssecCheckTop.height

    widthPercent: .75

    property string testName: ""
    property string testResult: ""
    property string resolverName: ""

    text: ""

    onTestNameChanged: { updateText() ; }
    onTestResultChanged: { updateText(); }
    onResolverNameChanged: { updateText(); }

    function updateText() {
        resultInfo.text = "<style>a { color: #8888ff; } a:visited { color: red; }</style><h2>DNSSEC-Check Result</h2>" +
                "The <b>" + resultInfo.testName + "</b> test was run and tested against the <b>" + resolverName +
                "</b> resolver, with the following result:" +
                "<p>" + testResult + "</p>"
    }

    Component.onCompleted: {
        updateText()
    }
}
