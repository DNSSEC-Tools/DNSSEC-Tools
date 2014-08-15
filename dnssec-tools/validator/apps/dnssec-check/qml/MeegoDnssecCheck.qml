import QtQuick 2.0

// wrapper just for meego/harmattan to set up the screen correctly

import com.nokia.meego 1.0
PageStackWindow {
   initialPage: Page {
      orientationLock: PageOrientation.LockLandscape
      DnssecCheck { anchors.fill: parent }
   }
}
