/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is mozilla.org code.
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 1998
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either of the GNU General Public License Version 2 or later (the "GPL"),
 * or the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */
#include "nsCOMPtr.h"
#include "nsPresContext.h"
#include "nsIPresShell.h"
#include "nsILinkHandler.h"
#include "nsIDocShellTreeItem.h"
#include "nsIDocShell.h"
#include "nsIContentViewer.h"
#include "nsIDocumentViewer.h"
#include "nsPIDOMWindow.h"
#include "nsIFocusController.h"
#include "nsStyleSet.h"
#include "nsImageLoader.h"
#include "nsIContent.h"
#include "nsIFrame.h"
#include "nsIRenderingContext.h"
#include "nsIURL.h"
#include "nsIDocument.h"
#include "nsStyleContext.h"
#include "nsLayoutAtoms.h"
#include "nsILookAndFeel.h"
#include "nsWidgetsCID.h"
#include "nsIComponentManager.h"
#include "nsIURIContentListener.h"
#include "nsIInterfaceRequestor.h"
#include "nsIInterfaceRequestorUtils.h"
#include "nsIServiceManager.h"
#include "nsIDOMElement.h"
#include "nsContentPolicyUtils.h"
#include "nsIScriptGlobalObject.h"
#include "nsIDOMWindow.h"
#include "nsXPIDLString.h"
#include "nsIWeakReferenceUtils.h"
#include "nsCSSRendering.h"
#include "prprf.h"
#include "prnetdb.h"
#include "nsContentPolicyUtils.h"
#include "nsIScriptGlobalObject.h"
#include "nsIDOMDocument.h"
#include "nsAutoPtr.h"
#include "nsEventStateManager.h"
#include "nsIEventQueue.h"
#include "nsIEventQueueService.h"

#ifdef IBMBIDI
#include "nsBidiPresUtils.h"
#endif // IBMBIDI

#include "nsContentUtils.h"

// Needed for Start/Stop of Image Animation
#include "imgIContainer.h"
#include "nsIImageLoadingContent.h"

//needed for resetting of image service color
#include "nsLayoutCID.h"
#include "nsISelectionImageService.h"

static nscolor
MakeColorPref(const char *colstr)
{
  PRUint32 red, green, blue;
  nscolor colorref;

  // 4.x stored RGB color values as a string rather than as an int,
  // thus we need to do this conversion
  PR_sscanf(colstr, "#%02x%02x%02x", &red, &green, &blue);
  colorref = NS_RGB(red, green, blue);
  return colorref;
}

int PR_CALLBACK
nsPresContext::PrefChangedCallback(const char* aPrefName, void* instance_data)
{
  nsPresContext*  presContext = (nsPresContext*)instance_data;

  NS_ASSERTION(nsnull != presContext, "bad instance data");
  if (nsnull != presContext) {
    presContext->PreferenceChanged(aPrefName);
  }
  return 0;  // PREF_OK
}


void
nsPresContext::PrefChangedUpdateTimerCallback(nsITimer *aTimer, void *aClosure)
{
  nsPresContext*  presContext = (nsPresContext*)aClosure;
  NS_ASSERTION(presContext != nsnull, "bad instance data");
  if (presContext)
    presContext->UpdateAfterPreferencesChanged();
}

#ifdef IBMBIDI
static PRBool
IsVisualCharset(const nsCString& aCharset)
{
  if (aCharset.LowerCaseEqualsLiteral("ibm864")             // Arabic//ahmed
      || aCharset.LowerCaseEqualsLiteral("ibm862")          // Hebrew
      || aCharset.LowerCaseEqualsLiteral("iso-8859-8") ) {  // Hebrew
    return PR_TRUE; // visual text type
  }
  else {
    return PR_FALSE; // logical text type
  }
}
#endif // IBMBIDI


PR_STATIC_CALLBACK(PRBool) destroy_loads(nsHashKey *aKey, void *aData, void* closure)
{
  nsISupports *sup = NS_REINTERPRET_CAST(nsISupports*, aData);
  nsImageLoader *loader = NS_REINTERPRET_CAST(nsImageLoader*, sup);
  loader->Destroy();
  return PR_TRUE;
}

static NS_DEFINE_CID(kLookAndFeelCID,  NS_LOOKANDFEEL_CID);
#include "nsContentCID.h"
static NS_DEFINE_CID(kSelectionImageService, NS_SELECTIONIMAGESERVICE_CID);

  // NOTE! nsPresContext::operator new() zeroes out all members, so don't
  // bother initializing members to 0.

nsPresContext::nsPresContext(nsPresContextType aType)
  : mType(aType),
    mTextZoom(1.0),
    mViewportStyleOverflow(NS_STYLE_OVERFLOW_AUTO, NS_STYLE_OVERFLOW_AUTO),
    mCompatibilityMode(eCompatibility_FullStandards),
    mImageAnimationModePref(imgIContainer::kNormalAnimMode),
    mDefaultVariableFont("serif", NS_FONT_STYLE_NORMAL, NS_FONT_VARIANT_NORMAL,
                         NS_FONT_WEIGHT_NORMAL, 0, NSIntPointsToTwips(12)),
    mDefaultFixedFont("monospace", NS_FONT_STYLE_NORMAL, NS_FONT_VARIANT_NORMAL,
                      NS_FONT_WEIGHT_NORMAL, 0, NSIntPointsToTwips(10)),
    mDefaultSerifFont("serif", NS_FONT_STYLE_NORMAL, NS_FONT_VARIANT_NORMAL,
                      NS_FONT_WEIGHT_NORMAL, 0, NSIntPointsToTwips(12)),
    mDefaultSansSerifFont("sans-serif", NS_FONT_STYLE_NORMAL, NS_FONT_VARIANT_NORMAL,
                          NS_FONT_WEIGHT_NORMAL, 0, NSIntPointsToTwips(12)),
    mDefaultMonospaceFont("monospace", NS_FONT_STYLE_NORMAL, NS_FONT_VARIANT_NORMAL,
                          NS_FONT_WEIGHT_NORMAL, 0, NSIntPointsToTwips(10)),
    mDefaultCursiveFont("cursive", NS_FONT_STYLE_NORMAL, NS_FONT_VARIANT_NORMAL,
                        NS_FONT_WEIGHT_NORMAL, 0, NSIntPointsToTwips(12)),
    mDefaultFantasyFont("fantasy", NS_FONT_STYLE_NORMAL, NS_FONT_VARIANT_NORMAL,
                        NS_FONT_WEIGHT_NORMAL, 0, NSIntPointsToTwips(12))
{
  // NOTE! nsPresContext::operator new() zeroes out all members, so don't
  // bother initializing members to 0.

  mDoScaledTwips = PR_TRUE;

  SetBackgroundImageDraw(PR_TRUE);		// always draw the background
  SetBackgroundColorDraw(PR_TRUE);

  mBackgroundColor = NS_RGB(0xFF, 0xFF, 0xFF);
  
  mUseDocumentColors = PR_TRUE;
  mUseDocumentFonts = PR_TRUE;

  // the minimum font-size is unconstrained by default

  mLinkColor = NS_RGB(0x00, 0x00, 0xEE);
  mActiveLinkColor = NS_RGB(0xEE, 0x00, 0x00);
  mVisitedLinkColor = NS_RGB(0x55, 0x1A, 0x8B);
  mUnderlineLinks = PR_TRUE;

  mFocusTextColor = mDefaultColor;
  mFocusBackgroundColor = mBackgroundColor;
  mFocusRingWidth = 1;

  mLanguageSpecificTransformType = eLanguageSpecificTransformType_Unknown;
  if (aType == eContext_Galley) {
    mMedium = nsLayoutAtoms::screen;
    mImageAnimationMode = imgIContainer::kNormalAnimMode;
  } else {
    SetBackgroundImageDraw(PR_FALSE);
    SetBackgroundColorDraw(PR_FALSE);
    mImageAnimationMode = imgIContainer::kDontAnimMode;
    mNeverAnimate = PR_TRUE;
    mMedium = nsLayoutAtoms::print;
    mPaginated = PR_TRUE;
    if (aType == eContext_PrintPreview) {
      mCanPaginatedScroll = PR_TRUE;
      mPageDim.SetRect(-1, -1, -1, -1);
    } else {
      mPageDim.SetRect(0, 0, 0, 0);
    }
  }
}

nsPresContext::~nsPresContext()
{
  mImageLoaders.Enumerate(destroy_loads);

  NS_PRECONDITION(!mShell, "Presshell forgot to clear our mShell pointer");
  SetShell(nsnull);

  if (mEventManager) {
    mEventManager->SetPresContext(nsnull);   // unclear if this is needed, but can't hurt
    NS_RELEASE(mEventManager);
  }

  if (mPrefChangedTimer)
  {
    mPrefChangedTimer->Cancel();
    mPrefChangedTimer = nsnull;
  }

  // Unregister preference callbacks
  nsContentUtils::UnregisterPrefCallback("font.",
                                         nsPresContext::PrefChangedCallback,
                                         this);
  nsContentUtils::UnregisterPrefCallback("browser.display.",
                                         nsPresContext::PrefChangedCallback,
                                         this);
  nsContentUtils::UnregisterPrefCallback("browser.underline_anchors",
                                         nsPresContext::PrefChangedCallback,
                                         this);
  nsContentUtils::UnregisterPrefCallback("browser.anchor_color",
                                         nsPresContext::PrefChangedCallback,
                                         this);
  nsContentUtils::UnregisterPrefCallback("browser.active_color",
                                         nsPresContext::PrefChangedCallback,
                                         this);
  nsContentUtils::UnregisterPrefCallback("browser.visited_color",
                                         nsPresContext::PrefChangedCallback,
                                         this);
  nsContentUtils::UnregisterPrefCallback("image.animation_mode",
                                         nsPresContext::PrefChangedCallback,
                                         this);
  nsContentUtils::UnregisterPrefCallback("image.animation_mode",
                                         nsPresContext::PrefChangedCallback,
                                         this);
#ifdef MOZ_DNSSEC
  nsContentUtils::UnregisterPrefCallback("security.dnssec.dnssecBehavior",
                                         nsPresContext::PrefChangedCallback,
                                         this);
#endif
#ifdef IBMBIDI
  nsContentUtils::UnregisterPrefCallback("bidi.", PrefChangedCallback, this);

  delete mBidiUtils;
#endif // IBMBIDI

  NS_IF_RELEASE(mDeviceContext);
  NS_IF_RELEASE(mLookAndFeel);
  NS_IF_RELEASE(mLangGroup);
  NS_IF_RELEASE(mEventQueueService);
}

NS_IMPL_ISUPPORTS2(nsPresContext, nsPresContext, nsIObserver)

#define MAKE_FONT_PREF_KEY(_pref, _s0, _s1) \
 _pref.Assign(_s0); \
 _pref.Append(_s1);

static const char* const kGenericFont[] = {
  ".variable.",
  ".fixed.",
  ".serif.", 
  ".sans-serif.", 
  ".monospace.",
  ".cursive.",
  ".fantasy."
};

// Set to true when LookAndFeelChanged needs to be called.  This is used
// because the look and feel is a service, so there's no need to notify it from
// more than one prescontext.
static PRBool sLookAndFeelChanged;

// Set to true when ThemeChanged needs to be called on mTheme.  This is used
// because mTheme is a service, so there's no need to notify it from more than
// one prescontext.
static PRBool sThemeChanged;


void
nsPresContext::GetFontPreferences()
{
  if (!mLangGroup)
    return;

  /* Fetch the font prefs to be used -- see bug 61883 for details.
     Not all prefs are needed upfront. Some are fallback prefs intended
     for the GFX font sub-system...

  1) unit : assumed to be the same for all language groups -------------
  font.size.unit = px | pt    XXX could be folded in the size... bug 90440

  2) attributes for generic fonts --------------------------------------
  font.default = serif | sans-serif - fallback generic font
  font.name.[generic].[langGroup] = current user' selected font on the pref dialog
  font.name-list.[generic].[langGroup] = fontname1, fontname2, ... [factory pre-built list]
  font.size.[generic].[langGroup] = integer - settable by the user
  font.size-adjust.[generic].[langGroup] = "float" - settable by the user
  font.minimum-size.[langGroup] = integer - settable by the user
  */

  float p2t = ScaledPixelsToTwips();
  mDefaultVariableFont.size = NSFloatPixelsToTwips((float)16, p2t);
  mDefaultFixedFont.size = NSFloatPixelsToTwips((float)13, p2t);

  const char *langGroup;
  mLangGroup->GetUTF8String(&langGroup);

  nsCAutoString pref;

  // get the current applicable font-size unit
  enum {eUnit_unknown = -1, eUnit_px, eUnit_pt};
  PRInt32 unit = eUnit_px;

  nsAdoptingCString cvalue =
    nsContentUtils::GetCharPref("font.size.unit");

  if (!cvalue.IsEmpty()) {
    if (cvalue.Equals("px")) {
      unit = eUnit_px;
    }
    else if (cvalue.Equals("pt")) {
      unit = eUnit_pt;
    }
    else {
      NS_WARNING("unexpected font-size unit -- expected: 'px' or 'pt'");
      unit = eUnit_unknown;
    }
  }

  // get font.minimum-size.[langGroup]

  pref.Assign("font.minimum-size.");
  pref.Append(langGroup);

  PRInt32 size = nsContentUtils::GetIntPref(pref.get());
  if (size > 0) {
    if (unit == eUnit_px) {
      mMinimumFontSize = NSFloatPixelsToTwips((float)size, p2t);
    }
    else if (unit == eUnit_pt) {
      mMinimumFontSize = NSIntPointsToTwips(size);
    }
  }

  // get attributes specific to each generic font
  nsCAutoString generic_dot_langGroup;
  for (PRInt32 eType = eDefaultFont_Variable; eType < eDefaultFont_COUNT; ++eType) {
    generic_dot_langGroup.Assign(kGenericFont[eType]);
    generic_dot_langGroup.Append(langGroup);

    nsFont* font;
    switch (eType) {
      case eDefaultFont_Variable:  font = &mDefaultVariableFont;  break;
      case eDefaultFont_Fixed:     font = &mDefaultFixedFont;     break;
      case eDefaultFont_Serif:     font = &mDefaultSerifFont;     break;
      case eDefaultFont_SansSerif: font = &mDefaultSansSerifFont; break;
      case eDefaultFont_Monospace: font = &mDefaultMonospaceFont; break;
      case eDefaultFont_Cursive:   font = &mDefaultCursiveFont;   break;
      case eDefaultFont_Fantasy:   font = &mDefaultFantasyFont;   break;
    }

    // set the default variable font (the other fonts are seen as 'generic' fonts
    // in GFX and will be queried there when hunting for alternative fonts)
    if (eType == eDefaultFont_Variable) {
      MAKE_FONT_PREF_KEY(pref, "font.name", generic_dot_langGroup);

      nsAdoptingString value =
        nsContentUtils::GetStringPref(pref.get());
      if (!value.IsEmpty()) {
        font->name.Assign(value);
      }
      else {
        MAKE_FONT_PREF_KEY(pref, "font.default.", langGroup);
        value = nsContentUtils::GetStringPref(pref.get());
        if (!value.IsEmpty()) {
          mDefaultVariableFont.name.Assign(value);
        }
      } 
    }
    else {
      if (eType == eDefaultFont_Monospace) {
        // This takes care of the confusion whereby people often expect "monospace" 
        // to have the same default font-size as "-moz-fixed" (this tentative
        // size may be overwritten with the specific value for "monospace" when
        // "font.size.monospace.[langGroup]" is read -- see below)
        font->size = mDefaultFixedFont.size;
      }
      else if (eType != eDefaultFont_Fixed) {
        // all the other generic fonts are initialized with the size of the
        // variable font, but their specific size can supersede later -- see below
        font->size = mDefaultVariableFont.size;
      }
    }

    // Bug 84398: for spec purists, a different font-size only applies to the
    // .variable. and .fixed. fonts and the other fonts should get |font-size-adjust|.
    // The problem is that only GfxWin has the support for |font-size-adjust|. So for
    // parity, we enable the ability to set a different font-size on all platforms.

    // get font.size.[generic].[langGroup]
    // size=0 means 'Auto', i.e., generic fonts retain the size of the variable font
    MAKE_FONT_PREF_KEY(pref, "font.size", generic_dot_langGroup);
    size = nsContentUtils::GetIntPref(pref.get());
    if (size > 0) {
      if (unit == eUnit_px) {
        font->size = NSFloatPixelsToTwips((float)size, p2t);
      }
      else if (unit == eUnit_pt) {
        font->size = NSIntPointsToTwips(size);
      }
    }

    // get font.size-adjust.[generic].[langGroup]
    // XXX only applicable on GFX ports that handle |font-size-adjust|
    MAKE_FONT_PREF_KEY(pref, "font.size-adjust", generic_dot_langGroup);
    cvalue = nsContentUtils::GetCharPref(pref.get());
    if (!cvalue.IsEmpty()) {
      font->sizeAdjust = (float)atof(cvalue.get());
    }

#ifdef DEBUG_rbs
    printf("%s Family-list:%s size:%d sizeAdjust:%.2f\n",
           generic_dot_langGroup.get(),
           NS_ConvertUCS2toUTF8(font->name).get(), font->size,
           font->sizeAdjust);
#endif
  }
}

void
nsPresContext::GetDocumentColorPreferences()
{
  PRInt32 useAccessibilityTheme = 0;
  PRBool usePrefColors = PR_TRUE;
  nsCOMPtr<nsIDocShellTreeItem> docShell(do_QueryReferent(mContainer));
  if (docShell) {
    PRInt32 docShellType;
    docShell->GetItemType(&docShellType);
    if (nsIDocShellTreeItem::typeChrome == docShellType) {
      usePrefColors = PR_FALSE;
    }
    else {
      mLookAndFeel->GetMetric(nsILookAndFeel::eMetric_UseAccessibilityTheme, useAccessibilityTheme);
      usePrefColors = !useAccessibilityTheme;
    }

  }
  if (usePrefColors) {
    usePrefColors =
      !nsContentUtils::GetBoolPref("browser.display.use_system_colors",
                                   PR_FALSE);
  }

  if (usePrefColors) {
    nsAdoptingCString colorStr =
      nsContentUtils::GetCharPref("browser.display.foreground_color");

    if (!colorStr.IsEmpty()) {
      mDefaultColor = MakeColorPref(colorStr);
    }

    colorStr =
      nsContentUtils::GetCharPref("browser.display.background_color");

    if (!colorStr.IsEmpty()) {
      mBackgroundColor = MakeColorPref(colorStr);
    }
  }
  else {
    mDefaultColor = NS_RGB(0x00, 0x00, 0x00);
    mBackgroundColor = NS_RGB(0xFF, 0xFF, 0xFF);
    mLookAndFeel->GetColor(nsILookAndFeel::eColor_WindowForeground,
                           mDefaultColor);
    mLookAndFeel->GetColor(nsILookAndFeel::eColor_WindowBackground,
                           mBackgroundColor);
  }

  mUseDocumentColors = !useAccessibilityTheme &&
    nsContentUtils::GetBoolPref("browser.display.use_document_colors",
                                mUseDocumentColors);
}

void
nsPresContext::GetUserPreferences()
{
  mFontScaler =
    nsContentUtils::GetIntPref("browser.display.base_font_scaler",
                               mFontScaler);

  // * document colors
  GetDocumentColorPreferences();

  // * link colors
  mUnderlineLinks =
    nsContentUtils::GetBoolPref("browser.underline_anchors", mUnderlineLinks);

  nsAdoptingCString colorStr =
    nsContentUtils::GetCharPref("browser.anchor_color");

  if (!colorStr.IsEmpty()) {
    mLinkColor = MakeColorPref(colorStr);
  }

  colorStr =
    nsContentUtils::GetCharPref("browser.active_color");

  if (!colorStr.IsEmpty()) {
    mActiveLinkColor = MakeColorPref(colorStr);
  }

  colorStr = nsContentUtils::GetCharPref("browser.visited_color");

  if (!colorStr.IsEmpty()) {
    mVisitedLinkColor = MakeColorPref(colorStr);
  }

  mUseFocusColors =
    nsContentUtils::GetBoolPref("browser.display.use_focus_colors",
                                mUseFocusColors);

  mFocusTextColor = mDefaultColor;
  mFocusBackgroundColor = mBackgroundColor;

  colorStr = nsContentUtils::GetCharPref("browser.display.focus_text_color");

  if (!colorStr.IsEmpty()) {
    mFocusTextColor = MakeColorPref(colorStr);
  }

  colorStr =
    nsContentUtils::GetCharPref("browser.display.focus_background_color");

  if (!colorStr.IsEmpty()) {
    mFocusBackgroundColor = MakeColorPref(colorStr);
  }

  mFocusRingWidth =
    nsContentUtils::GetIntPref("browser.display.focus_ring_width",
                               mFocusRingWidth);

  mFocusRingOnAnything =
    nsContentUtils::GetBoolPref("browser.display.focus_ring_on_anything",
                                mFocusRingOnAnything);

  // * use fonts?
  mUseDocumentFonts =
    nsContentUtils::GetIntPref("browser.display.use_document_fonts") != 0;

  // * replace backslashes with Yen signs? (bug 245770)
  mEnableJapaneseTransform =
    nsContentUtils::GetBoolPref("layout.enable_japanese_specific_transform");

  GetFontPreferences();

  // * image animation
  const nsAdoptingCString& animatePref =
    nsContentUtils::GetCharPref("image.animation_mode");
  if (animatePref.Equals("normal"))
    mImageAnimationModePref = imgIContainer::kNormalAnimMode;
  else if (animatePref.Equals("none"))
    mImageAnimationModePref = imgIContainer::kDontAnimMode;
  else if (animatePref.Equals("once"))
    mImageAnimationModePref = imgIContainer::kLoopOnceAnimMode;

#ifdef MOZ_DNSSEC
  PR_set_dnssec_validate_policy(nsContentUtils::GetIntPref("security.dnssec.dnssecBehavior"));
#endif /* MOZ_DNSSEC */


#ifdef IBMBIDI
  PRUint32 bidiOptions = mBidi;

  PRInt32 prefInt =
    nsContentUtils::GetIntPref("bidi.direction",
                               GET_BIDI_OPTION_DIRECTION(bidiOptions));
  SET_BIDI_OPTION_DIRECTION(bidiOptions, prefInt);

  prefInt =
    nsContentUtils::GetIntPref("bidi.texttype",
                               GET_BIDI_OPTION_TEXTTYPE(bidiOptions));
  SET_BIDI_OPTION_TEXTTYPE(bidiOptions, prefInt);

  prefInt =
    nsContentUtils::GetIntPref("bidi.controlstextmode",
                               GET_BIDI_OPTION_CONTROLSTEXTMODE(bidiOptions));
  SET_BIDI_OPTION_CONTROLSTEXTMODE(bidiOptions, prefInt);

  prefInt =
    nsContentUtils::GetIntPref("bidi.numeral",
                               GET_BIDI_OPTION_NUMERAL(bidiOptions));
  SET_BIDI_OPTION_NUMERAL(bidiOptions, prefInt);

  prefInt =
    nsContentUtils::GetIntPref("bidi.support",
                               GET_BIDI_OPTION_SUPPORT(bidiOptions));
  SET_BIDI_OPTION_SUPPORT(bidiOptions, prefInt);

  prefInt =
    nsContentUtils::GetIntPref("bidi.characterset",
                               GET_BIDI_OPTION_CHARACTERSET(bidiOptions));
  SET_BIDI_OPTION_CHARACTERSET(bidiOptions, prefInt);

  // We don't need to force reflow: either we are initializing a new
  // prescontext or we are being called from UpdateAfterPreferencesChanged()
  // which triggers a reflow anyway.
  SetBidi(bidiOptions, PR_FALSE);
#endif
}

void
nsPresContext::ClearStyleDataAndReflow()
{
  if (mShell) {
    // Clear out all our style data.
    mShell->StyleSet()->ClearStyleData(this);

    // Force a reflow of the root frame
    // XXX We really should only do a reflow if a preference that affects
    // formatting changed, e.g., a font change. If it's just a color change
    // then we only need to repaint...
    mShell->StyleChangeReflow();
  }
}

void
nsPresContext::PreferenceChanged(const char* aPrefName)
{
  // we use a zero-delay timer to coalesce multiple pref updates
  if (!mPrefChangedTimer)
  {
    mPrefChangedTimer = do_CreateInstance("@mozilla.org/timer;1");
    if (!mPrefChangedTimer)
      return;
    mPrefChangedTimer->InitWithFuncCallback(nsPresContext::PrefChangedUpdateTimerCallback, (void*)this, 0, nsITimer::TYPE_ONE_SHOT);
  }
}

void
nsPresContext::UpdateAfterPreferencesChanged()
{
  mPrefChangedTimer = nsnull;

  nsCOMPtr<nsIDocShellTreeItem> docShell(do_QueryReferent(mContainer));
  if (docShell) {
    PRInt32 docShellType;
    docShell->GetItemType(&docShellType);
    if (nsIDocShellTreeItem::typeChrome == docShellType)
      return;
  }

  // Initialize our state from the user preferences
  GetUserPreferences();

  // update the presShell: tell it to set the preference style rules up
  if (mShell) {
    mShell->SetPreferenceStyleRules(PR_TRUE);
  }

  mDeviceContext->FlushFontCache();
  ClearStyleDataAndReflow();
}

nsresult
nsPresContext::Init(nsIDeviceContext* aDeviceContext)
{
  NS_ASSERTION(!(mInitialized == PR_TRUE), "attempt to reinit pres context");
  NS_ENSURE_ARG(aDeviceContext);

  mDeviceContext = aDeviceContext;
  NS_ADDREF(mDeviceContext);

  // Get the look and feel service here; default colors will be initialized
  // from calling GetUserPreferences() below.
  nsresult rv = CallGetService(kLookAndFeelCID, &mLookAndFeel);
  if (NS_FAILED(rv)) {
    NS_ERROR("LookAndFeel service must be implemented for this toolkit");
    return rv;
  }

  mEventManager = new nsEventStateManager();
  if (!mEventManager)
    return NS_ERROR_OUT_OF_MEMORY;

  NS_ADDREF(mEventManager);

  mLangService = do_GetService(NS_LANGUAGEATOMSERVICE_CONTRACTID);

  // Register callbacks so we're notified when the preferences change
  nsContentUtils::RegisterPrefCallback("font.",
                                       nsPresContext::PrefChangedCallback,
                                       this);
  nsContentUtils::RegisterPrefCallback("browser.display.",
                                       nsPresContext::PrefChangedCallback,
                                       this);
  nsContentUtils::RegisterPrefCallback("browser.underline_anchors",
                                       nsPresContext::PrefChangedCallback,
                                       this);
  nsContentUtils::RegisterPrefCallback("browser.anchor_color",
                                       nsPresContext::PrefChangedCallback,
                                       this);
  nsContentUtils::RegisterPrefCallback("browser.active_color",
                                       nsPresContext::PrefChangedCallback,
                                       this);
  nsContentUtils::RegisterPrefCallback("browser.visited_color",
                                       nsPresContext::PrefChangedCallback,
                                       this);
  nsContentUtils::RegisterPrefCallback("image.animation_mode",
                                       nsPresContext::PrefChangedCallback,
                                       this);
#ifdef MOZ_DNSSEC
  nsContentUtils::RegisterPrefCallback("security.dnssec.dnssecBehavior",
                                       nsPresContext::PrefChangedCallback,
                                       this);
#endif
#ifdef IBMBIDI
  nsContentUtils::RegisterPrefCallback("bidi.", PrefChangedCallback,
                                       this);
#endif

  rv = CallGetService(NS_EVENTQUEUESERVICE_CONTRACTID, &mEventQueueService);
  NS_ENSURE_SUCCESS(rv, rv);

  // Initialize our state from the user preferences
  GetUserPreferences();

  rv = mEventManager->Init();
  NS_ENSURE_SUCCESS(rv, rv);

  mEventManager->SetPresContext(this);

#ifdef DEBUG
  mInitialized = PR_TRUE;
#endif

  float pixelsToTwips = PixelsToTwips();
  mBorderWidthTable[NS_STYLE_BORDER_WIDTH_THIN] = NSIntPixelsToTwips(1, pixelsToTwips);
  mBorderWidthTable[NS_STYLE_BORDER_WIDTH_MEDIUM] = NSIntPixelsToTwips(3, pixelsToTwips);
  mBorderWidthTable[NS_STYLE_BORDER_WIDTH_THICK] = NSIntPixelsToTwips(5, pixelsToTwips);

  return NS_OK;
}

// Note: We don't hold a reference on the shell; it has a reference to
// us
void
nsPresContext::SetShell(nsIPresShell* aShell)
{
  if (mShell) {
    // Remove ourselves as the charset observer from the shell's doc, because
    // this shell may be going away for good.
    nsIDocument *doc = mShell->GetDocument();
    if (doc) {
      doc->RemoveCharSetObserver(this);
    }
  }    

  mShell = aShell;

  if (mShell) {
    nsIDocument *doc = mShell->GetDocument();
    NS_ASSERTION(doc, "expect document here");
    if (doc) {
      nsIURI *docURI = doc->GetDocumentURI();

      if (mMedium != nsLayoutAtoms::print && docURI) {
        PRBool isChrome = PR_FALSE;
        PRBool isRes = PR_FALSE;
        docURI->SchemeIs("chrome", &isChrome);
        docURI->SchemeIs("resource", &isRes);

        if (!isChrome && !isRes)
          mImageAnimationMode = mImageAnimationModePref;
        else
          mImageAnimationMode = imgIContainer::kNormalAnimMode;
      }

      if (mLangService) {
        doc->AddCharSetObserver(this);
        UpdateCharSet(doc->GetDocumentCharacterSet());
      }
    }
  }
}

void
nsPresContext::UpdateCharSet(const nsAFlatCString& aCharSet)
{
  if (mLangService) {
    NS_IF_RELEASE(mLangGroup);
    mLangGroup = mLangService->LookupCharSet(aCharSet.get()).get();  // addrefs

    if (mLangGroup == nsLayoutAtoms::Japanese && mEnableJapaneseTransform) {
      mLanguageSpecificTransformType =
        eLanguageSpecificTransformType_Japanese;
    }
    else {
      mLanguageSpecificTransformType =
        eLanguageSpecificTransformType_None;
    }
    // bug 39570: moved from nsLanguageAtomService::LookupCharSet()
#if !defined(XP_BEOS) 
    if (mLangGroup == nsLayoutAtoms::Unicode) {
      NS_RELEASE(mLangGroup);
      NS_IF_ADDREF(mLangGroup = mLangService->GetLocaleLanguageGroup()); 
    }
#endif
    GetFontPreferences();
  }
#ifdef IBMBIDI
  //ahmed

  switch (GET_BIDI_OPTION_TEXTTYPE(mBidi)) {

    case IBMBIDI_TEXTTYPE_LOGICAL:
      SetVisualMode(PR_FALSE);
      break;

    case IBMBIDI_TEXTTYPE_VISUAL:
      SetVisualMode(PR_TRUE);
      break;

    case IBMBIDI_TEXTTYPE_CHARSET:
    default:
      SetVisualMode(IsVisualCharset(aCharSet));
  }
#endif // IBMBIDI
}

NS_IMETHODIMP
nsPresContext::Observe(nsISupports* aSubject, 
                        const char* aTopic,
                        const PRUnichar* aData)
{
  if (!nsCRT::strcmp(aTopic, "charset")) {
    UpdateCharSet(NS_LossyConvertUCS2toASCII(aData));
    mDeviceContext->FlushFontCache();
    ClearStyleDataAndReflow();

    return NS_OK;
  }

  NS_WARNING("unrecognized topic in nsPresContext::Observe");
  return NS_ERROR_FAILURE;
}

void
nsPresContext::SetCompatibilityMode(nsCompatibility aMode)
{
  mCompatibilityMode = aMode;

  if (!mShell)
    return;

  // enable/disable the QuirkSheet
  mShell->StyleSet()->
    EnableQuirkStyleSheet(mCompatibilityMode == eCompatibility_NavQuirks);
}

// Helper function for setting Anim Mode on image
static void SetImgAnimModeOnImgReq(imgIRequest* aImgReq, PRUint16 aMode)
{
  if (aImgReq) {
    nsCOMPtr<imgIContainer> imgCon;
    aImgReq->GetImage(getter_AddRefs(imgCon));
    if (imgCon) {
      imgCon->SetAnimationMode(aMode);
    }
  }
}

 // Enumeration call back for HashTable
PR_STATIC_CALLBACK(PRBool) set_animation_mode(nsHashKey *aKey, void *aData, void* closure)
{
  nsISupports *sup = NS_REINTERPRET_CAST(nsISupports*, aData);
  nsImageLoader *loader = NS_REINTERPRET_CAST(nsImageLoader*, sup);
  imgIRequest* imgReq = loader->GetRequest();
  SetImgAnimModeOnImgReq(imgReq, (PRUint16)NS_PTR_TO_INT32(closure));
  return PR_TRUE;
}

// IMPORTANT: Assumption is that all images for a Presentation 
// have the same Animation Mode (pavlov said this was OK)
//
// Walks content and set the animation mode
// this is a way to turn on/off image animations
void nsPresContext::SetImgAnimations(nsIContent *aParent, PRUint16 aMode)
{
  nsCOMPtr<nsIImageLoadingContent> imgContent(do_QueryInterface(aParent));
  if (imgContent) {
    nsCOMPtr<imgIRequest> imgReq;
    imgContent->GetRequest(nsIImageLoadingContent::CURRENT_REQUEST,
                           getter_AddRefs(imgReq));
    SetImgAnimModeOnImgReq(imgReq, aMode);
  }
  
  PRUint32 count = aParent->GetChildCount();
  for (PRUint32 i = 0; i < count; ++i) {
    SetImgAnimations(aParent->GetChildAt(i), aMode);
  }
}

void
nsPresContext::SetImageAnimationModeInternal(PRUint16 aMode)
{
  NS_ASSERTION(aMode == imgIContainer::kNormalAnimMode ||
               aMode == imgIContainer::kDontAnimMode ||
               aMode == imgIContainer::kLoopOnceAnimMode, "Wrong Animation Mode is being set!");

  // Image animation mode cannot be changed when rendering to a printer.
  if (mMedium == nsLayoutAtoms::print)
    return;

  // This hash table contains a list of background images
  // so iterate over it and set the mode
  mImageLoaders.Enumerate(set_animation_mode, NS_INT32_TO_PTR(aMode));

  // Now walk the content tree and set the animation mode 
  // on all the images
  if (mShell != nsnull) {
    nsIDocument *doc = mShell->GetDocument();
    if (doc) {
      nsIContent *rootContent = doc->GetRootContent();
      if (rootContent) {
        SetImgAnimations(rootContent, aMode);
      }
    }
  }

  mImageAnimationMode = aMode;
}

void
nsPresContext::SetImageAnimationModeExternal(PRUint16 aMode)
{
  SetImageAnimationModeInternal(aMode);
}

already_AddRefed<nsIFontMetrics>
nsPresContext::GetMetricsForInternal(const nsFont& aFont)
{
  nsIFontMetrics* metrics = nsnull;
  mDeviceContext->GetMetricsFor(aFont, mLangGroup, metrics);
  return metrics;
}

already_AddRefed<nsIFontMetrics>
nsPresContext::GetMetricsForExternal(const nsFont& aFont)
{
  return GetMetricsForInternal(aFont);
}

const nsFont*
nsPresContext::GetDefaultFontInternal(PRUint8 aFontID) const
{
  const nsFont *font;
  switch (aFontID) {
    // Special (our default variable width font and fixed width font)
    case kPresContext_DefaultVariableFont_ID:
      font = &mDefaultVariableFont;
      break;
    case kPresContext_DefaultFixedFont_ID:
      font = &mDefaultFixedFont;
      break;
    // CSS
    case kGenericFont_serif:
      font = &mDefaultSerifFont;
      break;
    case kGenericFont_sans_serif:
      font = &mDefaultSansSerifFont;
      break;
    case kGenericFont_monospace:
      font = &mDefaultMonospaceFont;
      break;
    case kGenericFont_cursive:
      font = &mDefaultCursiveFont;
      break;
    case kGenericFont_fantasy: 
      font = &mDefaultFantasyFont;
      break;
    default:
      font = nsnull;
      NS_ERROR("invalid arg");
      break;
  }
  return font;
}

const nsFont*
nsPresContext::GetDefaultFontExternal(PRUint8 aFontID) const
{
  return GetDefaultFontInternal(aFontID);
}

float
nsPresContext::TwipsToPixelsForFonts() const
{
  float app2dev;
#ifdef NS_PRINT_PREVIEW
  // If an alternative DC is available we want to use
  // it to get the scaling factor for fonts. Usually, the AltDC
  // is a printing DC so therefore we need to get the printers
  // scaling values for calculating the font heights
  nsCOMPtr<nsIDeviceContext> altDC;
  mDeviceContext->GetAltDevice(getter_AddRefs(altDC));
  if (altDC) {
    app2dev = altDC->AppUnitsToDevUnits();
  } else {
    app2dev = mDeviceContext->AppUnitsToDevUnits();
  }
#else
  app2dev = mDeviceContext->AppUnitsToDevUnits();
#endif
  return app2dev;
}



float
nsPresContext::ScaledPixelsToTwips() const
{
  float scale;
  float p2t;

  p2t = mDeviceContext->DevUnitsToAppUnits();
  if (mDoScaledTwips) {
    mDeviceContext->GetCanonicalPixelScale(scale);
    scale = p2t * scale;
  } else {
    scale = p2t;
  }

  return scale;
}

void
nsPresContext::SetTextZoomExternal(float aZoom)
{
  SetTextZoomInternal(aZoom);
}

imgIRequest*
nsPresContext::LoadImage(imgIRequest* aImage, nsIFrame* aTargetFrame)
{
  // look and see if we have a loader for the target frame.

  nsVoidKey key(aTargetFrame);
  nsImageLoader *loader = NS_REINTERPRET_CAST(nsImageLoader*, mImageLoaders.Get(&key)); // addrefs

  if (!loader) {
    loader = new nsImageLoader();
    if (!loader)
      return nsnull;

    NS_ADDREF(loader); // new

    loader->Init(aTargetFrame, this);
    mImageLoaders.Put(&key, loader);
  }

  loader->Load(aImage);

  imgIRequest *request = loader->GetRequest();
  NS_RELEASE(loader);

  return request;
}


void
nsPresContext::StopImagesFor(nsIFrame* aTargetFrame)
{
  nsVoidKey key(aTargetFrame);
  nsImageLoader *loader = NS_REINTERPRET_CAST(nsImageLoader*, mImageLoaders.Get(&key)); // addrefs

  if (loader) {
    loader->Destroy();
    NS_RELEASE(loader);

    mImageLoaders.Remove(&key);
  }
}


void
nsPresContext::SetContainer(nsISupports* aHandler)
{
  mContainer = do_GetWeakReference(aHandler);
  if (mContainer) {
    GetDocumentColorPreferences();
  }
}

already_AddRefed<nsISupports>
nsPresContext::GetContainerInternal()
{
  nsISupports *result;
  if (mContainer)
    CallQueryReferent(mContainer.get(), &result);
  else
    result = nsnull;

  return result;
}

already_AddRefed<nsISupports>
nsPresContext::GetContainerExternal()
{
  return GetContainerInternal();
}

#ifdef IBMBIDI
PRBool
nsPresContext::BidiEnabledInternal() const
{
  PRBool bidiEnabled = PR_FALSE;
  NS_ASSERTION(mShell, "PresShell must be set on PresContext before calling nsPresContext::GetBidiEnabled");
  if (mShell) {
    nsIDocument *doc = mShell->GetDocument();
    NS_ASSERTION(doc, "PresShell has no document in nsPresContext::GetBidiEnabled");
    if (doc) {
      bidiEnabled = doc->GetBidiEnabled();
    }
  }
  return bidiEnabled;
}

PRBool
nsPresContext::BidiEnabledExternal() const
{
  return BidiEnabledInternal();
}

void
nsPresContext::SetBidiEnabled(PRBool aBidiEnabled) const
{
  if (mShell) {
    nsIDocument *doc = mShell->GetDocument();
    if (doc) {
      doc->SetBidiEnabled(aBidiEnabled);
    }
  }
}

nsBidiPresUtils*
nsPresContext::GetBidiUtils()
{
  if (!mBidiUtils)
    mBidiUtils = new nsBidiPresUtils;

  return mBidiUtils;
}

void
nsPresContext::SetBidi(PRUint32 aSource, PRBool aForceReflow)
{
  // Don't do all this stuff if the options haven't changed
  if (aSource == mBidi) {
    return;
  }

  NS_ASSERTION(!(aForceReflow && (mBidi == 0)), 
               "ForceReflow on new prescontext");

  mBidi = aSource;
  if (IBMBIDI_TEXTDIRECTION_RTL == GET_BIDI_OPTION_DIRECTION(mBidi)
      || IBMBIDI_NUMERAL_HINDI == GET_BIDI_OPTION_NUMERAL(mBidi)) {
    SetBidiEnabled(PR_TRUE);
  }
  if (IBMBIDI_TEXTTYPE_VISUAL == GET_BIDI_OPTION_TEXTTYPE(mBidi)) {
    SetVisualMode(PR_TRUE);
  }
  else if (IBMBIDI_TEXTTYPE_LOGICAL == GET_BIDI_OPTION_TEXTTYPE(mBidi)) {
    SetVisualMode(PR_FALSE);
  }
  else {
    if (mShell) {
      nsIDocument* doc = mShell->GetDocument();
      if (doc) {
        SetVisualMode(IsVisualCharset(doc->GetDocumentCharacterSet()));
      }
    }
  }
  if (aForceReflow) {
    ClearStyleDataAndReflow();
  }
}
#endif //IBMBIDI

nsITheme*
nsPresContext::GetTheme()
{
  if (!mNoTheme && !mTheme) {
    mTheme = do_GetService("@mozilla.org/chrome/chrome-native-theme;1");
    if (!mTheme)
      mNoTheme = PR_TRUE;
  }

  return mTheme;
}

void
nsPresContext::ThemeChanged()
{
  if (!mPendingThemeChanged) {
    sLookAndFeelChanged = PR_TRUE;
    sThemeChanged = PR_TRUE;

    nsCOMPtr<nsIEventQueue> eventQ;
    mEventQueueService->
      GetSpecialEventQueue(nsIEventQueueService::UI_THREAD_EVENT_QUEUE,
                           getter_AddRefs(eventQ));
    if (!eventQ) {
      return;
    }

    PLEvent* evt = new PLEvent();
    if (!evt) {
      return;
    }

    PL_InitEvent(evt, this, nsPresContext::ThemeChangedInternal,
                 nsPresContext::DestroyThemeChangeEvt);

    // After this point, event destruction will release |this|
    NS_ADDREF_THIS();

    nsresult rv = eventQ->PostEvent(evt);
    if (NS_FAILED(rv)) {
      PL_DestroyEvent(evt);
    } else {
      mPendingThemeChanged = PR_TRUE;
    }
  }    
}

void* PR_CALLBACK
nsPresContext::ThemeChangedInternal(PLEvent *aEvent)
{
  nsPresContext* pc = NS_STATIC_CAST(nsPresContext*, aEvent->owner);

  pc->mPendingThemeChanged = PR_FALSE;

  // Tell the theme that it changed, so it can flush any handles to stale theme
  // data.
  if (pc->mTheme && sThemeChanged) {
    pc->mTheme->ThemeChanged();
    sThemeChanged = PR_FALSE;
  }

  // Clear all cached nsILookAndFeel colors.
  if (pc->mLookAndFeel && sLookAndFeelChanged) {
    pc->mLookAndFeel->LookAndFeelChanged();
    sLookAndFeelChanged = PR_FALSE;
  }

  // We have to clear style data because the assumption of style rule
  // immutability has been violated since any style rule that uses
  // system colors or fonts (and probably -moz-appearance as well) has
  // changed.
  pc->ClearStyleDataAndReflow();

  return nsnull;
}


void PR_CALLBACK
nsPresContext::DestroyThemeChangeEvt(PLEvent* aEvent)
{
  nsPresContext* pc = NS_STATIC_CAST(nsPresContext*, aEvent->owner);
  NS_RELEASE(pc);
  delete aEvent;
}

void
nsPresContext::SysColorChanged()
{
  if (!mPendingSysColorChanged) {
    sLookAndFeelChanged = PR_TRUE;

    nsCOMPtr<nsIEventQueue> eventQ;
    mEventQueueService->
      GetSpecialEventQueue(nsIEventQueueService::UI_THREAD_EVENT_QUEUE,
                           getter_AddRefs(eventQ));
    if (!eventQ) {
      return;
    }

    PLEvent* evt = new PLEvent();
    if (!evt) {
      return;
    }

    PL_InitEvent(evt, this, nsPresContext::SysColorChangedInternal,
                 nsPresContext::DestroySysColorChangeEvt);

    // After this point, event destruction will release |this|
    NS_ADDREF_THIS();

    nsresult rv = eventQ->PostEvent(evt);
    if (NS_FAILED(rv)) {
      PL_DestroyEvent(evt);
    } else {
      mPendingSysColorChanged = PR_TRUE;
    }
  }
}

void* PR_CALLBACK
nsPresContext::SysColorChangedInternal(PLEvent *aEvent)
{
  nsPresContext* pc = NS_STATIC_CAST(nsPresContext*, aEvent->owner);

  pc->mPendingSysColorChanged = PR_FALSE;
  
  if (pc->mLookAndFeel && sLookAndFeelChanged) {
     // Don't use the cached values for the system colors
    pc->mLookAndFeel->LookAndFeelChanged();
    sLookAndFeelChanged = PR_FALSE;
  }

  // Reset default background and foreground colors for the document since
  // they may be using system colors
  pc->GetDocumentColorPreferences();

  // Clear out all of the style data since it may contain RGB values
  // which originated from system colors.
  nsCOMPtr<nsISelectionImageService> imageService;
  nsresult result;
  imageService = do_GetService(kSelectionImageService, &result);
  if (NS_SUCCEEDED(result) && imageService)
  {
    imageService->Reset();
  }

  // We need to do a full reflow (and view update) here. Clearing the style
  // data without reflowing/updating views will lead to incorrect change hints
  // later, because when generating change hints, any style structs which have
  // been cleared and not reread are assumed to not be used at all.
  pc->ClearStyleDataAndReflow();

  return nsnull;
}

void PR_CALLBACK
nsPresContext::DestroySysColorChangeEvt(PLEvent* aEvent)
{
  nsPresContext* pc = NS_STATIC_CAST(nsPresContext*, aEvent->owner);
  NS_RELEASE(pc);
  delete aEvent;
}

void
nsPresContext::GetPageDim(nsRect* aActualRect, nsRect* aAdjRect)
{
  if (mMedium == nsLayoutAtoms::print) {
    if (aActualRect) {
      PRInt32 width, height;
      nsresult rv = mDeviceContext->GetDeviceSurfaceDimensions(width, height);
      if (NS_SUCCEEDED(rv))
        aActualRect->SetRect(0, 0, width, height);
    }
    if (aAdjRect)
      *aAdjRect = mPageDim;
  } else {
    if (aActualRect)
      aActualRect->SetRect(0, 0, 0, 0);
    if (aAdjRect)
      aAdjRect->SetRect(0, 0, 0, 0);
  }
}

void
nsPresContext::SetPageDim(const nsRect& aPageDim)
{
  if (mMedium == nsLayoutAtoms::print)
    mPageDim = aPageDim;
}

void
nsPresContext::SetPaginatedScrolling(PRBool aPaginated)
{
  if (mType == eContext_PrintPreview)
    mCanPaginatedScroll = aPaginated;
}

void
nsPresContext::SetPrintSettings(nsIPrintSettings *aPrintSettings)
{
  if (mMedium == nsLayoutAtoms::print)
    mPrintSettings = aPrintSettings;
}

PRBool
nsPresContext::EnsureVisible(PRBool aUnsuppressFocus)
{
  nsCOMPtr<nsIDocShell> docShell(do_QueryReferent(mContainer));
  if (docShell) {
    nsCOMPtr<nsIContentViewer> cv;
    docShell->GetContentViewer(getter_AddRefs(cv));
    // Make sure this is the content viewer we belong with
    nsCOMPtr<nsIDocumentViewer> docV(do_QueryInterface(cv));
    if (docV) {
      nsCOMPtr<nsPresContext> currentPresContext;
      docV->GetPresContext(getter_AddRefs(currentPresContext));
      if (currentPresContext == this) {
        // OK, this is us.  We want to call Show() on the content viewer.  But
        // first, we need to suppress focus changes; otherwise the focus will
        // get sent to the wrong place (toplevel window).
        nsCOMPtr<nsPIDOMWindow> privWindow = do_GetInterface(docShell);
        // XXXbz privWindow should never really be null!
        nsIFocusController* fc =
          privWindow ? privWindow->GetRootFocusController() : nsnull;
        if (fc) {
          fc->SetSuppressFocus(PR_TRUE,
                               "nsPresContext::EnsureVisible Suppression");
        }
        cv->Show();
        if (fc && aUnsuppressFocus) {
          fc->SetSuppressFocus(PR_FALSE,
                               "nsPresContext::EnsureVisible Suppression");
        }
        return PR_TRUE;
      }
    }
  }
  return PR_FALSE;
}

nsresult
NS_NewPresContext(nsPresContext::nsPresContextType aType,
                  nsPresContext** aInstancePtrResult)
{
  nsPresContext *context = new nsPresContext(aType);
  if (!context)
    return NS_ERROR_OUT_OF_MEMORY;

  NS_ADDREF(*aInstancePtrResult = context);
  return NS_OK;
}

#ifdef MOZ_REFLOW_PERF
void
nsPresContext::CountReflows(const char * aName,
                             PRUint32 aType, nsIFrame * aFrame)
{
  if (mShell) {
    mShell->CountReflows(aName, aType, aFrame);
  }
}

void
nsPresContext::PaintCount(const char * aName,
                           nsIRenderingContext* aRenderingContext,
                           nsIFrame * aFrame, PRUint32 aColor)
{
  if (mShell) {
    mShell->PaintCount(aName, aRenderingContext, this, aFrame, aColor);
  }
}
#endif
