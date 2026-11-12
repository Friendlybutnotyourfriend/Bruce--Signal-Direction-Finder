#pragma once
#include "core/display.h"
#include <globals.h>

namespace recon {
namespace ui {
#if defined(ES3C28P) && defined(USE_TFT_ESPI)
inline TFT_eSprite *frameBuffer() {
    static TFT_eSprite frame(tft.native());
    static int width = 0, height = 0;
    if (width != tftWidth || height != tftHeight) {
        frame.deleteSprite();
        frame.setColorDepth(16);
        if (!frame.createSprite(tftWidth, tftHeight)) return nullptr;
        width = tftWidth;
        height = tftHeight;
    }
    return &frame;
}
#endif

template <typename Paint> void renderFrame(Paint paint) {
    drawMainBorder(false);
#if defined(ES3C28P) && defined(USE_TFT_ESPI)
    if (auto *frame = frameBuffer()) {
        frame->fillSprite(bruceConfig.bgColor);
        frame->setTextDatum(0);
        frame->setTextSize(1);
        frame->setTextFont(1);
        paint(*frame);
        // Transfer only the body; keep the status bar, border and touch footer intact.
        frame->pushSprite(6, 26, 6, 26, tftWidth - 12, tftHeight - 32);
        return;
    }
#endif
    tft.fillRect(6, 26, tftWidth - 12, tftHeight - 32, bruceConfig.bgColor);
    tft.setTextSize(1);
    paint(tft);
}
} // namespace ui
} // namespace recon
