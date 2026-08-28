#include "DfMenu.h"

#include "core/utils.h"
#include "modules/df/ble_hunter.h"
#include <globals.h>

void DfMenu::optionsMenu() {
    options.clear();
    options.push_back({"BLE Hunter", []() { bleHunter(); }});

    addOptionToMainMenu();
    loopOptions(options, MENU_TYPE_SUBMENU, "Direction Finding", 0, false);
}

void DfMenu::drawIcon(float scale) {
    clearIconArea();

    const int radius = static_cast<int>(28 * scale);
    const int innerRadius = static_cast<int>(10 * scale);
    const int scaledLineWidth = static_cast<int>(3 * scale);
    const int lineWidth = scaledLineWidth < 2 ? 2 : scaledLineWidth;
    const int arm = static_cast<int>(42 * scale);
    const uint16_t color = bruceConfig.priColor;

    tft.drawCircle(iconCenterX, iconCenterY, radius, color);
    tft.drawCircle(iconCenterX, iconCenterY, innerRadius, color);

    tft.drawWideLine(
        iconCenterX - arm,
        iconCenterY,
        iconCenterX - innerRadius,
        iconCenterY,
        lineWidth,
        color,
        color
    );
    tft.drawWideLine(
        iconCenterX + innerRadius,
        iconCenterY,
        iconCenterX + arm,
        iconCenterY,
        lineWidth,
        color,
        color
    );
    tft.drawWideLine(
        iconCenterX,
        iconCenterY - arm,
        iconCenterX,
        iconCenterY - innerRadius,
        lineWidth,
        color,
        color
    );
    tft.drawWideLine(
        iconCenterX,
        iconCenterY + innerRadius,
        iconCenterX,
        iconCenterY + arm,
        lineWidth,
        color,
        color
    );

    const int scaledCenter = static_cast<int>(3 * scale);
    const int centerRadius = scaledCenter < 2 ? 2 : scaledCenter;
    tft.fillCircle(iconCenterX, iconCenterY, centerRadius, color);
}
