#ifndef __DF_MENU_H__
#define __DF_MENU_H__

#include <MenuItemInterface.h>

class DfMenu : public MenuItemInterface {
public:
    DfMenu() : MenuItemInterface("DF") {}

    void optionsMenu(void);
    void drawIcon(float scale);
    bool hasTheme() { return false; }
    String themePath() { return ""; }
};

#endif
