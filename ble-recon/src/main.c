/* BLE Recon V2 - direct USB CDC console, no Zephyr shell dependency */
#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/addr.h>
#include <zephyr/bluetooth/gap.h>
#include <zephyr/sys/util.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_DEVICES 48
#define LINE_MAX 96

struct seen_dev {
    bool used;
    bt_addr_le_t addr;
    char addr_str[BT_ADDR_LE_STR_LEN];
    int8_t last_rssi;
    int8_t min_rssi;
    int8_t max_rssi;
    int32_t rssi_sum;
    uint32_t packets;
    uint32_t adv_len;
    uint8_t adv_type;
    int64_t first_ms;
    int64_t last_ms;
};

static struct seen_dev devs[MAX_DEVICES];
K_MUTEX_DEFINE(dev_lock);
static bool scanning;
static bool active_scan = true;

static const struct device *const cdc = DEVICE_DT_GET(DT_CHOSEN(zephyr_console));

static void tx_char(char c)
{
    uart_poll_out(cdc, c);
}

static void tx(const char *s)
{
    while (*s) {
        tx_char(*s++);
    }
}

static void txln(const char *s)
{
    tx(s);
    tx("\r\n");
}

static const char *addr_class(const bt_addr_le_t *addr)
{
    if (addr->type == BT_ADDR_LE_PUBLIC) return "PUBLIC";
    if (addr->type == BT_ADDR_LE_PUBLIC_ID) return "PUBLIC_ID";
    if (addr->type == BT_ADDR_LE_RANDOM || addr->type == BT_ADDR_LE_RANDOM_ID ||
        addr->type == BT_ADDR_LE_UNRESOLVED) {
        uint8_t top = (addr->a.val[5] >> 6) & 0x03;
        if (top == 0x03) return "STATIC";
        if (top == 0x01) return "RPA";
        if (top == 0x00) return "NRPA";
        return "RANDOM?";
    }
    return "OTHER";
}

static const char *adv_type_str(uint8_t t)
{
    switch (t) {
    case BT_GAP_ADV_TYPE_ADV_IND: return "ADV_IND";
    case BT_GAP_ADV_TYPE_ADV_DIRECT_IND: return "DIRECT";
    case BT_GAP_ADV_TYPE_ADV_SCAN_IND: return "SCAN_IND";
    case BT_GAP_ADV_TYPE_ADV_NONCONN_IND: return "NONCONN";
    case BT_GAP_ADV_TYPE_SCAN_RSP: return "SCAN_RSP";
    case BT_GAP_ADV_TYPE_EXT_ADV: return "EXT_ADV";
    default: return "UNKNOWN";
    }
}

static int find_dev(const bt_addr_le_t *addr)
{
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (devs[i].used && bt_addr_le_cmp(&devs[i].addr, addr) == 0) return i;
    }
    return -1;
}

static int alloc_dev(const bt_addr_le_t *addr)
{
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (!devs[i].used) {
            memset(&devs[i], 0, sizeof(devs[i]));
            devs[i].used = true;
            bt_addr_le_copy(&devs[i].addr, addr);
            bt_addr_le_to_str(addr, devs[i].addr_str, sizeof(devs[i].addr_str));
            devs[i].min_rssi = 127;
            devs[i].max_rssi = -127;
            return i;
        }
    }
    return -1;
}

static void scan_recv(const struct bt_le_scan_recv_info *info, struct net_buf_simple *buf)
{
    int64_t now = k_uptime_get();
    k_mutex_lock(&dev_lock, K_FOREVER);
    int idx = find_dev(info->addr);
    if (idx < 0) idx = alloc_dev(info->addr);
    if (idx >= 0) {
        struct seen_dev *d = &devs[idx];
        if (d->packets == 0) d->first_ms = now;
        d->last_ms = now;
        d->last_rssi = info->rssi;
        d->min_rssi = MIN(d->min_rssi, info->rssi);
        d->max_rssi = MAX(d->max_rssi, info->rssi);
        d->rssi_sum += info->rssi;
        d->packets++;
        d->adv_len = buf->len;
        d->adv_type = info->adv_type;
    }
    k_mutex_unlock(&dev_lock);
}

static struct bt_le_scan_cb scan_cb = {
    .recv = scan_recv,
};

static int start_scan(void)
{
    struct bt_le_scan_param p = {
        .type = active_scan ? BT_LE_SCAN_TYPE_ACTIVE : BT_LE_SCAN_TYPE_PASSIVE,
        .options = BT_LE_SCAN_OPT_NONE,
        .interval = BT_GAP_SCAN_FAST_INTERVAL_MIN,
        .window = BT_GAP_SCAN_FAST_WINDOW,
        .timeout = 0,
    };
    int err = bt_le_scan_start(&p, NULL);
    if (!err) scanning = true;
    return err;
}

static int stop_scan(void)
{
    int err = bt_le_scan_stop();
    if (!err || err == -EALREADY) {
        scanning = false;
        return 0;
    }
    return err;
}

static void cmd_help(void)
{
    txln("Commands:");
    txln("  help                 show this list");
    txln("  status               scanner/USB status");
    txln("  list                 list observed BLE advertisers");
    txln("  list -70             list only RSSI >= -70 dBm");
    txln("  scan on              start scan");
    txln("  scan off             stop scan");
    txln("  scan active          active scan + scan responses");
    txln("  scan passive         receive-only scan");
    txln("  clear                clear device table");
}

static void cmd_status(void)
{
    char b[160];
    int count = 0;
    k_mutex_lock(&dev_lock, K_FOREVER);
    for (int i = 0; i < MAX_DEVICES; i++) if (devs[i].used) count++;
    k_mutex_unlock(&dev_lock);
    snprintf(b, sizeof(b), "BLE Recon V2 | scan=%s | mode=%s | devices=%d | uptime=%llds",
             scanning ? "ON" : "OFF", active_scan ? "ACTIVE" : "PASSIVE",
             count, (long long)(k_uptime_get() / 1000));
    txln(b);
}

static void cmd_list(int floor)
{
    char b[220];
    int64_t now = k_uptime_get();
    txln("Idx RSSI Avg  Pkts Age  Address                Class   Type      Len");
    txln("--- ---- ---- ---- ---- ---------------------- ------- --------- ---");
    k_mutex_lock(&dev_lock, K_FOREVER);
    for (int i = 0; i < MAX_DEVICES; i++) {
        struct seen_dev *d = &devs[i];
        if (!d->used || d->last_rssi < floor) continue;
        int avg = d->packets ? (int)(d->rssi_sum / (int32_t)d->packets) : d->last_rssi;
        long long age = (long long)((now - d->last_ms) / 1000);
        snprintf(b, sizeof(b), "%3d %4d %4d %4u %4lld %-22s %-7s %-9s %3u",
                 i, d->last_rssi, avg, d->packets, age, d->addr_str,
                 addr_class(&d->addr), adv_type_str(d->adv_type), d->adv_len);
        txln(b);
    }
    k_mutex_unlock(&dev_lock);
}

static void process_line(char *line)
{
    while (*line == ' ') line++;
    if (!*line) return;

    if (!strcmp(line, "help") || !strcmp(line, "?")) {
        cmd_help();
    } else if (!strcmp(line, "status")) {
        cmd_status();
    } else if (!strncmp(line, "list", 4)) {
        int floor = -127;
        if (line[4]) floor = atoi(line + 4);
        cmd_list(floor);
    } else if (!strcmp(line, "clear")) {
        k_mutex_lock(&dev_lock, K_FOREVER);
        memset(devs, 0, sizeof(devs));
        k_mutex_unlock(&dev_lock);
        txln("Device table cleared.");
    } else if (!strcmp(line, "scan off")) {
        int e = stop_scan();
        if (e) {
            char b[64]; snprintf(b, sizeof(b), "scan stop error: %d", e); txln(b);
        } else txln("Scanning stopped.");
    } else if (!strcmp(line, "scan on")) {
        int e = scanning ? 0 : start_scan();
        if (e) {
            char b[64]; snprintf(b, sizeof(b), "scan start error: %d", e); txln(b);
        } else txln("Scanning started.");
    } else if (!strcmp(line, "scan active")) {
        stop_scan(); active_scan = true; k_sleep(K_MSEC(50));
        int e = start_scan();
        if (e) { char b[64]; snprintf(b, sizeof(b), "scan error: %d", e); txln(b); }
        else txln("Active scanning enabled.");
    } else if (!strcmp(line, "scan passive")) {
        stop_scan(); active_scan = false; k_sleep(K_MSEC(50));
        int e = start_scan();
        if (e) { char b[64]; snprintf(b, sizeof(b), "scan error: %d", e); txln(b); }
        else txln("Passive scanning enabled.");
    } else {
        tx("Unknown command: "); txln(line);
        txln("Type help");
    }
}

static void wait_for_terminal(void)
{
#ifdef CONFIG_UART_LINE_CTRL
    uint32_t dtr = 0;
    while (uart_line_ctrl_get(cdc, UART_LINE_CTRL_DTR, &dtr) == 0 && !dtr) {
        k_sleep(K_MSEC(100));
    }
#endif
    k_sleep(K_MSEC(150));
}

int main(void)
{
    if (!device_is_ready(cdc)) {
        return 0;
    }

    wait_for_terminal();
    txln("");
    txln("========================================");
    txln(" BLE Recon V2 - nice!nano direct CDC");
    txln("========================================");
    txln("CDC console: OK");

    int err = bt_enable(NULL);
    if (err) {
        char b[80];
        snprintf(b, sizeof(b), "Bluetooth init FAILED: %d", err);
        txln(b);
    } else {
        bt_le_scan_cb_register(&scan_cb);
        err = start_scan();
        if (err) {
            char b[80];
            snprintf(b, sizeof(b), "Bluetooth scan FAILED: %d", err);
            txln(b);
        } else {
            txln("Bluetooth: OK | active scan started");
        }
    }

    txln("Type help, status, or list");
    tx("> ");

    char line[LINE_MAX];
    size_t n = 0;
    bool last_cr = false;

    while (1) {
        unsigned char c;
        if (uart_poll_in(cdc, &c) == 0) {
            if (c == '\r' || c == '\n') {
                if (c == '\n' && last_cr) {
                    last_cr = false;
                    continue;
                }
                last_cr = (c == '\r');
                tx("\r\n");
                line[n] = '\0';
                process_line(line);
                n = 0;
                tx("> ");
            } else {
                last_cr = false;
                if (c == 0x08 || c == 0x7f) {
                    if (n) {
                        n--;
                        tx("\b \b");
                    }
                } else if (c >= 0x20 && c < 0x7f && n < sizeof(line) - 1) {
                    line[n++] = (char)c;
                    tx_char((char)c);
                }
            }
        } else {
            k_sleep(K_MSEC(2));
        }
    }
    return 0;
}
